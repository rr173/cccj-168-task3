"""领域服务：队列生命周期、安全事件、快照与规则引擎、投票与决策证明、紧急暂停。

核心一致性原则
--------------
1. 冻结不可变：队列冻结后剂量方案/观察窗固定；受试者集合用 revision 编号，
   替补产生新 revision，旧快照永远指向旧 revision。
2. 快照隔离：每次决策必须基于单一快照（content_hash 锚定）。迟到 AE、AE 裁定
   变更、替补、给药等「实质性事件」会把该队列所有未决快照标记 superseded；
   规则修订不重算历史快照（快照绑定 ruleset_version），仅在新快照上作 advisory。
3. 投票防拼接：投票载荷含快照 content_hash 且乐观并发（expected_version），
   两名委员并发投票不可能在彼此陈旧视图上合并结论。
4. 紧急暂停即时生效：与暂停事实同一事务提交；暂停期的给药请求被阻断，
   但「阻断的尝试」与「已给药事实」都永久留痕。
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import timedelta

from . import rules
from .archives import ArchiveService
from .clock import now_utc, now_iso, parse_iso, set_clock
from .crypto import canonical_json, canonical_hash, verify_hmac
from .errors import Conflict, DomainError, NotFound, ValidationFailed
from .store import MATERIAL_EVENT_TYPES, append_event, verify_chain

# 委员会门槛：至少 2 票，且其中至少 2 票来自独立安全委员
QUORUM = 2
REQUIRED_INDEPENDENT = 2

VALID_GRADES = set(rules.SEVERITY_ORDER)


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _json_dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)


class Services:
    def __init__(self, conn):
        self.conn = conn
        # 同一连接被多线程直接使用时（HTTP 层另有写锁），保证 CAS 检查-写入原子性
        self._lock = threading.RLock()
        # 监管稽核归档：复用本服务的证明校验与锁，事件追加共用同一连接
        self.archives = ArchiveService(conn, self.verify_proof, self._lock)

    # ------------------------------------------------------------------ 引导
    def bootstrap(self) -> dict:
        """初始化委员会与首版规则（幂等）。返回演示用委员密钥。"""
        created = []
        if self.conn.execute("SELECT COUNT(*) c FROM committee_members").fetchone()["c"] == 0:
            seed = [
                ("CM-DAC", {"name": "陈岱（独立委员）", "role": "independent"}),
                ("CM-ELN", {"name": "Ellena Ross（独立委员）", "role": "independent"}),
                ("CM-SPO", {"name": "申办方医学监查", "role": "sponsor"}),
            ]
            for mid, info in seed:
                key = f"demo-key-{mid}"
                self.conn.execute(
                    "INSERT INTO committee_members(member_id,name,role,hmac_key)"
                    " VALUES(?,?,?,?)",
                    (mid, info["name"], info["role"], key),
                )
                created.append({"member_id": mid, **info, "hmac_key": key})
            append_event(self.conn, "committee_seeded", "system",
                         {"members": [{"member_id": m, "role": next(s[1]["role"] for s in seed if s[0] == m)}
                                      for m, _ in seed]})
        if self.conn.execute("SELECT COUNT(*) c FROM rulesets").fetchone()["c"] == 0:
            self._publish_ruleset(rules.DEFAULT_SPEC, "system",
                                  "首版规则：≥3 级可评估 AE 计 DLT，标准 3+3 区间", created=False)
        if self.conn.execute("SELECT COUNT(*) c FROM auditors").fetchone()["c"] == 0:
            # 演示稽核员（与委员会/操作角色分离的归档授权主体）
            self.conn.execute(
                "INSERT INTO auditors(auditor_id,name,api_key,active,created_at)"
                " VALUES('AUD-01','林岚（监管稽核员）','demo-auditor-key',1,?)",
                (now_iso(self.conn),))
        self.conn.commit()
        return {"members": created}

    # ------------------------------------------------------------- 基础对象
    def create_trial(self, actor: str, title: str) -> dict:
        tid = _uid("T")
        with self.conn:
            append_event(self.conn, "trial_created", actor,
                         {"trial_id": tid, "title": title}, tid)
            self.conn.execute(
                "INSERT INTO trials(trial_id,title,created_at,created_by)"
                " VALUES(?,?,?,?)",
                (tid, title, now_iso(self.conn), actor),
            )
        return self.get_trial(tid)

    def create_cohort(self, actor: str, trial_id: str, level: int,
                      dose: float, dose_unit: str, planned_n: int,
                      window_days: int, parent_cohort_id: str | None = None,
                      parent_decision_id: str | None = None,
                      rationale: str = "") -> dict:
        if self.conn.execute("SELECT 1 FROM trials WHERE trial_id=?", (trial_id,)).fetchone() is None:
            raise NotFound(f"试验 {trial_id}")
        if planned_n < 1 or window_days < 1:
            raise ValidationFailed("planned_n 与 window_days 必须为正整数")
        n = self.conn.execute(
            "SELECT COUNT(*) c FROM cohorts WHERE trial_id=?", (trial_id,)
        ).fetchone()["c"] + 1
        cid = f"{trial_id}-C{n}"
        with self.conn:
            append_event(self.conn, "cohort_created", actor, {
                "cohort_id": cid, "trial_id": trial_id, "level": level,
                "dose": dose, "dose_unit": dose_unit, "planned_n": planned_n,
                "window_days": window_days,
                "parent_cohort_id": parent_cohort_id,
                "parent_decision_id": parent_decision_id, "rationale": rationale,
            }, cid)
            self.conn.execute(
                "INSERT INTO cohorts(cohort_id,trial_id,level,dose,dose_unit,planned_n,"
                "window_days,status,parent_cohort_id,parent_decision_id,rationale,created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (cid, trial_id, level, dose, dose_unit, planned_n, window_days,
                 "draft", parent_cohort_id, parent_decision_id, rationale, now_iso(self.conn)),
            )
        return self.get_cohort(cid)

    def get_trial(self, trial_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM trials WHERE trial_id=?", (trial_id,)).fetchone()
        if row is None:
            raise NotFound(f"试验 {trial_id}")
        return dict(row)

    def _require_cohort(self, cohort_id: str):
        row = self.conn.execute("SELECT * FROM cohorts WHERE cohort_id=?", (cohort_id,)).fetchone()
        if row is None:
            raise NotFound(f"队列 {cohort_id}")
        return row

    def get_cohort(self, cohort_id: str) -> dict:
        c = self._require_cohort(cohort_id)
        d = dict(c)
        d["subjects"] = [dict(r) for r in self.conn.execute(
            "SELECT * FROM subjects WHERE cohort_id=? ORDER BY ordinal", (cohort_id,))]
        d["adverse_events"] = [dict(r) for r in self.conn.execute(
            "SELECT * FROM adverse_events WHERE cohort_id=? ORDER BY onset_at,id", (cohort_id,))]
        d["pending_data"] = [dict(r) for r in self.conn.execute(
            "SELECT * FROM pending_data WHERE cohort_id=? ORDER BY id", (cohort_id,))]
        d["administrations"] = [dict(r) for r in self.conn.execute(
            "SELECT * FROM administrations WHERE cohort_id=? ORDER BY given_at,id", (cohort_id,))]
        return d

    # ------------------------------------------------------------- 受试者/冻结
    def enroll_subject(self, actor: str, cohort_id: str) -> dict:
        c = self._require_cohort(cohort_id)
        if c["status"] != "draft":
            raise Conflict("cohort_locked", "队列已冻结，不能再入组；如需补充请使用受试者替补")
        n = self.conn.execute(
            "SELECT COUNT(*) c FROM subjects WHERE cohort_id=?", (cohort_id,)
        ).fetchone()["c"] + 1
        sid = f"{cohort_id}-S{n:02d}"
        with self.conn:
            append_event(self.conn, "subject_enrolled", actor,
                         {"subject_id": sid, "cohort_id": cohort_id, "ordinal": n}, cohort_id)
            self.conn.execute(
                "INSERT INTO subjects(id,cohort_id,ordinal,revision_added,status)"
                " VALUES(?,?,?,?, 'enrolled')",
                (sid, cohort_id, n, 0),
            )
        return {"subject_id": sid}

    def freeze_cohort(self, actor: str, cohort_id: str) -> dict:
        c = self._require_cohort(cohort_id)
        if c["status"] != "draft":
            raise Conflict("cohort_locked", f"队列当前状态 {c['status']}，不可冻结")
        active = self.conn.execute(
            "SELECT COUNT(*) c FROM subjects WHERE cohort_id=? AND revision_removed IS NULL",
            (cohort_id,)).fetchone()["c"]
        if active != c["planned_n"]:
            raise Conflict("freeze_set_mismatch",
                           f"冻结要求当前受试者集合为 {c['planned_n']} 人，实际 {active} 人")
        ts = now_iso(self.conn)
        with self.conn:
            append_event(self.conn, "cohort_frozen", actor, {
                "cohort_id": cohort_id, "planned_n": c["planned_n"],
                "dose": c["dose"], "dose_unit": c["dose_unit"],
                "window_days": c["window_days"], "frozen_at": ts,
            }, cohort_id)
            self.conn.execute(
                "UPDATE cohorts SET status='active',frozen_at=? WHERE cohort_id=?",
                (ts, cohort_id))
        return self.get_cohort(cohort_id)

    # ------------------------------------------------------------- 暂停/给药
    def _active_holds(self, cohort_id: str) -> list[dict]:
        c = self._require_cohort(cohort_id)
        rows = self.conn.execute(
            "SELECT * FROM holds WHERE status='active' AND "
            "(scope='trial' AND trial_id=? OR scope='cohort' AND cohort_id=?)",
            (c["trial_id"], cohort_id)).fetchall()
        return [dict(r) for r in rows]

    def emergency_hold(self, actor: str, scope: str, reason: str,
                       trial_id: str | None = None, cohort_id: str | None = None) -> dict:
        """紧急暂停：立即阻断后续给药（同一事务内对所有后续请求生效）。"""
        if scope not in ("trial", "cohort") or not reason:
            raise ValidationFailed("scope 必须为 trial/cohort，且必须填写原因")
        if scope == "cohort":
            if not cohort_id:
                raise ValidationFailed("cohort 级暂停必须提供 cohort_id")
            c = self._require_cohort(cohort_id)
            trial_id = c["trial_id"]
        elif not trial_id:
            raise ValidationFailed("trial 级暂停必须提供 trial_id")
        hid = _uid("H")
        ts = now_iso(self.conn)
        with self.conn:
            append_event(self.conn, "emergency_hold", actor, {
                "hold_id": hid, "scope": scope, "trial_id": trial_id,
                "cohort_id": cohort_id, "reason": reason, "created_at": ts,
            }, cohort_id or trial_id)
            self.conn.execute(
                "INSERT INTO holds(id,scope,trial_id,cohort_id,reason,status,"
                "created_by,created_at) VALUES(?,?,?,?,?, 'active',?,?)",
                (hid, scope, trial_id, cohort_id, reason, actor, ts))
        return {"hold_id": hid, "status": "active", "created_at": ts}

    def release_hold(self, actor: str, hold_id: str, reason: str) -> dict:
        row = self.conn.execute("SELECT * FROM holds WHERE id=?", (hold_id,)).fetchone()
        if row is None:
            raise NotFound(f"暂停 {hold_id}")
        if row["status"] != "active":
            raise Conflict("hold_not_active", "该暂停已解除")
        if not reason:
            raise ValidationFailed("解除暂停必须记录原因")
        ts = now_iso(self.conn)
        with self.conn:
            append_event(self.conn, "hold_released", actor,
                         {"hold_id": hold_id, "reason": reason, "released_at": ts},
                         row["cohort_id"] or row["trial_id"])
            self.conn.execute(
                "UPDATE holds SET status='released',released_reason=?,released_by=?,"
                "released_at=? WHERE id=?", (reason, actor, ts, hold_id))
        return {"hold_id": hold_id, "status": "released"}

    def record_administration(self, actor: str, cohort_id: str, subject_id: str,
                              dose: float | None = None,
                              dose_unit: str | None = None,
                              given_at: str | None = None) -> dict:
        c = self._require_cohort(cohort_id)
        s = self.conn.execute(
            "SELECT * FROM subjects WHERE id=? AND cohort_id=?", (subject_id, cohort_id)
        ).fetchone()
        if s is None:
            raise NotFound(f"受试者 {subject_id}")
        if s["revision_removed"] is not None:
            raise Conflict("subject_replaced", "该受试者已被替补退出，不能给药")
        if c["status"] != "active":
            raise Conflict("cohort_not_active", f"队列状态 {c['status']}，不能给药")
        dose = c["dose"] if dose is None else dose
        dose_unit = c["dose_unit"] if dose_unit is None else dose_unit
        if dose != c["dose"] or dose_unit != c["dose_unit"]:
            raise Conflict("dose_frozen",
                           "给药剂量/单位必须与冻结方案一致，不得更改")
        if s["dose_given"]:
            raise Conflict("already_dosed", "该受试者已有给药事实，不可重复给药")
        ts = given_at or now_iso(self.conn)
        if given_at:
            parse_iso(given_at)  # 校验
        holds = self._active_holds(cohort_id)
        aid = _uid("ADM")
        if holds:
            # 阻断后续给药，但阻断尝试本身作为事实留痕：先提交留痕，再返回冲突。
            # 任何情况下不得修改/删除已存在的 administrations 行。
            with self.conn:
                payload = {"administration_id": aid, "subject_id": subject_id,
                           "cohort_id": cohort_id, "attempted_at": ts,
                           "dose": dose, "dose_unit": dose_unit,
                           "hold_ids": [h["id"] for h in holds]}
                append_event(self.conn, "administration_blocked", actor, payload, cohort_id)
                self.conn.execute(
                    "INSERT INTO administrations(id,subject_id,cohort_id,given_at,dose,"
                    "dose_unit,held_back,reason,recorded_by) VALUES(?,?,?,?,?,?,1,?,?)",
                    (aid, subject_id, cohort_id, ts, dose, dose_unit,
                     f"紧急暂停期间给药被阻断: {holds[0]['reason']}", actor))
            raise Conflict("hold_active",
                           f"给药已被紧急暂停阻断（尝试编号 {aid} 已留痕）；"
                           "已给药事实保持不变")
        with self.conn:
            append_event(self.conn, "administration_recorded", actor, {
                "administration_id": aid, "subject_id": subject_id,
                "cohort_id": cohort_id, "given_at": ts,
                "dose": dose, "dose_unit": dose_unit,
            }, cohort_id)
            self.conn.execute(
                "INSERT INTO administrations(id,subject_id,cohort_id,given_at,dose,"
                "dose_unit,recorded_by) VALUES(?,?,?,?,?,?,?)",
                (aid, subject_id, cohort_id, ts, dose, dose_unit, actor))
            self.conn.execute(
                "UPDATE subjects SET dose_given=1,dose_at=?,status='evaluable' WHERE id=?",
                (ts, subject_id))
        return {"administration_id": aid, "held_back": False, "given_at": ts}

    # ------------------------------------------------------------- 安全事件
    def report_ae(self, actor: str, cohort_id: str, subject_id: str,
                  term: str, severity: str, onset_at: str) -> dict:
        c = self._require_cohort(cohort_id)
        s = self.conn.execute(
            "SELECT 1 FROM subjects WHERE id=? AND cohort_id=?", (subject_id, cohort_id)
        ).fetchone()
        if s is None:
            raise NotFound(f"受试者 {subject_id}")
        if severity not in VALID_GRADES:
            raise ValidationFailed(f"severity 必须是 {sorted(VALID_GRADES)}")
        parse_iso(onset_at)
        ae_id = _uid("AE")
        prior_snapshots = self.conn.execute(
            "SELECT COUNT(*) c FROM snapshots WHERE cohort_id=?", (cohort_id,)
        ).fetchone()["c"]
        late = 1 if prior_snapshots else 0
        ts = now_iso(self.conn)
        with self.conn:
            append_event(self.conn, "ae_reported", actor, {
                "ae_id": ae_id, "subject_id": subject_id, "cohort_id": cohort_id,
                "term": term, "severity": severity, "onset_at": onset_at,
                "late": late, "note": "迟到不良事件：在既有快照之后到达" if late else "",
            }, cohort_id)
            active_rs = self._active_ruleset_version()
            self.conn.execute(
                "INSERT INTO adverse_events(id,subject_id,cohort_id,term,severity,"
                "onset_at,is_dlt_rule,late,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (ae_id, subject_id, cohort_id, term, severity, onset_at,
                 f"ruleset-v{active_rs}", late, ts))
            if late:
                self._mark_snapshots_stale(cohort_id, reason="late_ae",
                                           extra={"ae_id": ae_id})
        return {"ae_id": ae_id, "late": late}

    def adjudicate_ae(self, actor: str, ae_id: str, evaluable: bool,
                      counts_as_dlt: bool, note: str = "") -> dict:
        row = self.conn.execute("SELECT * FROM adverse_events WHERE id=?", (ae_id,)).fetchone()
        if row is None:
            raise NotFound(f"不良事件 {ae_id}")
        if counts_as_dlt and not evaluable:
            raise ValidationFailed("不可评估的事件不能计为 DLT")
        # 计 DLT 必须满足当前生效规则的严重度门槛（裁定不能越过规则门槛）
        active_version = self._active_ruleset_version()
        spec = json.loads(self.conn.execute(
            "SELECT spec FROM rulesets WHERE version=?", (active_version,)
        ).fetchone()["spec"])
        if counts_as_dlt:
            if rules.SEVERITY_ORDER[row["severity"]] < rules.SEVERITY_ORDER[spec["min_severity_dlt"]]:
                raise Conflict("below_rule_threshold",
                               f"{row['severity']} 低于规则门槛 {spec['min_severity_dlt']}，不能计 DLT")
        ts = now_iso(self.conn)
        with self.conn:
            append_event(self.conn, "ae_adjudicated", actor, {
                "ae_id": ae_id, "cohort_id": row["cohort_id"],
                "evaluable": evaluable, "counts_as_dlt": counts_as_dlt,
                "note": note,
            }, row["cohort_id"])
            self.conn.execute(
                "UPDATE adverse_events SET assessed=1,evaluable=?,counts_as_dlt=?,"
                "assess_note=?,assessed_by=?,assessed_at=? WHERE id=?",
                (1 if evaluable else 0, 1 if counts_as_dlt else 0, note, actor, ts, ae_id))
            self._recompute_subject_dlt(row["subject_id"], row["cohort_id"])
            self._mark_snapshots_stale(row["cohort_id"], reason="ae_adjudicated",
                                       extra={"ae_id": ae_id})
        return {"ae_id": ae_id, "evaluable": evaluable, "counts_as_dlt": counts_as_dlt}

    def _recompute_subject_dlt(self, subject_id: str, cohort_id: str):
        row = self.conn.execute(
            "SELECT COUNT(*) c FROM adverse_events WHERE subject_id=? AND counts_as_dlt=1",
            (subject_id,)).fetchone()
        self.conn.execute("UPDATE subjects SET dlt=? WHERE id=?",
                          (1 if row["c"] > 0 else 0, subject_id))

    # ------------------------------------------------------------- 缺失数据
    def add_pending(self, actor: str, cohort_id: str, kind: str, note: str,
                    subject_id: str | None = None) -> dict:
        self._require_cohort(cohort_id)
        if kind not in ("lab", "followup", "ae_assessment", "other"):
            raise ValidationFailed("kind 非法")
        pid = _uid("PD")
        with self.conn:
            append_event(self.conn, "pending_added", actor, {
                "pending_id": pid, "cohort_id": cohort_id, "subject_id": subject_id,
                "kind": kind, "note": note,
            }, cohort_id)
            self.conn.execute(
                "INSERT INTO pending_data(id,cohort_id,subject_id,kind,note,status,"
                "created_at) VALUES(?,?,?,?,?, 'open',?)",
                (pid, cohort_id, subject_id, kind, note, now_iso(self.conn)))
        return {"pending_id": pid}

    def resolve_pending(self, actor: str, pending_id: str, resolution: str,
                        imputed: bool = False) -> dict:
        row = self.conn.execute("SELECT * FROM pending_data WHERE id=?", (pending_id,)).fetchone()
        if row is None:
            raise NotFound(f"缺失数据项 {pending_id}")
        if row["status"] != "open":
            raise Conflict("pending_closed", "该缺失数据项已处理")
        if not resolution:
            raise ValidationFailed("必须记录处理方式（补获或缺失处理/插补说明）")
        ts = now_iso(self.conn)
        status = "imputed" if imputed else "resolved"
        with self.conn:
            append_event(self.conn, "pending_resolved", actor, {
                "pending_id": pending_id, "cohort_id": row["cohort_id"],
                "status": status, "resolution": resolution, "imputed": imputed,
            }, row["cohort_id"])
            self.conn.execute(
                "UPDATE pending_data SET status=?,resolution=?,resolved_by=?,resolved_at=?"
                " WHERE id=?", (status, resolution, actor, ts, pending_id))
        return {"pending_id": pending_id, "status": status}

    # ------------------------------------------------------------- 受试者替补
    def replace_subject(self, actor: str, cohort_id: str, subject_id: str,
                        reason: str) -> dict:
        c = self._require_cohort(cohort_id)
        if c["status"] != "active":
            raise Conflict("cohort_not_active", "仅 active 队列可替补受试者")
        s = self.conn.execute(
            "SELECT * FROM subjects WHERE id=? AND cohort_id=?", (subject_id, cohort_id)
        ).fetchone()
        if s is None:
            raise NotFound(f"受试者 {subject_id}")
        if s["revision_removed"] is not None:
            raise Conflict("subject_replaced", "该受试者已退出")
        if not reason:
            raise ValidationFailed("替补必须记录原因")
        with self.conn:
            new_rev = c["revision"] + 1
            ordinal = self.conn.execute(
                "SELECT COUNT(*) c FROM subjects WHERE cohort_id=?", (cohort_id,)
            ).fetchone()["c"] + 1
            new_id = f"{cohort_id}-S{ordinal:02d}"
            append_event(self.conn, "subject_replaced", actor, {
                "cohort_id": cohort_id, "removed_subject_id": subject_id,
                "replacement_subject_id": new_id, "revision": new_rev,
                "reason": reason,
            }, cohort_id)
            self.conn.execute(
                "UPDATE subjects SET status='replaced',revision_removed=?,"
                "replaced_by=?,replaced_reason=? WHERE id=?",
                (new_rev, new_id, reason, subject_id))
            self.conn.execute(
                "INSERT INTO subjects(id,cohort_id,ordinal,revision_added,status)"
                " VALUES(?,?,?,?,'enrolled')",
                (new_id, cohort_id, ordinal, new_rev))
            self.conn.execute("UPDATE cohorts SET revision=? WHERE cohort_id=?",
                              (new_rev, cohort_id))
            self._mark_snapshots_stale(cohort_id, reason="subject_replaced",
                                       extra={"removed": subject_id, "replacement": new_id})
        return {"replacement_subject_id": new_id, "revision": new_rev}

    # ------------------------------------------------------------- 规则版本
    def _active_ruleset_version(self) -> int:
        row = self.conn.execute(
            "SELECT version FROM rulesets WHERE active=1 ORDER BY version DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise Conflict("no_ruleset", "尚未发布任何规则集")
        return row["version"]

    def publish_ruleset(self, actor: str, spec: dict, note: str = "") -> dict:
        with self.conn:
            return self._publish_ruleset(spec, actor, note, created=False)

    def _publish_ruleset(self, spec: dict, actor: str, note: str, created: bool) -> dict:
        spec = rules.validate_spec(spec)
        row = self.conn.execute("SELECT MAX(version) m FROM rulesets").fetchone()
        version = (row["m"] or 0) + 1
        ts = now_iso(self.conn)
        append_event(self.conn, "ruleset_published", actor, {
            "version": version, "spec": spec, "note": note,
        })
        self.conn.execute("UPDATE rulesets SET active=0")
        self.conn.execute(
            "INSERT INTO rulesets(version,spec,active,published_by,published_at,note)"
            " VALUES(?, ?,1,?,?,?)",
            (version, _json_dumps(spec), actor, ts, note))
        if created:
            self.conn.commit()
        return {"version": version, "spec": spec, "active": True}

    # ------------------------------------------------------------- 快照
    def _latest_material_seq(self, cohort_id: str) -> int:
        placeholders = ",".join("?" for _ in MATERIAL_EVENT_TYPES)
        row = self.conn.execute(
            f"SELECT MAX(seq) m FROM journal WHERE cohort_id=? AND event_type IN ({placeholders})",
            (cohort_id, *MATERIAL_EVENT_TYPES)).fetchone()
        return row["m"] or 0

    def _mark_snapshots_stale(self, cohort_id: str, reason: str, extra: dict):
        """实质性事件使队列所有未决快照失效（快照内结论一律作废，需重新构建）。"""
        rows = self.conn.execute(
            "SELECT id FROM snapshots WHERE cohort_id=? AND superseded=0", (cohort_id,)
        ).fetchall()
        for r in rows:
            append_event(self.conn, "snapshot_superseded", "system", {
                "snapshot_id": r["id"], "cohort_id": cohort_id,
                "reason": reason, **extra,
            }, cohort_id)
        self.conn.execute(
            "UPDATE snapshots SET superseded=1 WHERE cohort_id=? AND superseded=0",
            (cohort_id,))

    def _build_gates(self, c, subjects: list[dict]) -> dict:
        now = now_utc(self.conn)
        # 门 1：观察窗完整（每名给药者 dose_at + window_days <= now，且全部已给药）
        window_ok = True
        window_detail = []
        for s in subjects:
            if not s["dose_given"] or not s.get("dose_at"):
                window_ok = False
                window_detail.append({"subject_id": s["id"], "reason": "尚未给药"})
                continue
            end = parse_iso(s["dose_at"]) + timedelta(days=c["window_days"])
            if now < end:
                window_ok = False
                window_detail.append({
                    "subject_id": s["id"],
                    "reason": f"观察窗未结束（{end.isoformat()}）",
                })
        # 门 2：缺失数据全部处理
        pending = self.conn.execute(
            "SELECT * FROM pending_data WHERE cohort_id=? AND status='open'",
            (c["cohort_id"],)).fetchall()
        pending_ok = len(pending) == 0
        # 门 3：进入引擎的安全事件全部完成可评估裁定
        rs_version = self._active_ruleset_version()
        spec = json.loads(self.conn.execute(
            "SELECT spec FROM rulesets WHERE version=?", (rs_version,)).fetchone()["spec"])
        threshold = rules.SEVERITY_ORDER[spec["min_severity_dlt"]]
        ae_rows = self._active_ae_rows(c["cohort_id"])
        unassessed = []
        events = []
        dlt_subject_ids = set()
        for ae in ae_rows:
            d = dict(ae)
            if rules.SEVERITY_ORDER[d["severity"]] >= threshold:
                # DLT 归属按「本快照绑定的规则版本」重算，而不是沿用裁定时的标志
                is_dlt = rules.counts_as_dlt(d, spec)
                events.append({
                    "ae_id": d["id"], "subject_id": d["subject_id"],
                    "term": d["term"], "severity": d["severity"],
                    "onset_at": d["onset_at"], "assessed": bool(d["assessed"]),
                    "evaluable": bool(d["evaluable"]),
                    "counts_as_dlt": is_dlt,
                    "adjudicated_as_dlt": bool(d["counts_as_dlt"]),
                    "late": bool(d["late"]),
                })
                if is_dlt:
                    dlt_subject_ids.add(d["subject_id"])
                if not d["assessed"]:
                    unassessed.append(d["id"])
        # 门 4：可评估受试者达到计划人数（集合完整）
        evaluable_subjects = [s for s in subjects if s["dose_given"]]
        evaluable_ok = len(evaluable_subjects) >= c["planned_n"]
        # 门 5：独立委员达到法定人数（门槛可能被满足）
        independent = self.conn.execute(
            "SELECT COUNT(*) c FROM committee_members WHERE active=1 AND role='independent'"
        ).fetchone()["c"]
        committee_ok = independent >= REQUIRED_INDEPENDENT

        gates = {
            "window_complete": {"passed": window_ok, "blockers": window_detail},
            "missing_data_resolved": {
                "passed": pending_ok,
                "blockers": [{"pending_id": p["id"], "kind": p["kind"], "note": p["note"]}
                             for p in pending],
            },
            "events_adjudicated": {
                "passed": len(unassessed) == 0,
                "blockers": [{"ae_id": a, "reason": "安全事件尚未完成可评估裁定"}
                             for a in unassessed],
            },
            "evaluable_set_complete": {
                "passed": evaluable_ok,
                "blockers": [] if evaluable_ok else [
                    {"reason": f"可评估受试者 {len(evaluable_subjects)}/{c['planned_n']}"}],
            },
            "independent_quorum_available": {
                "passed": committee_ok,
                "blockers": [] if committee_ok else [
                    {"reason": f"在职独立委员 {independent}/{REQUIRED_INDEPENDENT}"}],
            },
        }
        gates["ready"] = all(g["passed"] for k, g in gates.items())
        return gates, events, spec, rs_version, dlt_subject_ids

    def _active_ae_rows(self, cohort_id: str):
        """当前修订集合中受试者的 AE（被替补者的事件不进入新快照）。"""
        return self.conn.execute(
            "SELECT ae.* FROM adverse_events ae JOIN subjects s ON s.id=ae.subject_id"
            " WHERE ae.cohort_id=? AND s.revision_removed IS NULL"
            " ORDER BY ae.onset_at,ae.id",
            (cohort_id,)).fetchall()

    def create_snapshot(self, actor: str, cohort_id: str) -> dict:
        c = self._require_cohort(cohort_id)
        if c["status"] != "active":
            raise Conflict("cohort_not_active", f"队列状态 {c['status']}，不能构建快照")
        subjects_rows = self.conn.execute(
            "SELECT * FROM subjects WHERE cohort_id=? AND revision_removed IS NULL"
            " ORDER BY ordinal", (cohort_id,)).fetchall()
        subjects = []
        for s in subjects_rows:
            d = dict(s)
            d["evaluable"] = bool(s["dose_given"])
            subjects.append(d)
        gates, events, spec, rs_version, dlt_subject_ids = self._build_gates(c, subjects)
        material_seq = self._latest_material_seq(cohort_id)
        n = self.conn.execute(
            "SELECT COUNT(*) c FROM snapshots WHERE cohort_id=?", (cohort_id,)
        ).fetchone()["c"] + 1
        sid = f"{cohort_id}-SN{n}"
        ts = now_iso(self.conn)

        window_end = None
        if subjects and all(s["dose_given"] for s in subjects):
            window_end = (max(parse_iso(s["dose_at"]) for s in subjects)
                          + timedelta(days=c["window_days"])).isoformat()

        payload = {
            "snapshot": {
                "snapshot_id": sid,
                "cohort_id": cohort_id,
                "revision": c["revision"],
                "ruleset_version": rs_version,
                "material_seq": material_seq,
                "window_end": window_end,
                "built_at": ts,
                "built_by": actor,
            },
            "cohort": {
                "cohort_id": c["cohort_id"], "trial_id": c["trial_id"],
                "level": c["level"], "dose": c["dose"], "dose_unit": c["dose_unit"],
                "planned_n": c["planned_n"], "window_days": c["window_days"],
                "frozen_at": c["frozen_at"],
            },
            "planned_n": c["planned_n"],
            "subjects": [
                {
                    "id": s["id"], "ordinal": s["ordinal"],
                    "revision_added": s["revision_added"],
                    "status": s["status"], "dose_given": bool(s["dose_given"]),
                    "dose_at": s["dose_at"], "evaluable": bool(s["dose_given"]),
                    # 按本快照绑定规则版本重算的 DLT 归属
                    "dlt": s["id"] in dlt_subject_ids,
                }
                for s in subjects
            ],
            "events": events,
            "gates": gates,
        }
        outcome = rules.evaluate(payload, spec)
        payload["outcome"] = outcome

        # 规则修订 advisory：若存在更新的激活规则（此处 rs_version 即激活版本，
        # 保留扩展位）；历史快照绑定的规则永不被重算。
        payload["advisory"] = []

        content_hash = canonical_hash(payload)
        with self.conn:
            ev = append_event(self.conn, "snapshot_created", actor, {
                "snapshot_id": sid, "cohort_id": cohort_id,
                "revision": c["revision"], "ruleset_version": rs_version,
                "material_seq": material_seq, "content_hash": content_hash,
                "gates_ready": gates["ready"],
                "recommendation": outcome["recommendation"],
            }, cohort_id)
            # 完整冻结载荷内容寻址存储（哈希即身份，投票与证明都锚定它）
            self.conn.execute(
                "INSERT INTO snapshot_payloads(snapshot_id,content_hash,payload)"
                " VALUES(?,?,?)",
                (sid, content_hash, _json_dumps(payload)))
            self.conn.execute(
                "INSERT INTO snapshots(id,cohort_id,seq,revision,ruleset_version,"
                "material_seq,window_end,content_hash,created_at,created_by)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (sid, cohort_id, ev["seq"], c["revision"], rs_version,
                 material_seq, window_end, content_hash, ts, actor))
        return self.get_snapshot(sid)

    def get_snapshot(self, snapshot_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
        if row is None:
            raise NotFound(f"快照 {snapshot_id}")
        payload = self._load_snapshot_payload(row)
        votes = [dict(v) for v in self.conn.execute(
            "SELECT * FROM votes WHERE snapshot_id=? ORDER BY created_at", (snapshot_id,))]
        version = self.conn.execute(
            "SELECT COUNT(*) c FROM votes WHERE snapshot_id=?", (snapshot_id,)).fetchone()["c"]
        fresh_material = self._latest_material_seq(row["cohort_id"])
        return {
            "snapshot_id": snapshot_id,
            "cohort_id": row["cohort_id"],
            "seq": row["seq"],
            "revision": row["revision"],
            "ruleset_version": row["ruleset_version"],
            "material_seq": row["material_seq"],
            "content_hash": row["content_hash"],
            "superseded": bool(row["superseded"]),
            "stale_by_new_material": fresh_material > row["material_seq"],
            "created_at": row["created_at"],
            "votes": votes,
            "vote_version": version,
            "payload": payload,
            "gates": payload["gates"],
            "outcome": payload["outcome"],
        }

    def _load_snapshot_payload(self, row) -> dict:
        rec = self.conn.execute(
            "SELECT payload FROM snapshot_payloads WHERE snapshot_id=?",
            (row["id"],)).fetchone()
        if rec is None:
            raise NotFound(f"快照 {row['id']} 的载荷缺失")
        return json.loads(rec["payload"])

    # ------------------------------------------------------------- 投票
    def cast_vote(self, actor: str, snapshot_id: str, member_id: str,
                  action: str, signature: str, expected_version: int) -> dict:
        """委员投票（乐观并发 + HMAC 签名 + 快照哈希锚定）。

        整个检查-写入在服务级锁内原子完成；HTTP 层另有写锁，双保险保证
        两名委员并发投票时，后到者必然得到 snapshot_version_conflict，
        必须基于含对方投票的新视图重试。
        """
        with self._lock:
            snap = self.conn.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
            if snap is None:
                raise NotFound(f"快照 {snapshot_id}")
            member = self.conn.execute(
                "SELECT * FROM committee_members WHERE member_id=? AND active=1", (member_id,)
            ).fetchone()
            if member is None:
                raise NotFound(f"在职委员 {member_id}")
            if action not in rules.VALID_ACTIONS:
                raise ValidationFailed(f"action 必须是 {sorted(rules.VALID_ACTIONS)}")

            # 乐观并发：期望版本必须等于当前票数
            current_version = self.conn.execute(
                "SELECT COUNT(*) c FROM votes WHERE snapshot_id=?", (snapshot_id,)).fetchone()["c"]
            if expected_version != current_version:
                raise Conflict("snapshot_version_conflict",
                               f"快照投票版本已变化（期望 {expected_version}，实际 {current_version}），"
                               "请重新拉取快照后投票，禁止在陈旧视图上合并结论")

            if snap["superseded"]:
                raise Conflict("snapshot_superseded",
                               "该快照已被迟到事件/替补等失效，必须基于新快照投票")
            if self._latest_material_seq(snap["cohort_id"]) > snap["material_seq"]:
                raise Conflict("snapshot_superseded",
                               "快照之后出现新的实质性事件，必须重新构建快照")
            if self._recompute_snapshot_hash(snap) != snap["content_hash"]:
                raise Conflict("snapshot_tampered", "快照内容哈希与构建时不一致")

            payload = self._load_snapshot_payload(snap)
            if not payload["gates"]["ready"]:
                raise Conflict("gates_not_satisfied",
                               "五道安全门槛尚未全部通过，不能投票/决策")
            c = self._require_cohort(snap["cohort_id"])
            if c["status"] != "active":
                raise Conflict("cohort_not_active", "队列已结束，不能再投票")

            holds = self._active_holds(snap["cohort_id"])
            if holds and action not in ("stop", "continue"):
                raise Conflict("hold_active",
                               "紧急暂停生效期间只允许投票 stop 或 continue（解除暂停）")

            message = canonical_json({
                "snapshot_id": snapshot_id,
                "content_hash": snap["content_hash"],
                "action": action,
                "member_id": member_id,
            })
            if not verify_hmac(member["hmac_key"], message, signature):
                raise Conflict("bad_signature", "委员签名校验失败")

            ts = now_iso(self.conn)
            vid = _uid("V")
            with self.conn:
                # 数据库层原子 CAS：仅当票数仍等于期望值时才插入
                cur = self.conn.execute(
                    "SELECT COUNT(*) c FROM votes WHERE snapshot_id=?", (snapshot_id,)
                ).fetchone()["c"]
                if cur != expected_version:
                    raise Conflict("snapshot_version_conflict",
                                   f"并发投票冲突（实际版本 {cur}），请刷新快照后重试")
                try:
                    append_event(self.conn, "vote_cast", actor, {
                        "vote_id": vid, "snapshot_id": snapshot_id,
                        "cohort_id": snap["cohort_id"], "member_id": member_id,
                        "role": member["role"], "action": action,
                        "content_hash": snap["content_hash"],
                        "expected_version": expected_version, "signature": signature,
                    }, snap["cohort_id"])
                    self.conn.execute(
                        "INSERT INTO votes(id,snapshot_id,cohort_id,member_id,action,"
                        "content_hash,signature,created_at) VALUES(?,?,?,?,?,?,?,?)",
                        (vid, snapshot_id, snap["cohort_id"], member_id, action,
                         snap["content_hash"], signature, ts))
                except Exception as e:  # UNIQUE 冲突
                    raise Conflict("vote_exists", "该委员已在此快照投票，投票不可修改") from e
            return {"vote_id": vid, "version": expected_version + 1}

    def _recompute_snapshot_hash(self, snap) -> str:
        payload = self._load_snapshot_payload(snap)
        return canonical_hash(payload)

    # ------------------------------------------------------------- 断网投票草稿
    # 草稿在委员本地（离线）生成并签名，网络恢复后由本端点一次性提交：
    # 先核对快照仍然有效（未被迟到事件/替补推进、规则未换版、指纹一致），
    # 再原子写票；同一 draft_id 重复提交返回首次结果，绝不产生第二张票。
    # 待提交（pending）状态只存在于客户端本地；服务端队列只记录终态。
    TRANSIENT_DRAFT_CONFLICTS = {"snapshot_version_conflict", "hold_active"}

    def submit_vote_draft(self, actor: str, draft_id: str, snapshot_id: str,
                          member_id: str, action: str, content_hash: str,
                          signature: str, expected_version: int) -> dict:
        if not draft_id:
            raise ValidationFailed("draft_id 必填（客户端生成的幂等键）")
        with self._lock:
            # 1) 幂等回放：同一 draft_id 直接返回首次结果，不产生第二张票
            row = self.conn.execute(
                "SELECT * FROM vote_drafts WHERE id=?", (draft_id,)).fetchone()
            if row is not None:
                core = (row["snapshot_id"], row["member_id"], row["action"],
                        row["content_hash"])
                if core != (snapshot_id, member_id, action, content_hash):
                    raise Conflict("draft_payload_mismatch",
                                   "同一 draft_id 携带了不同的投票载荷，拒绝重放")
                view = self._draft_view(row)
                view["replayed"] = True
                return view

            # 2) 认证：委员在职、动作合法、离线签名有效（动作+快照指纹）
            member = self.conn.execute(
                "SELECT * FROM committee_members WHERE member_id=? AND active=1",
                (member_id,)).fetchone()
            if member is None:
                raise NotFound(f"在职委员 {member_id}")
            if action not in rules.VALID_ACTIONS:
                raise ValidationFailed(f"action 必须是 {sorted(rules.VALID_ACTIONS)}")
            message = canonical_json({
                "snapshot_id": snapshot_id, "content_hash": content_hash,
                "action": action, "member_id": member_id})
            if not verify_hmac(member["hmac_key"], message, signature):
                raise Conflict("bad_signature", "草稿签名校验失败")

            # 3) 核对快照仍然有效（草稿专用：含规则换版检查）
            snap = self.conn.execute(
                "SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
            conflict = self._draft_snapshot_conflict(snap)
            if conflict is None and snap["content_hash"] != content_hash:
                conflict = ("snapshot_hash_mismatch",
                            "草稿锚定的快照指纹与快照内容哈希不一致")
            if conflict is not None:
                return self._expire_draft(actor, draft_id, snap, snapshot_id,
                                          member_id, action, content_hash,
                                          signature, *conflict)

            # 4) 快照有效：复用实时投票的全部检查，原子写票
            try:
                vote = self.cast_vote(actor, snapshot_id, member_id, action,
                                      signature, expected_version)
            except Conflict as e:
                if e.code in self.TRANSIENT_DRAFT_CONFLICTS:
                    raise  # 瞬态冲突：不落库，客户端刷新后持同一 draft_id 重试
                return self._expire_draft(actor, draft_id, snap, snapshot_id,
                                          member_id, action, content_hash,
                                          signature, e.code, e.message)
            ts = now_iso(self.conn)
            with self.conn:
                append_event(self.conn, "vote_draft_submitted", actor, {
                    "draft_id": draft_id, "snapshot_id": snapshot_id,
                    "cohort_id": snap["cohort_id"], "member_id": member_id,
                    "action": action, "vote_id": vote["vote_id"],
                    "content_hash": content_hash}, snap["cohort_id"])
                self.conn.execute(
                    "INSERT INTO vote_drafts(id,snapshot_id,cohort_id,member_id,action,"
                    "content_hash,signature,status,vote_id,created_at,resolved_at)"
                    " VALUES(?,?,?,?,?,?,?, 'submitted',?,?,?)",
                    (draft_id, snapshot_id, snap["cohort_id"], member_id, action,
                     content_hash, signature, vote["vote_id"], ts, ts))
            return self.get_vote_draft(draft_id)

    def _expire_draft(self, actor: str, draft_id: str, snap, snapshot_id: str,
                      member_id: str, action: str, content_hash: str,
                      signature: str, code: str, message: str) -> dict:
        """永久性冲突：草稿落库为 expired（含冲突原因），不写入任何票。"""
        cohort_id = snap["cohort_id"] if snap else None
        ts = now_iso(self.conn)
        with self.conn:
            append_event(self.conn, "vote_draft_expired", actor, {
                "draft_id": draft_id, "snapshot_id": snapshot_id,
                "cohort_id": cohort_id, "member_id": member_id, "action": action,
                "conflict_code": code, "detail": message}, cohort_id)
            self.conn.execute(
                "INSERT INTO vote_drafts(id,snapshot_id,cohort_id,member_id,action,"
                "content_hash,signature,status,conflict_code,conflict_detail,"
                "created_at,resolved_at) VALUES(?,?,?,?,?,?,?, 'expired',?,?,?,?)",
                (draft_id, snapshot_id, cohort_id or "", member_id, action,
                 content_hash, signature, code, message, ts, ts))
        return self.get_vote_draft(draft_id)

    def _draft_snapshot_conflict(self, snap) -> tuple[str, str] | None:
        """草稿提交前的快照有效性核对。

        与实时投票相同的失效检查（迟到事件/替补/新实质事件），外加草稿特有规则：
        规则换版后，离线期间按旧规则结论作出的决定必须基于新快照重新作出。
        """
        if snap is None:
            return ("snapshot_not_found", "草稿锚定的快照不存在")
        if snap["superseded"]:
            return ("snapshot_superseded",
                    "快照已被迟到事件/替补等实质性事件失效，须重建快照后重新决定")
        if self._latest_material_seq(snap["cohort_id"]) > snap["material_seq"]:
            return ("snapshot_superseded", "快照之后出现新的实质性事件，须重建快照")
        active = self._active_ruleset_version()
        if snap["ruleset_version"] != active:
            return ("ruleset_advanced",
                    f"规则已换版（快照绑定 v{snap['ruleset_version']}，当前生效 "
                    f"v{active}），离线决定不再有效，须基于新规则重建快照")
        return None

    def _draft_view(self, row) -> dict:
        return {
            "draft_id": row["id"], "snapshot_id": row["snapshot_id"],
            "cohort_id": row["cohort_id"], "member_id": row["member_id"],
            "action": row["action"], "content_hash": row["content_hash"],
            "signature": row["signature"],
            "status": row["status"], "vote_id": row["vote_id"],
            "conflict": ({"code": row["conflict_code"],
                          "message": row["conflict_detail"]}
                         if row["conflict_code"] else None),
            "created_at": row["created_at"], "resolved_at": row["resolved_at"],
        }

    def get_vote_draft(self, draft_id: str) -> dict:
        row = self.conn.execute(
            "SELECT * FROM vote_drafts WHERE id=?", (draft_id,)).fetchone()
        if row is None:
            raise NotFound(f"草稿 {draft_id}")
        return self._draft_view(row)

    def list_vote_drafts(self, cohort_id: str | None = None) -> list:
        if cohort_id:
            rows = self.conn.execute(
                "SELECT * FROM vote_drafts WHERE cohort_id=? ORDER BY created_at,id",
                (cohort_id,)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM vote_drafts ORDER BY created_at,id").fetchall()
        return [self._draft_view(r) for r in rows]

    # ------------------------------------------------------------- 决策证明
    def issue_decision(self, actor: str, snapshot_id: str) -> dict:
        snap = self.conn.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
        if snap is None:
            raise NotFound(f"快照 {snapshot_id}")
        if snap["superseded"]:
            raise Conflict("snapshot_superseded", "快照已失效，不能据此决策")
        if self._latest_material_seq(snap["cohort_id"]) > snap["material_seq"]:
            raise Conflict("snapshot_superseded", "快照后有新实质性事件，必须重建快照")
        if self._recompute_snapshot_hash(snap) != snap["content_hash"]:
            raise Conflict("snapshot_tampered", "快照内容哈希不一致")

        payload = self._load_snapshot_payload(snap)
        if not payload["gates"]["ready"]:
            raise Conflict("gates_not_satisfied", "五道安全门未全部通过，不能决策")

        votes = self.conn.execute(
            "SELECT * FROM votes WHERE snapshot_id=? ORDER BY created_at", (snapshot_id,)
        ).fetchall()
        # 每一张票都必须锚定同一个快照哈希（防拼接的最终闸口）
        for v in votes:
            if v["content_hash"] != snap["content_hash"]:
                raise Conflict("mixed_snapshots",
                               f"投票 {v['id']} 锚定不同快照，禁止拼接快照得出结论")

        actions = {v["action"] for v in votes}
        if len(actions) != 1:
            raise Conflict("vote_conflict",
                           f"当前投票动作不一致 {sorted(actions)}，无法形成决定；请统一后重试")
        action = next(iter(actions))

        approvers = []
        independent_yes = 0
        members_cache = {}
        for v in votes:
            m = self.conn.execute(
                "SELECT * FROM committee_members WHERE member_id=?", (v["member_id"],)
            ).fetchone()
            members_cache[v["member_id"]] = m
            msg = canonical_json({
                "snapshot_id": snapshot_id,
                "content_hash": v["content_hash"],
                "action": v["action"],
                "member_id": v["member_id"],
            })
            sig_ok = verify_hmac(m["hmac_key"], msg, v["signature"])
            approvers.append({
                "member_id": m["member_id"], "name": m["name"], "role": m["role"],
                "action": v["action"], "signature": v["signature"],
                "signature_valid": sig_ok,
            })
            if sig_ok and m["role"] == "independent":
                independent_yes += 1
        if len(votes) < QUORUM or independent_yes < REQUIRED_INDEPENDENT:
            raise Conflict("quorum_not_met",
                           f"门槛未达：总票 {len(votes)}/{QUORUM}，"
                           f"独立委员 {independent_yes}/{REQUIRED_INDEPENDENT}")

        outcome = payload["outcome"]
        c = self._require_cohort(snap["cohort_id"])
        holds = self._active_holds(snap["cohort_id"])
        if holds and action not in ("stop", "continue"):
            raise Conflict("hold_active", "暂停期间仅可决定 stop 或 continue")
        # 引擎约束：委员会动作不得比引擎建议更激进（保守覆盖永远允许）
        if not rules.action_within_engine(action, outcome["recommendation"]):
            raise Conflict("engine_disagreement",
                           f"委员会动作 {action} 比规则引擎建议 "
                           f"{outcome['recommendation']} 更激进，不允许")

        did = _uid("D")
        decision_ts = now_iso(self.conn)
        chain = verify_chain(self.conn)
        proof = {
            "proof_version": 1,
            "decision_id": did,
            "cohort_id": c["cohort_id"],
            "trial_id": c["trial_id"],
            "snapshot_id": snapshot_id,
            "action": action,
            "issued_at": decision_ts,
            "issued_by": actor,
            "snapshot_content_hash": snap["content_hash"],
            "snapshot_payload": payload,
            "rule_engine": {
                "ruleset_version": snap["ruleset_version"],
                "recommendation": outcome["recommendation"],
                "band_label": outcome["band_label"],
                "dlt_count": outcome["dlt_count"],
                "evaluable_n": outcome["evaluable_n"],
            },
            "gates": payload["gates"],
            "votes": approvers,
            "quorum": {"required": QUORUM, "independent_required": REQUIRED_INDEPENDENT,
                       "cast": len(votes), "independent_cast": independent_yes},
            "holds_at_decision": [
                {"hold_id": h["id"], "scope": h["scope"], "reason": h["reason"]}
                for h in holds],
            "journal_anchor": {
                "events_before_decision": chain["events"],
                "head_hash_before_decision": chain["head"],
            },
        }
        proof_hash = canonical_hash(proof)
        proof["proof_hash"] = proof_hash

        child_id = None
        with self.conn:
            if action == "stop":
                self.conn.execute(
                    "UPDATE cohorts SET status='stopped',decided_at=? WHERE cohort_id=?",
                    (decision_ts, c["cohort_id"]))
                for h in holds:
                    self.conn.execute(
                        "UPDATE holds SET status='released',released_reason=?,"
                        "released_by=?,released_at=? WHERE id=?",
                        ("队列停止，暂停随决定归档", actor, decision_ts, h["id"]))
            elif action == "continue":
                if not holds:
                    raise Conflict("no_active_hold", "无生效暂停，continue 无对象；请先正常走递增决策")
                for h in holds:
                    append_event(self.conn, "hold_released", actor,
                                 {"hold_id": h["id"], "reason": "委员会基于快照投票决定继续",
                                  "released_at": decision_ts}, c["cohort_id"])
                    self.conn.execute(
                        "UPDATE holds SET status='released',released_reason=?,"
                        "released_by=?,released_at=? WHERE id=?",
                        ("委员会决定继续", actor, decision_ts, h["id"]))
            else:
                # escalate / expand：关闭当前队列，派生下一代队列草案
                level = c["level"] + (1 if action == "escalate" else 0)
                planned_n = c["planned_n"]
                rationale = (f"由 {c['cohort_id']} 决定 {action} 派生"
                             f"（决定 {did}，快照 {snapshot_id}）")
                n = self.conn.execute(
                    "SELECT COUNT(*) c FROM cohorts WHERE trial_id=?", (c["trial_id"],)
                ).fetchone()["c"] + 1
                child_id = f"{c['trial_id']}-C{n}"
                append_event(self.conn, "cohort_created", actor, {
                    "cohort_id": child_id, "trial_id": c["trial_id"], "level": level,
                    "dose": c["dose"], "dose_unit": c["dose_unit"],
                    "planned_n": planned_n, "window_days": c["window_days"],
                    "parent_cohort_id": c["cohort_id"], "parent_decision_id": did,
                    "rationale": rationale,
                }, child_id)
                self.conn.execute(
                    "INSERT INTO cohorts(cohort_id,trial_id,level,dose,dose_unit,planned_n,"
                    "window_days,status,parent_cohort_id,parent_decision_id,rationale,created_at)"
                    " VALUES(?,?,?,?,?,?,?, 'draft',?,?,?,?)",
                    (child_id, c["trial_id"], level, c["dose"], c["dose_unit"],
                     planned_n, c["window_days"], c["cohort_id"], did, rationale, decision_ts))
                self.conn.execute(
                    "UPDATE cohorts SET status='closed',decided_at=? WHERE cohort_id=?",
                    (decision_ts, c["cohort_id"]))

            append_event(self.conn, "decision_issued", actor, {
                "decision_id": did, "cohort_id": c["cohort_id"],
                "snapshot_id": snapshot_id, "action": action,
                "child_cohort_id": child_id, "proof_hash": proof_hash,
                "engine_recommendation": outcome["recommendation"],
                "votes_cast": len(votes), "independent_cast": independent_yes,
            }, c["cohort_id"])
            self.conn.execute(
                "INSERT INTO decisions(id,cohort_id,snapshot_id,action,outcome,"
                "child_cohort_id,proof_hash,proof_bundle,created_at,created_by)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (did, c["cohort_id"], snapshot_id, action,
                 outcome["recommendation"], child_id, proof_hash,
                 _json_dumps(proof), decision_ts, actor))
        return self.get_decision(did)

    def get_decision(self, decision_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
        if row is None:
            raise NotFound(f"决定 {decision_id}")
        d = dict(row)
        d["decision_id"] = row["id"]
        d["proof_bundle"] = json.loads(row["proof_bundle"])
        return d

    def verify_proof(self, decision_id: str, tampered_proof: dict | None = None) -> dict:
        """独立校验决策证明：哈希、签名、门槛、快照门、规则结论、日志链。"""
        row = self.conn.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
        if row is None:
            raise NotFound(f"决定 {decision_id}")
        stored = json.loads(row["proof_bundle"])
        proof = tampered_proof or stored
        checks = []

        def check(name, ok, detail=""):
            checks.append({"check": name, "passed": bool(ok), "detail": detail})

        embedded_hash = proof.pop("proof_hash", None) if tampered_proof else proof.get("proof_hash")
        recomputed = canonical_hash({k: v for k, v in proof.items() if k != "proof_hash"})
        check("proof_hash_unchanged", recomputed == row["proof_hash"] == embedded_hash,
              f"recomputed={recomputed[:12]}")

        snap_row = self.conn.execute(
            "SELECT * FROM snapshots WHERE id=?", (proof["snapshot_id"],)).fetchone()
        check("snapshot_hash_anchors_decision",
              proof["snapshot_content_hash"] == snap_row["content_hash"],
              snap_row["content_hash"][:12])
        check("snapshot_payload_hash_recomputed",
              canonical_hash(proof["snapshot_payload"]) == snap_row["content_hash"])
        check("snapshot_not_superseded_now", snap_row["superseded"] == 0)

        check("all_gates_passed", all(
            g["passed"] for k, g in proof["gates"].items() if k != "ready"))
        eng = proof["rule_engine"]
        spec = json.loads(self.conn.execute(
            "SELECT spec FROM rulesets WHERE version=?",
            (eng["ruleset_version"],)).fetchone()["spec"])
        re_eval = rules.evaluate(proof["snapshot_payload"], spec)
        check("engine_recomputation_matches",
              re_eval["recommendation"] == eng["recommendation"]
              and re_eval["dlt_count"] == eng["dlt_count"],
              f"{re_eval['recommendation']}/{re_eval['dlt_count']}")

        all_sig = True
        bound_hashes = set()
        ind = 0
        for v in proof["votes"]:
            m = self.conn.execute(
                "SELECT * FROM committee_members WHERE member_id=?", (v["member_id"],)
            ).fetchone()
            msg = canonical_json({
                "snapshot_id": proof["snapshot_id"],
                "content_hash": snap_row["content_hash"],
                "action": v["action"], "member_id": v["member_id"],
            })
            ok = verify_hmac(m["hmac_key"], msg, v["signature"])
            bound_hashes.add(
                self.conn.execute(
                    "SELECT content_hash FROM votes WHERE member_id=? AND snapshot_id=?",
                    (v["member_id"], proof["snapshot_id"])).fetchone()["content_hash"])
            all_sig &= ok
            if m["role"] == "independent":
                ind += 1
        check("all_vote_signatures_valid", all_sig)
        check("every_vote_bound_single_snapshot", bound_hashes == {snap_row["content_hash"]},
              f"distinct={len(bound_hashes)}")
        check("quorum_met",
              len(proof["votes"]) >= QUORUM and ind >= REQUIRED_INDEPENDENT,
              f"{len(proof['votes'])}票/独立{ind}")

        chain = verify_chain(self.conn)
        check("journal_hashchain_intact", chain["ok"],
              f"events={chain['events']}" + ("" if chain["ok"] else f" broken@{chain['broken_at']}"))
        check("action_not_more_aggressive_than_engine",
              rules.action_within_engine(proof["action"], eng["recommendation"]),
              f"action={proof['action']} vs engine={eng['recommendation']}")

        return {"decision_id": decision_id,
                "verified": all(c["passed"] for c in checks),
                "checks": checks}

    # ------------------------------------------------------------- 查询/时钟
    def advance_clock(self, ts: str) -> dict:
        with self.conn:
            value = set_clock(self.conn, ts)
            append_event(self.conn, "clock_advanced", "system", {"now": value})
        return {"now": value}

    def get_state(self, cohort_id: str | None = None) -> dict:
        trials = [dict(r) for r in self.conn.execute(
            "SELECT * FROM trials ORDER BY trial_id")]
        cohorts = []
        rows = self.conn.execute("SELECT cohort_id FROM cohorts ORDER BY cohort_id")
        if cohort_id:
            rows = self.conn.execute(
                "SELECT cohort_id FROM cohorts WHERE cohort_id=?", (cohort_id,))
        for r in rows:
            cohorts.append(self.get_cohort(r["cohort_id"]))
        members = [{"member_id": r["member_id"], "name": r["name"], "role": r["role"],
                    "active": bool(r["active"])}
                   for r in self.conn.execute(
                       "SELECT * FROM committee_members ORDER BY member_id")]
        rulesets = [{"version": r["version"], "spec": json.loads(r["spec"]),
                     "active": bool(r["active"]), "note": r["note"],
                     "published_at": r["published_at"]}
                    for r in self.conn.execute(
                        "SELECT * FROM rulesets ORDER BY version")]
        holds = [dict(r) for r in self.conn.execute(
            "SELECT * FROM holds ORDER BY created_at DESC")]
        snapshots = [{"snapshot_id": r["id"], "cohort_id": r["cohort_id"],
                      "superseded": bool(r["superseded"]),
                      "ruleset_version": r["ruleset_version"],
                      "content_hash": r["content_hash"][:16],
                      "created_at": r["created_at"]}
                     for r in self.conn.execute(
                         "SELECT * FROM snapshots ORDER BY seq")]
        decisions = [dict(r) for r in self.conn.execute(
            "SELECT id,cohort_id,snapshot_id,action,outcome,child_cohort_id,"
            "proof_hash,created_at FROM decisions ORDER BY created_at")]
        drafts = self.list_vote_drafts()
        chain = verify_chain(self.conn)
        return {
            "now": now_iso(self.conn),
            "trials": trials,
            "cohorts": cohorts,
            "committee": members,
            "rulesets": rulesets,
            "holds": holds,
            "snapshots": snapshots,
            "decisions": decisions,
            "drafts": drafts,
            "journal": {"events": chain["events"], "head": chain["head"][:16],
                        "chain_ok": chain["ok"]},
        }

    def list_journal(self, cohort_id: str | None = None, limit: int = 100) -> list:
        if cohort_id:
            rows = self.conn.execute(
                "SELECT seq,event_type,cohort_id,actor,event_hash,prev_hash,created_at"
                " FROM journal WHERE cohort_id=? ORDER BY seq DESC LIMIT ?",
                (cohort_id, limit)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT seq,event_type,cohort_id,actor,event_hash,prev_hash,created_at"
                " FROM journal ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
