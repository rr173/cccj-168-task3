"""监管稽核决定归档包。

获授权稽核员针对已签发的队列决定生成「决定归档包」：

- 请求时固定三样东西：决定证明（完整性闸口复核）、相关日志区间
  [1, 请求当时的链头]、委员角色名册（个人密钥永不导出）；
- 相同决定 + 相同导出策略只生成一份结果：服务锁串行 + 部分唯一索引兜底，
  并发/重复请求幂等回放同一份归档；
- 生成可中断续传：分块处理日志区间并逐步持久化检查点，中断后从检查点
  继续，且严格限定在请求时固定的区间内——绝不混入后续日志；
- 包可下载、可独立验真：verify_package 是不接触数据库的纯函数，
  对下载的包 JSON 逐项重算（包哈希/哈希链/证明锚定/引擎重算/法定人数）；
- 旧包不可改写：之后出现的新安全事实只在归档视图上产生「覆盖新区间」
  提示，稽核员可发起 renew 生成新归档，旧归档标记 superseded 但内容不变；
- 归档自身的事件类型不属于实质性事件，不影响给药、投票草稿与原有证明校验。
"""
from __future__ import annotations

import json
import uuid

from . import rules
from .clock import now_iso
from .crypto import canonical_hash
from .errors import Conflict, Forbidden, NotFound, ValidationFailed
from .store import GENESIS_HASH, MATERIAL_EVENT_TYPES, append_event

# 导出策略：决定归档包的内容与脱敏方式。策略内容哈希是去重键的一部分。
ARCHIVE_POLICY_DEFAULTS = {
    # 隐藏非必要身份：委员名册中的姓名 → 保留委员编号与角色（法定人数可核对）。
    # 决定证明本身是哈希锚定的封存件，逐字保留、不可脱敏，否则证明哈希失效。
    "redact_member_names": False,
    # 包内附固定区间的哈希链日志（独立验真链条所需）；个人密钥任何策略下都不导出。
    "include_journal": True,
}

JOURNAL_CHUNK = 25  # 日志分块大小：每块落一次检查点，支撑可续传的中断语义


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


class ArchiveInterrupted(Exception):
    """生成中断（模拟进程崩溃/掉电）：检查点已持久化，归档保持 building 可续传。"""


class ArchiveBuildError(Exception):
    """生成失败（数据损坏或模拟故障）：归档置为 failed，可在同一固定区间内重试。"""


def _contains_key_named(obj, key: str) -> bool:
    """递归扫描：包内任何层级都不得出现指定字段（如 hmac_key）。"""
    if isinstance(obj, dict):
        return any(k == key or _contains_key_named(v, key) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_contains_key_named(v, key) for v in obj)
    return False


def normalize_policy(policy: dict | None) -> dict:
    """规范化导出策略：补默认值、拒绝未知项与非法类型（请求参数校验）。"""
    policy = dict(policy or {})
    unknown = sorted(set(policy) - set(ARCHIVE_POLICY_DEFAULTS))
    if unknown:
        raise ValidationFailed(f"未知导出策略项: {unknown}")
    merged = dict(ARCHIVE_POLICY_DEFAULTS)
    for k, v in policy.items():
        if not isinstance(v, bool):
            raise ValidationFailed(f"导出策略 {k} 必须为布尔值")
        merged[k] = v
    return merged


def _event_hash(ev: dict) -> str:
    return canonical_hash({
        "seq": ev.get("seq"), "event_type": ev.get("event_type"),
        "cohort_id": ev.get("cohort_id"), "actor": ev.get("actor"),
        "payload": ev.get("payload"), "prev_hash": ev.get("prev_hash"),
        "created_at": ev.get("created_at"),
    })


def verify_package(pkg: dict) -> dict:
    """独立验真归档包：纯函数，不接触数据库。

    对下载的包逐项重算：包哈希、日志区间哈希链（含终点锚定）、证明哈希、
    快照锚定、规则引擎重算、五门、法定人数（按包内名册角色）、投票锚定、
    动作-引擎一致性、决定事件交叉锚定。个人密钥按设计不导出，因此签名
    不可离线重算——以证明内签发时的校验结论为准（在线可经原证明校验端点复核）。
    """
    checks = []

    def check(name, ok, detail=""):
        checks.append({"check": name, "passed": bool(ok), "detail": detail})

    if not isinstance(pkg, dict):
        return {"verified": False,
                "checks": [{"check": "package_shape", "passed": False,
                            "detail": "包不是 JSON 对象"}]}

    embedded = pkg.get("package_hash")
    recomputed = canonical_hash({k: v for k, v in pkg.items() if k != "package_hash"})
    check("package_hash_unchanged",
          embedded is not None and embedded == recomputed,
          f"recomputed={recomputed[:12]}")

    check("no_personal_keys_exported", not _contains_key_named(pkg, "hmac_key"),
          "递归扫描：包内无委员个人密钥字段")

    rng = pkg.get("log_range") or {}
    journal = pkg.get("journal") or []
    if journal:
        ok, prev, expect, broken = True, GENESIS_HASH, rng.get("seq_from", 1), None
        for ev in journal:
            if (ev.get("seq") != expect or ev.get("prev_hash") != prev
                    or _event_hash(ev) != ev.get("event_hash")):
                ok, broken = False, ev.get("seq")
                break
            prev, expect = ev["event_hash"], expect + 1
        tail_ok = expect - 1 == rng.get("seq_to") and prev == rng.get("head_hash")
        check("journal_chain_intact_in_range", ok and tail_ok,
              f"events={len(journal)}"
              + (f" broken@{broken}" if not ok else "")
              + ("" if tail_ok else " 区间终点/链头哈希不锚定"))
    else:
        check("journal_chain_intact_in_range", True, "导出策略未包含日志区间（跳过）")

    proof = pkg.get("decision_proof") or {}
    proof_recomputed = (canonical_hash({k: v for k, v in proof.items() if k != "proof_hash"})
                        if proof else "")
    check("proof_hash_unchanged",
          bool(proof) and proof.get("proof_hash") == proof_recomputed == pkg.get("proof_hash"),
          f"recomputed={proof_recomputed[:12]}")

    sp = proof.get("snapshot_payload")
    check("snapshot_payload_anchors_decision",
          bool(sp) and canonical_hash(sp) == proof.get("snapshot_content_hash"))

    spec = (pkg.get("ruleset") or {}).get("spec")
    if sp and spec:
        re_eval = rules.evaluate(sp, spec)
        eng = proof.get("rule_engine") or {}
        check("engine_recomputation_matches",
              re_eval["recommendation"] == eng.get("recommendation")
              and re_eval["dlt_count"] == eng.get("dlt_count"),
              f"{re_eval['recommendation']}/{re_eval['dlt_count']}")
    else:
        check("engine_recomputation_matches", False, "缺少快照载荷或规则规格")

    gates = proof.get("gates") or {}
    check("all_gates_passed",
          bool(gates) and all(g.get("passed") for k, g in gates.items() if k != "ready"))

    roles = {m.get("member_id"): m.get("role") for m in (pkg.get("committee") or [])}
    votes = proof.get("votes") or []
    quorum = proof.get("quorum") or {}
    ind = sum(1 for v in votes if roles.get(v.get("member_id")) == "independent")
    check("quorum_met",
          bool(votes) and 0 < quorum.get("required", 0) <= len(votes)
          and 0 < quorum.get("independent_required", 0) <= ind
          and len(votes) == quorum.get("cast") and ind == quorum.get("independent_cast"),
          f"{len(votes)}票/独立{ind}")

    pkg_votes = pkg.get("votes") or []
    bound = {v.get("content_hash") for v in pkg_votes}
    check("every_vote_bound_single_snapshot",
          bool(pkg_votes) and bound == {proof.get("snapshot_content_hash")},
          f"distinct={len(bound)}")

    check("vote_signatures_attested",
          bool(votes) and all(v.get("signature_valid") for v in votes),
          "密钥不导出：以证明封存件内签发时的签名校验结论为准")

    eng_rec = (proof.get("rule_engine") or {}).get("recommendation")
    check("action_not_more_aggressive_than_engine",
          bool(eng_rec) and rules.action_within_engine(proof.get("action"), eng_rec),
          f"action={proof.get('action')} vs engine={eng_rec}")

    if journal:
        anchored = any(
            ev.get("event_type") == "decision_issued"
            and (ev.get("payload") or {}).get("decision_id") == pkg.get("decision_id")
            and (ev.get("payload") or {}).get("proof_hash") == pkg.get("proof_hash")
            for ev in journal)
        check("decision_event_anchored_in_journal", anchored,
              "日志区间内存在同 proof_hash 的 decision_issued 事件")

    return {"archive_id": pkg.get("archive_id"),
            "decision_id": pkg.get("decision_id"),
            "verified": all(c["passed"] for c in checks),
            "checks": checks}


class ArchiveService:
    """归档领域服务。proof_verifier 复用平台既有 11 项证明校验。"""

    def __init__(self, conn, proof_verifier, lock):
        self.conn = conn
        self._verify_proof = proof_verifier
        self._lock = lock

    # ------------------------------------------------------------- 授权
    def _authorize(self, auditor_key: str | None):
        row = self.conn.execute(
            "SELECT * FROM auditors WHERE api_key=? AND active=1",
            (auditor_key or "",)).fetchone()
        if row is None:
            raise Forbidden("稽核员未授权：密钥缺失、无效或已停用")
        return row

    def _require(self, archive_id: str):
        row = self.conn.execute(
            "SELECT * FROM decision_archives WHERE id=?", (archive_id,)).fetchone()
        if row is None:
            raise NotFound(f"归档 {archive_id}")
        return row

    # ------------------------------------------------------------- 请求
    def request_archive(self, auditor_key: str | None, decision_id: str,
                        policy: dict | None = None, request_id: str | None = None,
                        renew: bool = False) -> dict:
        """发起归档：授权 → 参数校验 → 证明完整性闸口 → 固定日志区间 → 排队。

        幂等：同一 request_id 或同一（决定, 策略）的重复请求回放既有结果；
        renew=True 时以新固定区间生成新归档并取代旧的活跃归档。
        """
        auditor = self._authorize(auditor_key)
        with self._lock:
            d = self.conn.execute(
                "SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
            if d is None:
                raise NotFound(f"决定 {decision_id}")
            policy = normalize_policy(policy)
            policy_hash = canonical_hash(policy)

            # 1) 幂等回放：同一 request_id 直接返回首次结果
            if request_id:
                dup = self.conn.execute(
                    "SELECT * FROM decision_archives WHERE request_id=?",
                    (request_id,)).fetchone()
                if dup is not None:
                    if (dup["decision_id"], dup["policy_hash"]) != (decision_id, policy_hash):
                        raise Conflict(
                            "archive_param_conflict",
                            "同一 request_id 携带了不同的决定或导出策略，拒绝重放")
                    return {"archive": self._view(dup), "replayed": True}

            # 2) 相同决定 + 相同导出策略的活跃归档已存在：只回放，不另生一份
            active = self.conn.execute(
                "SELECT * FROM decision_archives WHERE decision_id=? AND policy_hash=?"
                " AND superseded_by IS NULL",
                (decision_id, policy_hash)).fetchone()
            if active is not None and not renew:
                return {"archive": self._view(active), "replayed": True}

            # 3) 新建/取代前的证明完整性闸口：证明损坏明确拒绝
            self._assert_proof_intact(decision_id)

            if active is not None and active["status"] in ("queued", "building"):
                raise Conflict("archive_in_progress",
                               "相同策略的归档正在排队/生成中，不能另起新归档；"
                               "请先完成或等待其结束")

            # 4) 固定日志区间：先取链头，再追加请求事件（归档自身事件不进包）
            head = self.conn.execute(
                "SELECT seq, event_hash FROM journal ORDER BY seq DESC LIMIT 1").fetchone()
            seq_to, head_hash = head["seq"], head["event_hash"]
            aid = _uid("AR")
            ts = now_iso(self.conn)
            with self.conn:
                if active is not None:
                    append_event(self.conn, "archive_superseded", auditor["auditor_id"], {
                        "archive_id": active["id"], "superseded_by": aid,
                        "decision_id": decision_id, "cohort_id": d["cohort_id"],
                        "reason": "稽核员发起覆盖新区间的归档"}, d["cohort_id"])
                    self.conn.execute(
                        "UPDATE decision_archives SET superseded_by=?, status='superseded'"
                        " WHERE id=?", (aid, active["id"]))
                append_event(self.conn, "archive_requested", auditor["auditor_id"], {
                    "archive_id": aid, "decision_id": decision_id,
                    "cohort_id": d["cohort_id"], "policy": policy,
                    "policy_hash": policy_hash, "request_id": request_id,
                    "seq_from": 1, "seq_to": seq_to, "head_hash": head_hash,
                    "renew": bool(renew)}, d["cohort_id"])
                self.conn.execute(
                    "INSERT INTO decision_archives(id,request_id,decision_id,cohort_id,"
                    "policy,policy_hash,status,seq_from,seq_to,head_hash,"
                    "requested_by,requested_at)"
                    " VALUES(?,?,?,?,?,?, 'queued',1,?,?,?,?)",
                    (aid, request_id, decision_id, d["cohort_id"],
                     json.dumps(policy, ensure_ascii=False), policy_hash,
                     seq_to, head_hash, auditor["auditor_id"], ts))
            return {"archive": self._view(self._require(aid)), "replayed": False}

    def _assert_proof_intact(self, decision_id: str):
        """证明损坏即拒绝归档。

        snapshot_not_superseded_now 是「当前时效」检查而非损坏：决定签发后
        出现新安全事实不影响归档既有决定（只触发「覆盖新区间」提示）。
        """
        result = self._verify_proof(decision_id)
        broken = [c["check"] for c in result["checks"]
                  if not c["passed"] and c["check"] != "snapshot_not_superseded_now"]
        if broken:
            raise Conflict("proof_corrupted",
                           "决定证明完整性校验未通过，拒绝归档：" + "；".join(broken))

    # ------------------------------------------------------------- 生成/续传
    def build_archive(self, auditor_key: str | None, archive_id: str,
                      simulate_crash_after: int | None = None,
                      simulate_fail: bool = False) -> dict:
        """开始或继续生成。中断（崩溃）保持 building 可续传；失败置 failed 可重试。

        无论中断多少次，日志读取严格限定在请求时固定的 [seq_from, seq_to]，
        后续新事件绝不混入本包。
        """
        auditor = self._authorize(auditor_key)
        with self._lock:
            row = self._require(archive_id)
            if row["status"] == "ready" and not row["superseded_by"]:
                return {"archive": self._view(row), "interrupted": False}  # 幂等
            if row["superseded_by"]:
                raise Conflict("archive_superseded",
                               "该归档已被新归档取代，不能继续生成")
            policy = json.loads(row["policy"])
            progress = json.loads(row["progress"]) if row["progress"] else {}
            if row["status"] == "failed":
                progress = {}  # 重试：同一固定区间内从头生成
            parts = progress.get("parts") or {}
            seq_to = row["seq_to"]
            progress["built_upto_seq"] = progress.get("built_upto_seq") or 0
            progress["parts"] = parts
            self.conn.execute(
                "UPDATE decision_archives SET status='building', error=NULL, progress=?"
                " WHERE id=?",
                (json.dumps(progress, ensure_ascii=False), archive_id))
            self.conn.commit()
            try:
                # 阶段 1：决定证明（生成时复核封存件未被损坏）
                if "proof" not in parts:
                    parts["proof"] = self._load_proof_parts(row)
                    progress["parts"] = parts
                    self._save_progress(archive_id, progress)
                # 阶段 2：固定区间日志分块（逐块校验哈希衔接并落检查点）
                if policy["include_journal"]:
                    events = parts.get("journal") or []
                    built_upto = progress.get("built_upto_seq") or 0
                    if simulate_crash_after == 0 and built_upto == 0 and not events:
                        raise ArchiveInterrupted()  # 崩溃在日志阶段开始前
                    chunks_done = 0
                    while built_upto < seq_to:
                        upper = min(built_upto + JOURNAL_CHUNK, seq_to)
                        chunk = self._journal_chunk(built_upto + 1, upper)
                        self._check_chunk_links(events, chunk)
                        events.extend(chunk)
                        built_upto = upper
                        chunks_done += 1
                        parts["journal"] = events
                        progress["built_upto_seq"] = built_upto
                        progress["parts"] = parts
                        self._save_progress(archive_id, progress)  # 检查点提交
                        if (simulate_crash_after is not None
                                and chunks_done >= simulate_crash_after):
                            raise ArchiveInterrupted()
                # 阶段 3：委员角色名册（脱敏；个人密钥永不导出）
                if "committee" not in parts:
                    parts["committee"] = self._committee_roster(policy)
                    progress["parts"] = parts
                    self._save_progress(archive_id, progress)
                if simulate_fail:
                    raise ArchiveBuildError("模拟的生成故障（如写出 I/O 错误）")
                # 阶段 4：组装定稿，计算包哈希
                package = self._assemble(row, policy, parts)
                ts = now_iso(self.conn)
                with self.conn:
                    append_event(self.conn, "archive_ready", auditor["auditor_id"], {
                        "archive_id": archive_id, "decision_id": row["decision_id"],
                        "cohort_id": row["cohort_id"],
                        "package_hash": package["package_hash"],
                        "seq_to": seq_to}, row["cohort_id"])
                    self.conn.execute(
                        "UPDATE decision_archives SET status='ready', package=?,"
                        " package_hash=?, finished_at=?, progress=NULL, error=NULL"
                        " WHERE id=?",
                        (json.dumps(package, ensure_ascii=False),
                         package["package_hash"], ts, archive_id))
                return {"archive": self._view(self._require(archive_id)),
                        "interrupted": False}
            except ArchiveInterrupted:
                self.conn.commit()  # 检查点已逐块持久化；保持 building 等待续传
                return {"archive": self._view(self._require(archive_id)),
                        "interrupted": True}
            except ArchiveBuildError as e:
                with self.conn:
                    append_event(self.conn, "archive_failed", auditor["auditor_id"], {
                        "archive_id": archive_id, "decision_id": row["decision_id"],
                        "cohort_id": row["cohort_id"], "error": str(e)}, row["cohort_id"])
                    self.conn.execute(
                        "UPDATE decision_archives SET status='failed', error=? WHERE id=?",
                        (str(e), archive_id))
                return {"archive": self._view(self._require(archive_id)),
                        "interrupted": False}

    def _save_progress(self, archive_id: str, progress: dict):
        self.conn.execute(
            "UPDATE decision_archives SET progress=? WHERE id=?",
            (json.dumps(progress, ensure_ascii=False), archive_id))
        self.conn.commit()

    def _load_proof_parts(self, row) -> dict:
        d = self.conn.execute(
            "SELECT * FROM decisions WHERE id=?", (row["decision_id"],)).fetchone()
        proof = json.loads(d["proof_bundle"])
        recomputed = canonical_hash({k: v for k, v in proof.items() if k != "proof_hash"})
        if recomputed != d["proof_hash"] or proof.get("proof_hash") != d["proof_hash"]:
            raise ArchiveBuildError("决定证明哈希与签发时不一致（证明已损坏）")
        if canonical_hash(proof["snapshot_payload"]) != proof["snapshot_content_hash"]:
            raise ArchiveBuildError("快照载荷哈希锚定失败（证明已损坏）")
        rs = self.conn.execute(
            "SELECT * FROM rulesets WHERE version=?",
            (proof["rule_engine"]["ruleset_version"],)).fetchone()
        votes = self.conn.execute(
            "SELECT id, member_id, action, content_hash, signature, created_at"
            " FROM votes WHERE snapshot_id=? ORDER BY created_at",
            (d["snapshot_id"],)).fetchall()
        return {
            "decision_proof": proof,
            "proof_hash": d["proof_hash"],
            "ruleset": {"version": rs["version"], "spec": json.loads(rs["spec"])},
            "votes": [{"vote_id": v["id"], "member_id": v["member_id"],
                       "action": v["action"], "content_hash": v["content_hash"],
                       "signature": v["signature"], "created_at": v["created_at"]}
                      for v in votes],
        }

    def _journal_chunk(self, lo: int, hi: int) -> list[dict]:
        rows = self.conn.execute(
            "SELECT seq,event_type,cohort_id,actor,payload,event_hash,prev_hash,created_at"
            " FROM journal WHERE seq BETWEEN ? AND ? ORDER BY seq", (lo, hi)).fetchall()
        if len(rows) != hi - lo + 1:
            raise ArchiveBuildError(f"日志区间 [{lo},{hi}] 事件缺失")
        return [{"seq": r["seq"], "event_type": r["event_type"],
                 "cohort_id": r["cohort_id"], "actor": r["actor"],
                 "payload": json.loads(r["payload"]),
                 "prev_hash": r["prev_hash"], "event_hash": r["event_hash"],
                 "created_at": r["created_at"]} for r in rows]

    def _check_chunk_links(self, events: list[dict], chunk: list[dict]):
        prev = events[-1]["event_hash"] if events else GENESIS_HASH
        expect = (events[-1]["seq"] + 1) if events else 1
        for ev in chunk:
            if (ev["seq"] != expect or ev["prev_hash"] != prev
                    or _event_hash(ev) != ev["event_hash"]):
                raise ArchiveBuildError(f"日志区间哈希链校验失败 @seq={ev['seq']}")
            prev, expect = ev["event_hash"], expect + 1

    def _committee_roster(self, policy: dict) -> list[dict]:
        redact = policy["redact_member_names"]
        return [{
            "member_id": m["member_id"],
            "role": m["role"],
            "name": "[已隐藏]" if redact else m["name"],
            "active": bool(m["active"]),
            # 个人密钥（hmac_key）任何策略下都不进入归档包
        } for m in self.conn.execute(
            "SELECT * FROM committee_members ORDER BY member_id")]

    def _assemble(self, row, policy: dict, parts: dict) -> dict:
        redactions = ["committee_members.hmac_key：委员个人密钥任何策略下都不导出"]
        if policy["redact_member_names"]:
            redactions.append(
                "committee[].name：委员姓名已隐藏（保留编号与角色供法定人数核对；"
                "决定证明为哈希锚定封存件，逐字保留）")
        proof_parts = parts["proof"]
        proof = proof_parts["decision_proof"]
        pkg = {
            "package_version": 1,
            "archive_id": row["id"],
            "decision_id": row["decision_id"],
            "cohort_id": row["cohort_id"],
            "trial_id": proof.get("trial_id"),
            "snapshot_id": proof.get("snapshot_id"),
            "created_at": now_iso(self.conn),
            "requested_by": row["requested_by"],
            "policy": policy,
            "policy_hash": row["policy_hash"],
            "log_range": {"seq_from": row["seq_from"], "seq_to": row["seq_to"],
                          "head_hash": row["head_hash"]},
            "decision_proof": proof,
            "proof_hash": proof_parts["proof_hash"],
            "ruleset": proof_parts["ruleset"],
            "votes": proof_parts["votes"],
            "committee": parts["committee"],
            "journal": parts.get("journal") or [],
            "redactions": redactions,
        }
        pkg["package_hash"] = canonical_hash(pkg)
        return pkg

    # ------------------------------------------------------------- 下载/校验
    def get_package(self, auditor_key: str | None, archive_id: str) -> str:
        """下载包 JSON（ready 或已被取代的归档都可下载：旧包内容永不被改写）。"""
        self._authorize(auditor_key)
        row = self._require(archive_id)
        if row["package"] is None:
            raise Conflict("archive_not_ready",
                           f"归档当前状态 {self._view(row)['status']}，尚无包可下载")
        return row["package"]

    def verify_archive(self, auditor_key: str | None, archive_id: str | None = None,
                       package: dict | None = None) -> dict:
        """校验下载内容：传入下载的包 JSON 做独立验真；缺省校验库内包。"""
        self._authorize(auditor_key)
        if package is None:
            row = self._require(archive_id)
            if row["package"] is None:
                raise Conflict("archive_not_ready", "归档尚未生成，无包可校验")
            package = json.loads(row["package"])
        elif archive_id and package.get("archive_id") != archive_id:
            raise Conflict("archive_param_conflict", "上传校验的包不属于该归档")
        return verify_package(package)

    # ------------------------------------------------------------- 查询
    def get_archive(self, auditor_key: str | None, archive_id: str) -> dict:
        self._authorize(auditor_key)
        return self._view(self._require(archive_id))

    def list_archives(self, auditor_key: str | None,
                      cohort_id: str | None = None) -> list[dict]:
        self._authorize(auditor_key)
        if cohort_id:
            rows = self.conn.execute(
                "SELECT * FROM decision_archives WHERE cohort_id=?"
                " ORDER BY requested_at,id", (cohort_id,)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM decision_archives ORDER BY requested_at,id").fetchall()
        return [self._view(r) for r in rows]

    def _view(self, row) -> dict:
        """工作台视图：五种状态 + 新安全事实提示（不含包内容）。"""
        head = self.conn.execute(
            "SELECT seq FROM journal ORDER BY seq DESC LIMIT 1").fetchone()
        head_seq = head["seq"] if head else 0
        prog = json.loads(row["progress"]) if row["progress"] else None
        view = {
            "archive_id": row["id"],
            "decision_id": row["decision_id"],
            "cohort_id": row["cohort_id"],
            "policy": json.loads(row["policy"]),
            "policy_hash": row["policy_hash"],
            "status": "superseded" if row["superseded_by"] else row["status"],
            "log_range": {"seq_from": row["seq_from"], "seq_to": row["seq_to"],
                          "head_hash": row["head_hash"]},
            "package_hash": row["package_hash"],
            "error": row["error"],
            "requested_by": row["requested_by"],
            "requested_at": row["requested_at"],
            "finished_at": row["finished_at"],
            "superseded_by": row["superseded_by"],
            "progress": ({k: v for k, v in prog.items() if k != "parts"}
                         if prog else None),
        }
        if row["superseded_by"] is None:
            placeholders = ",".join("?" for _ in MATERIAL_EVENT_TYPES)
            new_material = self.conn.execute(
                f"SELECT COUNT(*) c FROM journal WHERE cohort_id=? AND seq>?"
                f" AND event_type IN ({placeholders})",
                (row["cohort_id"], row["seq_to"], *MATERIAL_EVENT_TYPES)).fetchone()["c"]
            view["freshness"] = {
                "head_seq_now": head_seq,
                "new_events": max(0, head_seq - row["seq_to"]),
                "new_material_events": new_material,
                "stale": new_material > 0,
                "hint": (f"归档后出现 {new_material} 条新的安全事实：旧包不会被改写，"
                         "建议创建覆盖新区间的归档") if new_material > 0 else "",
            }
        else:
            view["freshness"] = None
        return view
