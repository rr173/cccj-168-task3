"""平台不变量测试（标准库 unittest，零依赖）。"""
from __future__ import annotations

import json
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.crypto import canonical_hash, canonical_json, hmac_hex
from app.errors import Conflict, DomainError, ValidationFailed
from app.services import Services
from app.store import connect

T0 = "2026-10-01T09:00:00+00:00"
DOSE = "2026-10-01T10:00:00+00:00"
AFTER_WINDOW = "2026-10-22T10:01:00+00:00"


class PlatformBase(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.svc = Services(self.conn)
        self.svc.bootstrap()
        self.svc.advance_clock(T0)
        self.tid = self.svc.create_trial("test", "UT 递增试验")["trial_id"]

    def cid(self, planned_n=3, window_days=21):
        return self.svc.create_cohort(
            "test", self.tid, 1, 10.0, "mg", planned_n, window_days)["cohort_id"]

    def enroll_freeze_dose(self, cid, n=3, when=DOSE):
        sids = [self.svc.enroll_subject("test", cid)["subject_id"] for _ in range(n)]
        self.svc.freeze_cohort("test", cid)
        for s in sids:
            self.svc.record_administration("test", cid, s, given_at=when)
        return sids

    def close_windows(self):
        self.svc.advance_clock(AFTER_WINDOW)

    def sign(self, member, sid, action, content_hash):
        key = self.conn.execute(
            "SELECT hmac_key FROM committee_members WHERE member_id=?", (member,)
        ).fetchone()["hmac_key"]
        return hmac_hex(key, canonical_json({
            "snapshot_id": sid, "content_hash": content_hash,
            "action": action, "member_id": member,
        }))

    def vote(self, sid, member, action, version, ch=None):
        ch = ch or self.svc.get_snapshot(sid)["content_hash"]
        return self.svc.cast_vote(
            "test", sid, member, action, self.sign(member, sid, action, ch), version)

    def two_votes_and_decide(self, sid, action="escalate"):
        self.vote(sid, "CM-DAC", action, 0)
        self.vote(sid, "CM-ELN", action, 1)
        return self.svc.issue_decision("test", sid)


class PlatformTest(PlatformBase):
    # ---------------------------------------------------------- 1 冻结
    def test_freeze_locks_dose_and_set(self):
        cid = self.cid()
        self.svc.enroll_subject("test", cid)
        self.svc.enroll_subject("test", cid)
        with self.assertRaises(Conflict) as cm:
            self.svc.freeze_cohort("test", cid)
        self.assertEqual(cm.exception.code, "freeze_set_mismatch")
        self.svc.enroll_subject("test", cid)
        self.svc.freeze_cohort("test", cid)
        with self.assertRaises(Conflict):
            self.svc.enroll_subject("test", cid)
        # 剂量方案不可改：给药剂量必须等于冻结值
        sid = self.svc.get_cohort(cid)["subjects"][0]["id"]
        with self.assertRaises(Conflict):
            self.svc.record_administration("test", cid, sid, dose=20.0, given_at=DOSE)

    # ---------------------------------------------------------- 2 五道门
    def test_gates_block_until_window_and_pending(self):
        cid = self.cid()
        sids = self.enroll_freeze_dose(cid)
        self.svc.report_ae("test", cid, sids[0], "ALT 升高", "grade3",
                           "2026-10-04T00:00:00+00:00")
        self.svc.add_pending("test", cid, "lab", "血药浓度缺失", sids[1])

        # 窗口未到 + 未裁定 + 未补缺失 → 快照可构建（留证）但不可投票
        snap = self.svc.create_snapshot("test", cid)
        self.assertFalse(snap["gates"]["ready"])
        with self.assertRaises(Conflict) as cm:
            self.vote(snap["snapshot_id"], "CM-DAC", "escalate", 0)
        self.assertEqual(cm.exception.code, "gates_not_satisfied")

        self.svc.adjudicate_ae("test", self.svc.get_cohort(cid)["adverse_events"][0]["id"],
                               True, True, "确认 DLT")
        pid = self.svc.get_cohort(cid)["pending_data"][0]["id"]
        self.svc.resolve_pending("test", pid, "已回收复查，正常")
        self.close_windows()
        snap2 = self.svc.create_snapshot("test", cid)
        self.assertTrue(snap2["gates"]["ready"])
        self.assertEqual(snap2["outcome"]["dlt_count"], 1)
        self.assertEqual(snap2["outcome"]["recommendation"], "expand")

    # ---------------------------------------------------------- 3 迟到 AE
    def test_late_ae_supersedes_snapshot(self):
        cid = self.cid()
        sids = self.enroll_freeze_dose(cid)
        self.close_windows()
        snap = self.svc.create_snapshot("test", cid)
        self.assertTrue(snap["gates"]["ready"])
        self.vote(snap["snapshot_id"], "CM-DAC", "escalate", 0)
        # 决策前到达迟到 grade3 AE
        ae = self.svc.report_ae("test", cid, sids[1], "血小板下降", "grade3",
                                "2026-10-20T00:00:00+00:00")
        self.assertEqual(ae["late"], 1)
        # 旧快照被标记失效，旧票不能再用于决策
        with self.assertRaises(Conflict) as cm:
            self.svc.issue_decision("test", snap["snapshot_id"])
        self.assertEqual(cm.exception.code, "snapshot_superseded")
        # 必须裁定新 AE 后重建快照
        self.svc.adjudicate_ae("test", self.svc.get_cohort(cid)["adverse_events"][-1]["id"],
                               True, True, "迟到事件，确认 DLT")
        snap2 = self.svc.create_snapshot("test", cid)
        self.assertEqual(snap2["outcome"]["dlt_count"], 1)
        self.assertEqual(snap2["outcome"]["recommendation"], "expand")
        # 旧快照的票不能带到新快照：新快照 vote_version=0，须重新投票
        self.assertEqual(snap2["vote_version"], 0)

    # ---------------------------------------------------------- 4 替补
    def test_subject_replacement_bumps_revision_and_invalidates(self):
        cid = self.cid()
        sids = self.enroll_freeze_dose(cid)
        self.close_windows()
        snap = self.svc.create_snapshot("test", cid)
        rep = self.svc.replace_subject("test", cid, sids[2], "受试者撤回知情同意")
        self.assertEqual(rep["revision"], 1)
        with self.assertRaises(Conflict):
            self.svc.issue_decision("test", snap["snapshot_id"])
        # 新受试者在新修订上，需给药并等待新观察窗
        self.svc.record_administration("test", cid, rep["replacement_subject_id"],
                                       given_at="2026-10-22T11:00:00+00:00")
        self.svc.advance_clock("2026-11-13T11:01:00+00:00")
        snap2 = self.svc.create_snapshot("test", cid)
        self.assertTrue(snap2["gates"]["ready"])
        self.assertEqual(snap2["revision"], 1)
        # 被替补者的 AE 不进入新快照
        self.svc.report_ae("test", cid, sids[2], "grade4 event on removed", "grade4",
                           "2026-10-19T00:00:00+00:00")
        aeid = self.svc.get_cohort(cid)["adverse_events"][-1]["id"]
        self.svc.adjudicate_ae("test", aeid, True, True, "x")
        snap3 = self.svc.create_snapshot("test", cid)
        self.assertEqual(snap3["outcome"]["dlt_count"], 0)

    # ---------------------------------------------------------- 5 规则修订
    def test_rule_revision_does_not_recompute_old_snapshot(self):
        cid = self.cid()
        sids = self.enroll_freeze_dose(cid)
        self.close_windows()
        snap = self.svc.create_snapshot("test", cid)  # v1
        self.assertEqual(snap["ruleset_version"], 1)
        # 发布更宽松的修订（grade4 才算 DLT）
        self.svc.publish_ruleset("test", {
            "min_severity_dlt": "grade4",
            "bands": [{"max_dlt": 0, "action": "escalate"},
                      {"max_dlt": None, "action": "stop"}],
        }, "修订：DLT 门槛提高至 4 级")
        # 旧快照仍用 v1 规则，结论不变
        old = self.svc.get_snapshot(snap["snapshot_id"])
        self.assertEqual(old["ruleset_version"], 1)
        self.assertEqual(old["outcome"]["recommendation"], "escalate")
        # 新快照绑定 v2
        snap2 = self.svc.create_snapshot("test", cid)
        self.assertEqual(snap2["ruleset_version"], 2)

    # ---------------------------------------------------------- 6 并发投票
    def test_concurrent_votes_no_splicing(self):
        cid = self.cid()
        self.enroll_freeze_dose(cid)
        self.close_windows()
        snap = self.svc.create_snapshot("test", cid)
        sid = snap["snapshot_id"]
        ch = snap["content_hash"]
        results = {}

        def vote(member):
            try:
                self.vote(sid, member, "escalate", 0, ch=ch)
                results[member] = "ok"
            except Conflict as e:
                results[member] = e.code

        t1 = threading.Thread(target=vote, args=("CM-DAC",))
        t2 = threading.Thread(target=vote, args=("CM-ELN",))
        t1.start(); t2.start(); t1.join(); t2.join()
        # 恰好一个成功，另一个收到版本冲突——不存在基于陈旧视图的合并
        self.assertEqual(sorted(results.values()), ["ok", "snapshot_version_conflict"])
        # 失败者用新版本重试后成功
        self.vote(sid, "CM-ELN", "escalate", 1, ch=ch)
        d = self.svc.issue_decision("test", sid)
        self.assertEqual(d["action"], "escalate")
        self.assertTrue(self.svc.verify_proof(d["decision_id"])["verified"])

    def test_vote_bound_to_snapshot_hash(self):
        cid = self.cid()
        sids = self.enroll_freeze_dose(cid)
        self.close_windows()
        s1 = self.svc.create_snapshot("test", cid)
        self.vote(s1["snapshot_id"], "CM-DAC", "escalate", 0)
        # 新事件 → 新快照
        self.svc.add_pending("test", cid, "lab", "x", sids[0])
        self.svc.resolve_pending("test",
                                 self.svc.get_cohort(cid)["pending_data"][-1]["id"], "补获")
        s2 = self.svc.create_snapshot("test", cid)
        # 委员不能拿 s1 的哈希对 s2 投票
        with self.assertRaises(Conflict):
            self.svc.cast_vote("test", s2["snapshot_id"], "CM-ELN", "escalate",
                               self.sign("CM-ELN", s1["snapshot_id"], "escalate",
                                         s1["content_hash"]), 0)

    # ---------------------------------------------------------- 7 法定人数
    def test_quorum_requires_two_independents(self):
        cid = self.cid()
        self.enroll_freeze_dose(cid)
        self.close_windows()
        sid = self.svc.create_snapshot("test", cid)["snapshot_id"]
        # 1 独立 + 1 申办方：不满足 2 独立
        self.vote(sid, "CM-DAC", "escalate", 0)
        self.vote(sid, "CM-SPO", "escalate", 1)
        with self.assertRaises(Conflict) as cm:
            self.svc.issue_decision("test", sid)
        self.assertEqual(cm.exception.code, "quorum_not_met")
        self.vote(sid, "CM-ELN", "escalate", 2)
        self.svc.issue_decision("test", sid)  # 2 独立 + 1 申办方，通过

    def test_conflicting_actions_block_decision(self):
        cid = self.cid()
        self.enroll_freeze_dose(cid)
        self.close_windows()
        sid = self.svc.create_snapshot("test", cid)["snapshot_id"]
        self.vote(sid, "CM-DAC", "escalate", 0)
        self.vote(sid, "CM-ELN", "stop", 1)
        with self.assertRaises(Conflict) as cm:
            self.svc.issue_decision("test", sid)
        self.assertEqual(cm.exception.code, "vote_conflict")

    # ---------------------------------------------------------- 8 紧急暂停
    def test_emergency_hold_blocks_dosing_keeps_facts(self):
        cid = self.cid()
        sids = [self.svc.enroll_subject("test", cid)["subject_id"] for _ in range(3)]
        self.svc.freeze_cohort("test", cid)
        self.svc.record_administration("test", cid, sids[0], given_at=DOSE)
        self.svc.emergency_hold("test", "cohort", "收到疑似 SAE 信号，立即暂停", cohort_id=cid)
        # 后续给药被阻断
        with self.assertRaises(Conflict) as cm:
            self.svc.record_administration("test", cid, sids[1], given_at=DOSE)
        self.assertEqual(cm.exception.code, "hold_active")
        c = self.svc.get_cohort(cid)
        blocked = [a for a in c["administrations"] if a["held_back"]]
        dosed = [a for a in c["administrations"] if not a["held_back"]]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(len(dosed), 1)  # 已给药事实保留
        self.assertTrue(self.conn.execute(
            "SELECT dose_given FROM subjects WHERE id=?", (sids[0],)).fetchone()["dose_given"])
        self.assertFalse(self.conn.execute(
            "SELECT dose_given FROM subjects WHERE id=?", (sids[1],)).fetchone()["dose_given"])
        # 暂停期间禁止递增投票
        self.svc.advance_clock(AFTER_WINDOW)
        sid = self.svc.create_snapshot("test", cid)["snapshot_id"]
        # 第 2、3 人未给药，门不过；构造一个仅检验暂停动作限制的小场景
        with self.assertRaises(Conflict):
            self.svc.cast_vote("test", sid, "CM-DAC", "escalate",
                               self.sign("CM-DAC", sid, "escalate",
                                         self.svc.get_snapshot(sid)["content_hash"]), 0)

    def test_trial_wide_hold_blocks_other_cohorts(self):
        c1 = self.cid()
        c2 = self.svc.create_cohort("test", self.tid, 2, 20.0, "mg", 3, 21)["cohort_id"]
        s1 = [self.svc.enroll_subject("test", c1)["subject_id"] for _ in range(3)]
        self.svc.freeze_cohort("test", c1)
        self.svc.emergency_hold("test", "trial", "全试验安全信号", trial_id=self.tid)
        with self.assertRaises(Conflict):
            self.svc.record_administration("test", c1, s1[0], given_at=DOSE)

    def test_continue_decision_releases_hold(self):
        cid = self.cid()
        self.enroll_freeze_dose(cid)
        self.svc.emergency_hold("test", "cohort", "供应问题暂停", cohort_id=cid)
        self.close_windows()
        sid = self.svc.create_snapshot("test", cid)["snapshot_id"]
        self.two_votes_and_decide(sid, "continue")
        self.assertEqual([], self.svc._active_holds(cid))

    # ---------------------------------------------------------- 9 引擎约束
    def test_committee_cannot_override_stop_engine_upward(self):
        cid = self.cid()
        sids = self.enroll_freeze_dose(cid)
        for sid in sids[:2]:
            self.svc.report_ae("test", cid, sid, "DLT", "grade3",
                               "2026-10-05T00:00:00+00:00")
        for ae in self.svc.get_cohort(cid)["adverse_events"]:
            self.svc.adjudicate_ae("test", ae["id"], True, True, "确认")
        self.close_windows()
        snap = self.svc.create_snapshot("test", cid)
        self.assertEqual(snap["outcome"]["recommendation"], "stop")
        sid = snap["snapshot_id"]
        self.vote(sid, "CM-DAC", "escalate", 0)
        self.vote(sid, "CM-ELN", "escalate", 1)
        with self.assertRaises(Conflict) as cm:
            self.svc.issue_decision("test", sid)
        self.assertEqual(cm.exception.code, "engine_disagreement")
        # 保守的 stop 永远允许（覆盖引擎的更保守判断也允许，如 expand 引擎下投 stop）
        self.conn.execute("DELETE FROM votes")
        self.vote(sid, "CM-DAC", "stop", 0)
        self.vote(sid, "CM-ELN", "stop", 1)
        d = self.svc.issue_decision("test", sid)
        self.assertEqual(d["action"], "stop")

    # ---------------------------------------------------------- 10 派生队列
    def test_escalation_creates_child_cohort_and_closes_parent(self):
        cid = self.cid()
        self.enroll_freeze_dose(cid)
        self.close_windows()
        sid = self.svc.create_snapshot("test", cid)["snapshot_id"]
        d = self.two_votes_and_decide(sid, "escalate")
        self.assertEqual(self.svc.get_cohort(cid)["status"], "closed")
        child = self.svc.get_cohort(d["child_cohort_id"])
        self.assertEqual(child["status"], "draft")
        self.assertEqual(child["parent_decision_id"], d["decision_id"])

    # ---------------------------------------------------------- 11 哈希链/证明
    def test_v2_ruleset_recomputes_dlt_on_new_snapshot(self):
        """同一 grade3 事件：v1 下计 DLT（expand），v2 收紧门槛后新快照 DLT=0（escalate）。"""
        cid = self.cid()
        sids = self.enroll_freeze_dose(cid)
        self.svc.report_ae("test", cid, sids[0], "DLT", "grade3",
                           "2026-10-04T00:00:00+00:00")
        self.svc.adjudicate_ae("test", self.svc.get_cohort(cid)["adverse_events"][0]["id"],
                               True, True, "v1 下确认 DLT")
        self.close_windows()
        s1 = self.svc.create_snapshot("test", cid)
        self.assertEqual(s1["outcome"]["dlt_count"], 1)
        self.svc.publish_ruleset("test", {
            "min_severity_dlt": "grade4",
            "bands": [{"max_dlt": 0, "action": "escalate"},
                      {"max_dlt": None, "action": "stop"}]}, "v2")
        # 旧快照冻结在 v1，结论不变
        self.assertEqual(self.svc.get_snapshot(s1["snapshot_id"])["outcome"]["dlt_count"], 1)
        # 新快照按 v2 重算
        s2 = self.svc.create_snapshot("test", cid)
        self.assertEqual(s2["ruleset_version"], 2)
        self.assertEqual(s2["outcome"]["dlt_count"], 0)
        self.assertEqual(s2["outcome"]["recommendation"], "escalate")

    def test_conservative_action_always_allowed(self):
        """引擎建议 escalate 时，委员会保守决定 stop 必须允许。"""
        cid = self.cid()
        self.enroll_freeze_dose(cid)
        self.close_windows()
        sid = self.svc.create_snapshot("test", cid)["snapshot_id"]
        self.assertEqual(self.svc.get_snapshot(sid)["outcome"]["recommendation"], "escalate")
        self.vote(sid, "CM-DAC", "stop", 0)
        self.vote(sid, "CM-ELN", "stop", 1)
        d = self.svc.issue_decision("test", sid)
        self.assertEqual(d["action"], "stop")
        self.assertEqual(self.svc.get_cohort(cid)["status"], "stopped")
        self.assertTrue(self.svc.verify_proof(d["decision_id"])["verified"])

    def test_blocked_administration_is_persistent_fact(self):
        """暂停阻断的给药尝试在暂停解除后仍可审计，且已给药事实不被改写。"""
        cid = self.cid()
        sids = [self.svc.enroll_subject("test", cid)["subject_id"] for _ in range(3)]
        self.svc.freeze_cohort("test", cid)
        self.svc.record_administration("test", cid, sids[0], given_at=DOSE)
        self.svc.emergency_hold("test", "cohort", "x", cohort_id=cid)
        with self.assertRaises(Conflict):
            self.svc.record_administration("test", cid, sids[1], given_at=DOSE)
        self.svc.release_hold("test",
                              self.svc.get_state()["holds"][0]["id"], "解除")
        # 阻断记录仍在
        c = self.svc.get_cohort(cid)
        blocked = [a for a in c["administrations"] if a["held_back"]]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["subject_id"], sids[1])
        # 解除后可正常给同一人药（不与阻断记录冲突）
        self.svc.record_administration("test", cid, sids[1], given_at=DOSE)
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) c FROM administrations WHERE held_back=1").fetchone()["c"], 1)

    # ---------------------------------------------------------- 12 哈希链/证明
    def test_hash_chain_tamper_detected(self):
        cid = self.cid()
        self.enroll_freeze_dose(cid)
        self.close_windows()
        sid = self.svc.create_snapshot("test", cid)["snapshot_id"]
        d = self.two_votes_and_decide(sid)
        v = self.svc.verify_proof(d["decision_id"])
        self.assertTrue(v["verified"], msg=json.dumps(v["checks"], ensure_ascii=False))
        # 直接篡改事件库载荷
        row = self.conn.execute("SELECT payload FROM journal WHERE event_type='ae_reported'")
        # 无 AE 时改一条给药事件
        self.conn.execute(
            "UPDATE journal SET payload=? WHERE event_type='administration_recorded' LIMIT 1",
            (json.dumps({"hacked": True}),))
        v2 = self.svc.verify_proof(d["decision_id"])
        self.assertFalse(v2["verified"])
        self.assertFalse(any(c["passed"] for c in v2["checks"]
                             if c["check"] == "journal_hashchain_intact"))

    def test_proof_tamper_detected(self):
        cid = self.cid()
        self.enroll_freeze_dose(cid)
        self.close_windows()
        sid = self.svc.create_snapshot("test", cid)["snapshot_id"]
        d = self.two_votes_and_decide(sid)
        stored = json.loads(self.conn.execute(
            "SELECT proof_bundle FROM decisions WHERE id=?", (d["decision_id"],)
        ).fetchone()["proof_bundle"])
        stored["action"] = "stop"
        v = self.svc.verify_proof(d["decision_id"], tampered_proof=stored)
        self.assertFalse(v["verified"])

    def test_forged_signature_rejected(self):
        cid = self.cid()
        self.enroll_freeze_dose(cid)
        self.close_windows()
        snap = self.svc.create_snapshot("test", cid)
        with self.assertRaises(Conflict) as cm:
            self.svc.cast_vote("test", snap["snapshot_id"], "CM-DAC", "escalate",
                               "deadbeef", 0)
        self.assertEqual(cm.exception.code, "bad_signature")

    # ---------------------------------------------------------- 12 杂项
    def test_duplicate_dose_rejected(self):
        cid = self.cid()
        sids = self.enroll_freeze_dose(cid, n=3)
        with self.assertRaises(Conflict):
            self.svc.record_administration("test", cid, sids[0], given_at=DOSE)

    def test_below_threshold_dlt_rejected(self):
        cid = self.cid()
        sids = self.enroll_freeze_dose(cid)
        self.svc.report_ae("test", cid, sids[0], "轻度乏力", "grade1",
                           "2026-10-02T00:00:00+00:00")
        ae = self.svc.get_cohort(cid)["adverse_events"][0]
        with self.assertRaises(Conflict):
            self.svc.adjudicate_ae("test", ae["id"], True, True, "试图越级计 DLT")

    def test_expand_engine_path(self):
        cid = self.cid()
        sids = self.enroll_freeze_dose(cid)
        self.svc.report_ae("test", cid, sids[0], "ALT3", "grade3",
                           "2026-10-03T00:00:00+00:00")
        self.svc.adjudicate_ae("test", self.svc.get_cohort(cid)["adverse_events"][0]["id"],
                               True, True, "DLT")
        self.close_windows()
        snap = self.svc.create_snapshot("test", cid)
        self.assertEqual(snap["outcome"]["recommendation"], "expand")
        sid = snap["snapshot_id"]
        d = self.two_votes_and_decide(sid, "expand")
        self.assertEqual(d["action"], "expand")
        self.assertTrue(self.svc.get_cohort(d["child_cohort_id"]))


class OfflineDraftTest(PlatformBase):
    """断网投票草稿：本地草稿 → 恢复后先核对快照 → 幂等一次性提交。"""

    def ready_snapshot(self):
        cid = self.cid()
        self.enroll_freeze_dose(cid)
        self.close_windows()
        snap = self.svc.create_snapshot("test", cid)
        assert snap["gates"]["ready"]
        return cid, snap["snapshot_id"]

    def draft(self, sid, member, action="escalate", version=0,
              draft_id="DR-1", ch=None):
        ch = ch or self.svc.get_snapshot(sid)["content_hash"]
        return {"draft_id": draft_id, "snapshot_id": sid, "member_id": member,
                "action": action, "content_hash": ch,
                "signature": self.sign(member, sid, action, ch),
                "expected_version": version}

    def submit(self, d):
        return self.svc.submit_vote_draft("test", **d)

    def vote_count(self, sid):
        return self.conn.execute(
            "SELECT COUNT(*) c FROM votes WHERE snapshot_id=?", (sid,)
        ).fetchone()["c"]

    # 提交成功 + 幂等回放：重复提交只得到首次结果，不产生第二张票
    def test_draft_submit_and_idempotent_replay(self):
        cid, sid = self.ready_snapshot()
        d = self.draft(sid, "CM-DAC")
        r1 = self.submit(d)
        self.assertEqual(r1["status"], "submitted")
        self.assertEqual(self.vote_count(sid), 1)
        r2 = self.submit(d)
        self.assertTrue(r2["replayed"])
        self.assertEqual(r2["vote_id"], r1["vote_id"])
        self.assertEqual(self.vote_count(sid), 1)
        q = self.svc.list_vote_drafts(cid)
        self.assertEqual(len(q), 1)
        self.assertEqual(q[0]["status"], "submitted")

    # 同一幂等键携带不同载荷 → 拒绝
    def test_draft_payload_mismatch_rejected(self):
        cid, sid = self.ready_snapshot()
        self.submit(self.draft(sid, "CM-DAC"))
        d2 = self.draft(sid, "CM-DAC", action="stop")  # 同一 draft_id=DR-1
        with self.assertRaises(Conflict) as cm:
            self.submit(d2)
        self.assertEqual(cm.exception.code, "draft_payload_mismatch")
        self.assertEqual(self.vote_count(sid), 1)

    # 迟到事件推进快照 → 草稿过期并阻止写入；队列 API 返回冲突原因
    def test_draft_expired_by_late_ae(self):
        cid, sid = self.ready_snapshot()
        d = self.draft(sid, "CM-DAC")
        sids = [s["id"] for s in self.svc.get_cohort(cid)["subjects"]]
        self.svc.report_ae("test", cid, sids[0], "迟报 DLT", "grade3",
                           "2026-10-20T00:00:00+00:00")
        r = self.submit(d)
        self.assertEqual(r["status"], "expired")
        self.assertEqual(r["conflict"]["code"], "snapshot_superseded")
        self.assertEqual(self.vote_count(sid), 0)  # 阻止写入
        q = self.svc.list_vote_drafts(cid)
        self.assertEqual(q[0]["status"], "expired")
        self.assertEqual(q[0]["conflict"]["code"], "snapshot_superseded")
        # 重复提交仍是首次结果，仍无票
        r2 = self.submit(d)
        self.assertEqual(r2["status"], "expired")
        self.assertEqual(self.vote_count(sid), 0)

    # 替补推进快照 → 草稿过期
    def test_draft_expired_by_replacement(self):
        cid, sid = self.ready_snapshot()
        d = self.draft(sid, "CM-DAC")
        sid0 = self.svc.get_cohort(cid)["subjects"][0]["id"]
        self.svc.replace_subject("test", cid, sid0, "撤回知情同意")
        r = self.submit(d)
        self.assertEqual(r["status"], "expired")
        self.assertEqual(r["conflict"]["code"], "snapshot_superseded")
        self.assertEqual(self.vote_count(sid), 0)

    # 规则换版 → 草稿过期；但实时投票在旧快照上仍可用（既有语义不变）
    def test_draft_expired_by_ruleset_change_realtime_still_works(self):
        cid, sid = self.ready_snapshot()
        d = self.draft(sid, "CM-DAC")
        self.svc.publish_ruleset("test", {
            "min_severity_dlt": "grade4",
            "bands": [{"max_dlt": 0, "action": "escalate"},
                      {"max_dlt": None, "action": "stop"}]}, "v2")
        r = self.submit(d)
        self.assertEqual(r["status"], "expired")
        self.assertEqual(r["conflict"]["code"], "ruleset_advanced")
        self.assertEqual(self.vote_count(sid), 0)
        # 原有实时投票继续可用（在线委员看得见规则换版，自行判断）
        self.vote(sid, "CM-ELN", "escalate", 0)
        self.assertEqual(self.vote_count(sid), 1)

    # 委员已实时投票 → 草稿过期 vote_exists，不产生第二张票
    def test_draft_expired_when_member_already_voted(self):
        cid, sid = self.ready_snapshot()
        self.vote(sid, "CM-DAC", "escalate", 0)
        r = self.submit(self.draft(sid, "CM-DAC", version=1))
        self.assertEqual(r["status"], "expired")
        self.assertEqual(r["conflict"]["code"], "vote_exists")
        self.assertEqual(self.vote_count(sid), 1)

    # 伪造签名 → 拒绝且不入队
    def test_draft_bad_signature_not_queued(self):
        cid, sid = self.ready_snapshot()
        d = self.draft(sid, "CM-DAC")
        d["signature"] = "deadbeef"
        with self.assertRaises(Conflict) as cm:
            self.submit(d)
        self.assertEqual(cm.exception.code, "bad_signature")
        self.assertEqual(self.svc.list_vote_drafts(cid), [])

    # 瞬态版本冲突：不落库，刷新版本后同一草稿提交成功
    def test_draft_version_conflict_is_transient(self):
        cid, sid = self.ready_snapshot()
        d = self.draft(sid, "CM-DAC", version=0)
        self.vote(sid, "CM-ELN", "escalate", 0)  # 版本推到 1
        with self.assertRaises(Conflict) as cm:
            self.submit(d)
        self.assertEqual(cm.exception.code, "snapshot_version_conflict")
        self.assertEqual(self.svc.list_vote_drafts(cid), [])  # 未落库
        d["expected_version"] = 1
        r = self.submit(d)
        self.assertEqual(r["status"], "submitted")
        self.assertEqual(self.vote_count(sid), 2)

    # 两张草稿提交 → 签发决定 → 证明校验通过（实时链路不受影响）
    def test_drafts_then_decision_and_proof(self):
        cid, sid = self.ready_snapshot()
        r1 = self.submit(self.draft(sid, "CM-DAC", draft_id="DR-A", version=0))
        r2 = self.submit(self.draft(sid, "CM-ELN", draft_id="DR-B", version=1))
        self.assertEqual(r1["status"], "submitted")
        self.assertEqual(r2["status"], "submitted")
        d = self.svc.issue_decision("test", sid)
        self.assertEqual(d["action"], "escalate")
        v = self.svc.verify_proof(d["decision_id"])
        self.assertTrue(v["verified"], msg=json.dumps(v["checks"], ensure_ascii=False))


class ArchiveTest(PlatformBase):
    """监管稽核归档：授权发起、固定区间、断点续跑、幂等去重、脱敏与独立验真。"""

    AUD = ("AUD-01", "demo-audit-token")

    def decided(self):
        cid = self.cid()
        self.enroll_freeze_dose(cid)
        self.close_windows()
        sid = self.svc.create_snapshot("test", cid)["snapshot_id"]
        d = self.two_votes_and_decide(sid, "escalate")
        return cid, d["decision_id"]

    def request(self, did, policy="full", **kw):
        return self.svc.request_archive(self.AUD[0], self.AUD[1], did, policy, **kw)

    def bundle(self, archive_id):
        return self.svc.get_archive_bundle(self.AUD[0], self.AUD[1], archive_id)

    def verify(self, bundle):
        return self.svc.verify_archive_bundle(self.AUD[0], self.AUD[1], bundle)

    # 完整链路：queued→ready，包内含证明/日志区间/委员角色，独立验真全过
    def test_archive_full_flow_and_independent_verify(self):
        cid, did = self.decided()
        v = self.request(did)
        self.assertEqual(v["status"], "queued")
        self.assertEqual(v["journal_from"],
                         self.conn.execute(
                             "SELECT seq FROM journal WHERE event_type='cohort_created'"
                             " AND cohort_id=?", (cid,)).fetchone()["seq"])
        v = self.svc.drive_archive(v["archive_id"])
        self.assertEqual(v["status"], "ready")
        b = self.bundle(v["archive_id"])
        # 固定了当时的决定证明、日志区间与委员角色
        self.assertEqual(b["decision_proof"]["decision_id"], did)
        self.assertEqual(len(b["journal_events"]), v["total_events"])
        self.assertEqual(b["journal_events"][-1]["seq"], v["journal_to"])
        roles = {m["member_id"]: m["role"] for m in b["committee"]}
        self.assertEqual(roles, {"CM-DAC": "independent", "CM-ELN": "independent"})
        self.assertIn("name", b["committee"][0])  # full 策略保留姓名
        self.assertIn("payload", b["journal_events"][0])  # full 策略保留载荷
        r = self.verify(b)
        self.assertTrue(r["verified"], msg=json.dumps(r["checks"], ensure_ascii=False))

    # 精简策略：隐去日志操作人/载荷与委员姓名；绝不包含个人密钥
    def test_archive_redacted_hides_identity_and_keys(self):
        cid, did = self.decided()
        v = self.svc.drive_archive(self.request(did, "redacted")["archive_id"])
        b = self.bundle(v["archive_id"])
        for e in b["journal_events"]:
            self.assertNotIn("actor", e)
            self.assertNotIn("payload", e)
        for m in b["committee"]:
            self.assertNotIn("name", m)
        raw = json.dumps(b, ensure_ascii=False)
        for row in self.conn.execute("SELECT hmac_key FROM committee_members"):
            self.assertNotIn(row["hmac_key"], raw)
        self.assertNotIn("demo-audit-token", raw)
        r = self.verify(b)
        self.assertTrue(r["verified"], msg=json.dumps(r["checks"], ensure_ascii=False))
        names = {c["check"] for c in r["checks"]}
        self.assertIn("redaction_policy_respected", names)
        self.assertIn("no_personal_key_material", names)

    # 相同决定+相同策略的并发请求只生成一份结果
    def test_archive_concurrent_requests_single_result(self):
        cid, did = self.decided()
        results = {}

        def req(tag):
            results[tag] = self.request(did, "full")

        ts = [threading.Thread(target=req, args=(i,)) for i in range(2)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        views = list(results.values())
        self.assertEqual(len({v["archive_id"] for v in views}), 1)
        self.assertEqual(sorted(v["replayed"] for v in views), [False, True])
        n = self.conn.execute(
            "SELECT COUNT(*) c FROM archives WHERE decision_id=?", (did,)).fetchone()["c"]
        self.assertEqual(n, 1)
        # 无新事件时重复请求也是幂等回放
        again = self.request(did, "full")
        self.assertTrue(again["replayed"])
        self.assertEqual(again["archive_id"], views[0]["archive_id"])

    # 生成中断后可以继续，且恢复后绝不混入归档发起之后到达的日志
    def test_archive_resume_excludes_later_events(self):
        cid, did = self.decided()
        self.svc._archive_chunk_size = 3
        v = self.request(did)
        pinned_to = v["journal_to"]
        v = self.svc.process_archive(v["archive_id"], max_chunks=1)
        self.assertEqual(v["status"], "generating")
        self.assertLess(v["progress_seq"], pinned_to)
        # 中断期间出现新的安全事实（迟报 AE 等）
        sids = [s["id"] for s in self.svc.get_cohort(cid)["subjects"]]
        self.svc.report_ae("test", cid, sids[0], "迟报 DLT", "grade3",
                           "2026-10-20T00:00:00+00:00")
        v = self.svc.drive_archive(v["archive_id"])
        self.assertEqual(v["status"], "ready")
        b = self.bundle(v["archive_id"])
        seqs = [e["seq"] for e in b["journal_events"]]
        self.assertEqual(max(seqs), pinned_to)  # 未混入后续日志
        self.assertEqual(seqs, list(range(v["journal_from"], pinned_to + 1)))
        self.assertTrue(self.verify(b)["verified"])
        # 工作台提示：归档后出现新事件，建议创建覆盖新区间的归档
        view = self.svc.get_archive(v["archive_id"])
        self.assertTrue(view["stale"])
        self.assertGreater(view["newer_events_count"], 0)

    # 无权限明确拒绝（403）
    def test_archive_unauthorized_rejected(self):
        cid, did = self.decided()
        for aid, tok in ((self.AUD[0], "wrong-token"), ("AUD-99", "x"), (None, None)):
            with self.assertRaises(DomainError) as cm:
                self.svc.request_archive(aid, tok, did, "full")
            self.assertEqual(cm.exception.status, 403)
        with self.assertRaises(DomainError) as cm:
            self.svc.get_archive_bundle(self.AUD[0], "bad", "AR-x")
        self.assertEqual(cm.exception.status, 403)

    # 证明已损坏明确拒绝（409 proof_corrupted）
    def test_archive_corrupted_proof_rejected(self):
        cid, did = self.decided()
        stored = json.loads(self.conn.execute(
            "SELECT proof_bundle FROM decisions WHERE id=?", (did,)).fetchone()[0])
        stored["action"] = "stop"
        self.conn.execute("UPDATE decisions SET proof_bundle=? WHERE id=?",
                          (json.dumps(stored), did))
        self.conn.commit()
        with self.assertRaises(Conflict) as cm:
            self.request(did)
        self.assertEqual(cm.exception.code, "proof_corrupted")

    # 请求参数冲突明确拒绝（409 archive_param_conflict）
    def test_archive_param_conflict_rejected(self):
        cid, did = self.decided()
        head = self.svc._business_journal_head()
        with self.assertRaises(Conflict) as cm:
            self.request(did, cover_through_seq=head + 5)
        self.assertEqual(cm.exception.code, "archive_param_conflict")
        v = self.request(did, cover_through_seq=head)  # 与当前日志头一致则接受
        self.assertEqual(v["status"], "queued")
        with self.assertRaises(ValidationFailed):
            self.request(did, "weird-policy")

    # 新安全事实不改写旧包；覆盖新区间的新归档取代旧归档，旧包仍可验真
    def test_archive_superseded_by_new_range_old_bundle_intact(self):
        cid, did = self.decided()
        v1 = self.svc.drive_archive(self.request(did)["archive_id"])
        b1 = self.bundle(v1["archive_id"])
        hash1 = b1["bundle_hash"]
        # 归档后出现新的安全事实
        sids = [s["id"] for s in self.svc.get_cohort(cid)["subjects"]]
        self.svc.report_ae("test", cid, sids[1], "迟报：肝酶升高", "grade3",
                           "2026-10-21T00:00:00+00:00")
        self.assertTrue(self.svc.get_archive(v1["archive_id"])["stale"])
        v2 = self.request(did)
        self.assertFalse(v2["replayed"])  # 新区间 → 新归档
        self.assertGreater(v2["journal_to"], v1["journal_to"])
        v2 = self.svc.drive_archive(v2["archive_id"])
        self.assertEqual(v2["status"], "ready")
        self.assertEqual(self.svc.get_archive(v1["archive_id"])["status"], "superseded")
        # 旧包内容未被改写，仍可下载并独立验真
        b1_after = self.bundle(v1["archive_id"])
        self.assertEqual(b1_after["bundle_hash"], hash1)
        self.assertTrue(self.verify(b1_after)["verified"])
        self.assertTrue(self.verify(self.bundle(v2["archive_id"]))["verified"])

    # 生成失败进入 failed，可重试且仍只有一份归档
    def test_archive_failure_and_retry(self):
        cid, did = self.decided()
        self.svc._archive_chunk_size = 2
        v = self.request(did)
        calls = []

        def boom(n):
            calls.append(n)
            raise RuntimeError("模拟生成中断（磁盘故障）")

        self.svc._archive_fault_hook = boom
        v = self.svc.process_archive(v["archive_id"])
        self.assertEqual(v["status"], "failed")
        self.assertIn("模拟生成中断", v["error"])
        self.svc._archive_fault_hook = None
        # 重试：同一去重键复位重跑，不产生第二份归档
        v = self.request(did)
        self.assertFalse(v["replayed"])
        self.assertEqual(v["attempt"], 2)
        v = self.svc.drive_archive(v["archive_id"])
        self.assertEqual(v["status"], "ready")
        n = self.conn.execute(
            "SELECT COUNT(*) c FROM archives WHERE decision_id=?", (did,)).fetchone()["c"]
        self.assertEqual(n, 1)
        self.assertTrue(self.verify(self.bundle(v["archive_id"]))["verified"])

    # 未就绪不可下载
    def test_archive_download_requires_ready(self):
        cid, did = self.decided()
        v = self.request(did)  # queued，未驱动
        with self.assertRaises(Conflict) as cm:
            self.bundle(v["archive_id"])
        self.assertEqual(cm.exception.code, "archive_not_ready")

    # 篡改下载内容可被发现
    def test_tampered_bundle_fails_verification(self):
        cid, did = self.decided()
        v = self.svc.drive_archive(self.request(did)["archive_id"])
        b = self.bundle(v["archive_id"])
        b["decision_proof"]["action"] = "stop"
        r = self.verify(b)
        self.assertFalse(r["verified"])
        failed = {c["check"] for c in r["checks"] if not c["passed"]}
        self.assertIn("bundle_hash_unchanged", failed)
        self.assertIn("proof_hash_unchanged", failed)

    # 归档不影响给药、断网草稿与既有证明校验
    def test_archive_does_not_affect_existing_flows(self):
        cid, did = self.decided()
        v = self.svc.drive_archive(self.request(did)["archive_id"])
        self.assertEqual(v["status"], "ready")
        # 既有证明校验不受归档影响
        self.assertTrue(self.svc.verify_proof(did)["verified"])
        # 派生子队列：给药 → 快照 → 断网草稿投票 → 决定 → 证明校验 全链路如常
        child = self.svc.get_decision(did)["child_cohort_id"]
        sids = [self.svc.enroll_subject("test", child)["subject_id"] for _ in range(3)]
        self.svc.freeze_cohort("test", child)
        for s in sids:
            self.svc.record_administration("test", child, s,
                                           given_at="2026-10-23T10:00:00+00:00")
        self.svc.advance_clock("2026-11-14T10:01:00+00:00")
        snap = self.svc.create_snapshot("test", child)
        sid = snap["snapshot_id"]
        d1 = {"draft_id": "DR-AR-1", "snapshot_id": sid, "member_id": "CM-DAC",
              "action": "escalate", "content_hash": snap["content_hash"],
              "signature": self.sign("CM-DAC", sid, "escalate", snap["content_hash"]),
              "expected_version": 0}
        r = self.svc.submit_vote_draft("test", **d1)
        self.assertEqual(r["status"], "submitted")
        self.vote(sid, "CM-ELN", "escalate", 1)
        d2 = self.svc.issue_decision("test", sid)
        self.assertTrue(self.svc.verify_proof(d2["decision_id"])["verified"])
        # 归档包在后续业务事件之后仍可验真（内容固定）
        self.assertTrue(self.verify(self.bundle(v["archive_id"]))["verified"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
