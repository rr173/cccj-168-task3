"""一键演示数据：试验 T-DEMO 的 1 号队列已入组/冻结/给药，
观察窗差 1 天结束，且挂着一项未处理的实验室缺失数据——
打开工作台即可体验「门未过 → 处理 → 关窗 → 快照 → 双独立委员投票 → 证明」全链路。
"""
from __future__ import annotations

from .errors import DomainError

BASE = "2026-10-01T09:00:00+00:00"
DOSE_DAY = "2026-10-01T10:00:00+00:00"


def seed_demo(svc) -> dict:
    conn = svc.conn
    if conn.execute("SELECT 1 FROM trials WHERE title LIKE '%DEMO%' LIMIT 1").fetchone():
        return {"status": "already_seeded"}
    svc.advance_clock(BASE)
    t = svc.create_trial("demo", "T-DEMO 首次人体剂量递增试验")
    tid = t["trial_id"]
    c = svc.create_cohort("demo", tid, level=1, dose=10.0, dose_unit="mg",
                          planned_n=3, window_days=21,
                          rationale="起始剂量 10mg，3+3 设计")
    cid = c["cohort_id"]
    sids = [svc.enroll_subject("demo", cid)["subject_id"] for _ in range(3)]
    svc.freeze_cohort("demo", cid)
    for sid in sids:
        svc.record_administration("demo", cid, sid, given_at=DOSE_DAY)
    svc.report_ae("demo", cid, sids[0], "恶心（CTCAE）", "grade2",
                  "2026-10-03T08:00:00+00:00")
    svc.add_pending("demo", cid, "lab", "第 14 天血常规报告未回收", sids[1])
    # 观察窗 21 天；推到第 20 天，门 1（窗口）差 1 天
    svc.advance_clock("2026-10-21T10:00:00+00:00")
    return {
        "status": "seeded", "trial_id": tid, "cohort_id": cid,
        "subjects": sids,
        "hint": "处理缺失数据 → 把时钟推进到 2026-10-22 10:00 之后 → 构建快照 → 投票决策",
    }
