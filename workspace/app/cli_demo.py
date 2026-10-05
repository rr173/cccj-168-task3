"""命令行一键演示：完整体现平台所有关键安全语义。

运行：python3 -m app.cli_demo
"""
from __future__ import annotations

import threading

from .crypto import canonical_json, hmac_hex
from .services import Services
from .store import connect

T0 = "2026-10-01T09:00:00+00:00"
DOSE = "2026-10-01T10:00:00+00:00"


def line(t=""):
    print(f"\n{'─'*72}\n{t}\n{'─'*72}")


def sign(conn, member, sid, ch, action):
    key = conn.execute("SELECT hmac_key FROM committee_members WHERE member_id=?",
                       (member,)).fetchone()["hmac_key"]
    return hmac_hex(key, canonical_json({
        "snapshot_id": sid, "content_hash": ch,
        "action": action, "member_id": member}))


def expect_conflict(label, fn):
    try:
        fn()
        print(f"  ✗ {label}：本应被拒绝却成功了！")
    except Exception as e:  # noqa: BLE001
        print(f"  ✓ {label}：拒绝（{getattr(e,'code',e.__class__.__name__)}）{e}")


def main():
    svc = Services(connect(":memory:"))
    svc.bootstrap()
    svc.advance_clock(T0)

    line("1. 建试验/队列 → 入组 → 冻结方案（10mg × 3人 × 21天观察窗）")
    tid = svc.create_trial("sponsor", "FIH-101 首次人体试验")["trial_id"]
    cid = svc.create_cohort("sponsor", tid, 1, 10.0, "mg", 3, 21)["cohort_id"]
    sids = [svc.enroll_subject("crc", cid)["subject_id"] for _ in range(3)]
    svc.freeze_cohort("pi", cid)
    print("  队列已冻结：剂量/观察窗/受试者集合不可变")
    expect_conflict("冻结后再入组", lambda: svc.enroll_subject("crc", cid))
    expect_conflict("按非冻结剂量(20mg)给药",
                    lambda: svc.record_administration("nurse", cid, sids[0],
                                                      dose=20.0, given_at=DOSE))
    print("  （给药将按安全节奏在后续步骤逐人登记）")

    line("2. 安全事件按严重度进入引擎；紧急暂停立即阻断后续给药并留痕")
    # 先给第 1 名受试者给药
    svc.record_administration("nurse", cid, sids[0], given_at=DOSE)
    svc.emergency_hold("dsmb", "cohort", "外部安全数据库出现同类信号", cohort_id=cid)
    expect_conflict("暂停期间给第 2 名受试者给药",
                    lambda: svc.record_administration(
                        "nurse", cid, sids[1], given_at="2026-10-01T11:00:00+00:00"))
    adm = svc.get_cohort(cid)["administrations"]
    print(f"  给药事实留痕 {len(adm)} 条：已给药 {sum(1 for a in adm if not a['held_back'])}，"
          f"被阻断 {sum(1 for a in adm if a['held_back'])}（已给药事实不受影响）")
    hold_id = next(h["id"] for h in svc.get_state()["holds"]
                   if h["status"] == "active" and h["cohort_id"] == cid)
    svc.release_hold("dsmb", hold_id, "信号经核实与本药无关，按 SOP 解除并记录")
    ae = svc.report_ae("crc", cid, sids[0], "恶心", "grade2",
                       "2026-10-03T08:00:00+00:00")["ae_id"]
    svc.adjudicate_ae("cm", ae, True, False, "2 级，低于 ≥grade3 门槛")
    expect_conflict("grade1 试图越级计 DLT", lambda: (
        svc.report_ae("crc", cid, sids[1], "乏力", "grade1", "2026-10-03T09:00:00+00:00"),
        svc.adjudicate_ae("cm", svc.get_cohort(cid)["adverse_events"][-1]["id"],
                          True, True, "")))

    line("3. 缺失数据未处理 + 观察窗未满 → 五道安全门拦截")
    pid = svc.add_pending("crc", cid, "lab", "第14天血常规未回收", sids[1])["pending_id"]
    sp = svc.create_snapshot("system", cid)
    for k, v in sp["gates"].items():
        if k != "ready":
            print(f"  {'✓' if v['passed'] else '✗'} {k}"
                  + ("" if v["passed"] else f"：{[b.get('reason', b) for b in v['blockers']]}"))
    expect_conflict("门未过时投票",
                    lambda: svc.cast_vote(
                        "cm", sp["snapshot_id"], "CM-DAC", "escalate",
                        "x", 0))

    line("4. 缺失处理完毕、观察窗结束 → 新快照五门全过，引擎建议 ESCALATE（0 DLT）")
    # 解除暂停后补齐其余两名受试者给药（同一冻结剂量）
    svc.record_administration("nurse", cid, sids[1], given_at="2026-10-01T11:00:00+00:00")
    svc.record_administration("nurse", cid, sids[2], given_at="2026-10-01T11:00:00+00:00")
    svc.resolve_pending("crc", pid, "复查已回收，全部正常")
    svc.advance_clock("2026-10-22T11:01:00+00:00")
    sp = svc.create_snapshot("system", cid)
    print(f"  gates.ready={sp['gates']['ready']}  引擎={sp['outcome']['recommendation']}"
          f"  DLT={sp['outcome']['dlt_count']}/{sp['outcome']['evaluable_n']}")

    line("5. 两名委员并发投票：乐观并发保证绝不拼接陈旧视图")
    results = {}

    def vote(member):
        try:
            snap = svc.get_snapshot(sp["snapshot_id"])
            svc.cast_vote(member, sp["snapshot_id"], member, "escalate",
                          sign(svc.conn, member, sp["snapshot_id"],
                               snap["content_hash"], "escalate"), 0)
            results[member] = "201 接受"
        except Exception as e:  # noqa: BLE001
            results[member] = f"409 {getattr(e,'code','')}"

    ts = [threading.Thread(target=vote, args=(m,)) for m in ("CM-DAC", "CM-ELN")]
    [t.start() for t in ts]; [t.join() for t in ts]
    for m, r in results.items():
        print(f"  {m}: {r}")
    loser = next(m for m, r in results.items() if "409" in r)
    print(f"  → 失败者 {loser} 刷新得到 vote_version=1 后重试：")
    svc.cast_vote(loser, sp["snapshot_id"], loser, "escalate",
                  sign(svc.conn, loser, sp["snapshot_id"],
                       sp["content_hash"], "escalate"), 1)
    print("  ✓ 重试成功")

    line("6. 签发决定前出现迟到 grade3 AE → 旧快照立即失效，禁止据此决策")
    svc.report_ae("crc", cid, sids[1], "血小板下降（迟报）", "grade3",
                  "2026-10-20T00:00:00+00:00")
    expect_conflict("基于含旧结论的快照签发",
                    lambda: svc.issue_decision("cm", sp["snapshot_id"]))
    late = svc.get_cohort(cid)["adverse_events"][-1]
    print(f"  迟到事件已标记 late={late['late']}；旧快照 superseded="
          f"{svc.get_snapshot(sp['snapshot_id'])['superseded']}")
    svc.adjudicate_ae("cm", late["id"], True, True, "迟到事件裁定为 DLT")

    line("7. 决策前再次紧急暂停（本队列给药已完成，阻断效果体现在决策通道）")
    svc.emergency_hold("dsmb", "cohort", "迟到 DLT 触发即时暂停，等待委员会复核",
                       cohort_id=cid)
    print("  暂停已生效：后续任何给药立即阻断（同第 2 步机制），且投票通道仅余 stop/continue")

    line("8. 重建快照（1 DLT → 引擎建议 EXPAND）；暂停期只许 stop/continue")
    sp = svc.create_snapshot("system", cid)
    print(f"  引擎={sp['outcome']['recommendation']} DLT={sp['outcome']['dlt_count']}")
    expect_conflict("暂停中投 escalate", lambda: svc.cast_vote(
        "cm", sp["snapshot_id"], "CM-DAC", "escalate",
        sign(svc.conn, "CM-DAC", sp["snapshot_id"], sp["content_hash"], "escalate"), 0))

    line("9. 双独立委员投票 continue 解除暂停（同一 content_hash，2/2 独立）")
    for i, m in enumerate(("CM-DAC", "CM-ELN")):
        svc.cast_vote(m, sp["snapshot_id"], m, "continue",
                      sign(svc.conn, m, sp["snapshot_id"],
                           sp["content_hash"], "continue"), i)
    svc.issue_decision("dsmb", sp["snapshot_id"])
    print("  暂停已解除；活动暂停数 =", len(svc._active_holds(cid)))

    line("10. 规则修订发布 v2：历史快照永远绑定 v1，结论不被重算")
    old_rec = svc.get_snapshot(sp["snapshot_id"])["outcome"]["recommendation"]
    svc.publish_ruleset("dmc", {
        "min_severity_dlt": "grade4",
        "bands": [{"max_dlt": 0, "action": "escalate"},
                  {"max_dlt": None, "action": "stop"}]},
        "修订：DLT 门槛上调至 grade4")
    assert svc.get_snapshot(sp["snapshot_id"])["outcome"]["recommendation"] == old_rec
    print(f"  旧快照仍按 v1 计算 = {old_rec}（不变）；新快照将绑定 v2")

    line("11. 新快照按 v2 重算（grade3 不再计 DLT）→ 引擎 ESCALATE，双委员同票签发")
    sp = svc.create_snapshot("system", cid)
    print(f"  v2 引擎={sp['outcome']['recommendation']} DLT={sp['outcome']['dlt_count']}"
          f"（同一 AE 在 v1 下曾计 DLT，体现规则版本化）")
    for i, m in enumerate(("CM-DAC", "CM-ELN")):
        svc.cast_vote(m, sp["snapshot_id"], m, "escalate",
                      sign(svc.conn, m, sp["snapshot_id"],
                           sp["content_hash"], "escalate"), i)
    d = svc.issue_decision("dsmb", sp["snapshot_id"])
    print(f"  决定 {d['decision_id']}: {d['action']} → 派生队列 {d['child_cohort_id']}")

    line("12. 独立校验决策证明（哈希/签名/门槛/引擎/哈希链，共 11 项）")
    v = svc.verify_proof(d["decision_id"])
    for c in v["checks"]:
        print(f"  {'✓' if c['passed'] else '✗'} {c['check']} {c.get('detail','')}")
    print(f"\n  总结论：verified = {v['verified']}")

    line("13. 断网投票草稿：离线签名 → 恢复后先核对快照 → 幂等提交 / 过期阻断")
    # 派生的子队列草案走一遍到「五门全过」的快照
    cid2 = d["child_cohort_id"]
    sids2 = [svc.enroll_subject("crc", cid2)["subject_id"] for _ in range(3)]
    svc.freeze_cohort("pi", cid2)
    for s in sids2:
        svc.record_administration("nurse", cid2, s,
                                  given_at="2026-10-23T10:00:00+00:00")
    svc.advance_clock("2026-11-14T10:01:00+00:00")
    sp2 = svc.create_snapshot("system", cid2)
    print(f"  新队列 {cid2} 快照 {sp2['snapshot_id']} 五门全过，"
          f"引擎={sp2['outcome']['recommendation']}")

    # 委员 CM-DAC「断网」：本地把动作+快照指纹签成草稿（等价于工作台离线保存）
    draft = {"draft_id": "DR-OFFLINE-1", "snapshot_id": sp2["snapshot_id"],
             "member_id": "CM-DAC", "action": "escalate",
             "content_hash": sp2["content_hash"],
             "signature": sign(svc.conn, "CM-DAC", sp2["snapshot_id"],
                               sp2["content_hash"], "escalate"),
             "expected_version": 0}
    print(f"  断网期间本地保存草稿 {draft['draft_id']}（escalate @ {sp2['snapshot_id']}）")

    # 网络恢复前，迟到 AE 推进了快照 → 草稿过期，提交被阻止写入
    svc.report_ae("crc", cid2, sids2[1], "迟报：输注反应", "grade3",
                  "2026-11-10T00:00:00+00:00")
    r = svc.submit_vote_draft("cm", **draft)
    print(f"  恢复后提交：status={r['status']} 冲突=[{r['conflict']['code']}] "
          f"{r['conflict']['message']}")
    print(f"  ✓ 过期草稿未写入任何票（votes={svc.get_snapshot(sp2['snapshot_id'])['vote_version']}）")

    # 裁定迟到事件（v2 规则下 grade3 不达 DLT 门槛）→ 重建快照 → 新草稿提交成功
    late2 = svc.get_cohort(cid2)["adverse_events"][-1]
    svc.adjudicate_ae("cm", late2["id"], True, False, "按 v2 规则 grade3 不计 DLT")
    sp3 = svc.create_snapshot("system", cid2)
    print(f"  重建快照 {sp3['snapshot_id']}：引擎={sp3['outcome']['recommendation']} "
          f"DLT={sp3['outcome']['dlt_count']}（v2 规则）")
    draft2 = {"draft_id": "DR-OFFLINE-2", "snapshot_id": sp3["snapshot_id"],
              "member_id": "CM-DAC", "action": "escalate",
              "content_hash": sp3["content_hash"],
              "signature": sign(svc.conn, "CM-DAC", sp3["snapshot_id"],
                                sp3["content_hash"], "escalate"),
              "expected_version": 0}
    r1 = svc.submit_vote_draft("cm", **draft2)
    r2 = svc.submit_vote_draft("cm", **draft2)
    print(f"  首次提交 status={r1['status']} vote={r1['vote_id']}；"
          f"重复提交 replayed={r2.get('replayed')} 同一票={r2['vote_id'] == r1['vote_id']}")

    # 第二名委员实时投票 → 签发 → 证明校验（实时链路不受草稿影响）
    svc.cast_vote("cm", sp3["snapshot_id"], "CM-ELN", "escalate",
                  sign(svc.conn, "CM-ELN", sp3["snapshot_id"],
                       sp3["content_hash"], "escalate"), 1)
    d2 = svc.issue_decision("dsmb", sp3["snapshot_id"])
    v2 = svc.verify_proof(d2["decision_id"])
    print(f"  决定 {d2['decision_id']}: {d2['action']}；证明校验 verified={v2['verified']}")
    q = svc.list_vote_drafts(cid2)
    print("  草稿队列：", ", ".join(f"{x['draft_id']}={x['status']}" for x in q))


if __name__ == "__main__":
    main()
