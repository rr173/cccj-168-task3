"""规则引擎。

规则集是版本化、不可变的 JSON 规格，发布后不可修改，只能发布新版本。
每个快照在构建时固定 ruleset_version，重算/审计永远使用该版本，
因此规则修订不会改变任何历史快照的引擎结论。

判定链路：
  安全事件（AE）按严重度进入引擎（>= min_severity）
  + 事件可评估（assessed & evaluable）+ 受试者可评估
  → counts_as_dlt
  → DLT 例数落入剂量递增区间（bands）→ 建议动作
"""
from __future__ import annotations

from .errors import ValidationFailed

# CTCAE 风格严重度序
SEVERITY_ORDER = {
    "grade1": 1,
    "grade2": 2,
    "grade3": 3,
    "grade4": 4,
    "grade5": 5,
}

VALID_ACTIONS = {"escalate", "expand", "stop", "continue"}

# 激进度偏序：委员会动作不得比引擎建议更激进；更保守（stop）永远允许
_AGGRESSION = {"stop": 0, "expand": 1, "escalate": 2}


def action_within_engine(action: str, engine_recommendation: str) -> bool:
    """continue 是暂停解除语义、不改变剂量，单独放行；其余按激进度比较。"""
    if action == "continue":
        return True
    return _AGGRESSION.get(action, 0) <= _AGGRESSION.get(engine_recommendation, 0)

# 首版规则：≥3 级且经裁定可评估计为 DLT；按可评估受试者中的 DLT 例数给建议
DEFAULT_SPEC = {
    "min_severity_dlt": "grade3",
    "bands": [
        {"max_dlt": 0, "action": "escalate",
         "label": "0/可评估例 DLT：允许递增"},
        {"max_dlt": 1, "action": "expand",
         "label": "≤1 例 DLT：当前剂量扩展"},
        {"max_dlt": None, "action": "stop",
         "label": "≥2 例 DLT：停止递增"},
    ],
}


def validate_spec(spec: dict) -> dict:
    if not isinstance(spec, dict) or "bands" not in spec:
        raise ValidationFailed("规则规格必须包含 bands")
    ms = spec.get("min_severity_dlt", "grade3")
    if ms not in SEVERITY_ORDER:
        raise ValidationFailed(f"未知严重度等级: {ms}")
    bands = spec["bands"]
    if not isinstance(bands, list) or not bands:
        raise ValidationFailed("bands 必须是非空数组")
    seen = -1
    for b in bands:
        if b.get("action") not in {"escalate", "expand", "stop"}:
            raise ValidationFailed(f"非法区间动作: {b.get('action')}")
        mx = b.get("max_dlt")
        if mx is not None:
            if not isinstance(mx, int) or mx <= seen:
                raise ValidationFailed("max_dlt 必须严格递增")
            seen = mx
    return {
        "min_severity_dlt": ms,
        "bands": [
            {
                "max_dlt": b.get("max_dlt"),
                "action": b["action"],
                "label": b.get("label", ""),
            }
            for b in bands
        ],
    }


def counts_as_dlt(ae: dict, spec: dict) -> bool:
    """单条 AE 是否计为 DLT：进入引擎的严重度门槛 + 可评估裁定。"""
    if not (ae.get("assessed") and ae.get("evaluable")):
        return False
    sev = SEVERITY_ORDER.get(ae["severity"], 0)
    return sev >= SEVERITY_ORDER[spec["min_severity_dlt"]]


def evaluate(snapshot: dict, spec: dict) -> dict:
    """对快照载荷执行规则引擎，返回建议动作与可解释明细。

    snapshot 为构建时冻结的载荷：含 subjects[]（含 dlt/evaluable）、
    events[]（进入引擎的 AE 明细）、窗口与缺失数据门状态。
    """
    subjects = snapshot["subjects"]
    evaluable = [s for s in subjects if s["evaluable"]]
    dlt_subjects = {s["id"] for s in evaluable if s["dlt"]}

    dlt_count = len(dlt_subjects)
    chosen = None
    for band in spec["bands"]:
        mx = band["max_dlt"]
        if mx is None or dlt_count <= mx:
            chosen = band
            break

    return {
        "ruleset_version": snapshot.get("ruleset_version"),
        "recommendation": chosen["action"],
        "band_label": chosen.get("label", ""),
        "dlt_count": dlt_count,
        "evaluable_n": len(evaluable),
        "planned_n": snapshot["planned_n"],
        "dlt_subject_ids": sorted(dlt_subjects),
        "engine_events": snapshot.get("events", []),
    }
