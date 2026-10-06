"""持久化层。

SQLite 单文件，采用「哈希链事件日志 + 当前态表」混合模式：
- journal 只追加，每条事件含 seq / prev_hash / 自身哈希，构成防篡改链；
- 当前态表（cohorts、subjects …）是事件的物化投影，供查询与规则引擎使用；
- 所有业务写操作在单个事务内同时追加事件与更新投影。
"""
from __future__ import annotations

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS journal (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  cohort_id TEXT,
  actor     TEXT NOT NULL,
  payload   TEXT NOT NULL,
  event_hash TEXT NOT NULL,
  prev_hash  TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trials (
  trial_id   TEXT PRIMARY KEY,
  title      TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cohorts (
  cohort_id   TEXT PRIMARY KEY,
  trial_id    TEXT NOT NULL,
  level       INTEGER NOT NULL,
  dose        REAL NOT NULL,
  dose_unit   TEXT NOT NULL,
  planned_n   INTEGER NOT NULL,
  window_days INTEGER NOT NULL,
  status      TEXT NOT NULL,            -- draft|active|closed|stopped
  revision    INTEGER NOT NULL DEFAULT 0, -- 受试者集合版本：替补 +1
  frozen_at   TEXT,
  window_end  TEXT,
  decided_at  TEXT,
  parent_cohort_id TEXT,
  parent_decision_id TEXT,
  rationale   TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subjects (
  id          TEXT PRIMARY KEY,
  cohort_id   TEXT NOT NULL,
  ordinal     INTEGER NOT NULL,
  revision_added   INTEGER NOT NULL,
  revision_removed INTEGER,            -- 被替补退出时的修订号
  status      TEXT NOT NULL,            -- enrolled|replaced|evaluable
  replaced_by TEXT,
  replaced_reason TEXT,
  dose_given  INTEGER NOT NULL DEFAULT 0,
  dose_at     TEXT,
  dlt         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS administrations (
  id           TEXT PRIMARY KEY,
  subject_id   TEXT NOT NULL,
  cohort_id    TEXT NOT NULL,
  given_at     TEXT NOT NULL,
  dose         REAL NOT NULL,
  dose_unit    TEXT NOT NULL,
  held_back    INTEGER NOT NULL DEFAULT 0, -- 暂停期间尝试给药被阻断（事实留痕）
  reason       TEXT,
  recorded_by  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS adverse_events (
  id          TEXT PRIMARY KEY,
  subject_id  TEXT NOT NULL,
  cohort_id   TEXT NOT NULL,
  term        TEXT NOT NULL,
  severity    TEXT NOT NULL,           -- grade1|grade2|grade3|grade4|grade5
  onset_at    TEXT NOT NULL,
  is_dlt_rule TEXT NOT NULL DEFAULT 'at_grade3', -- 触发判定的谓词版本（由规则集复制）
  assessed    INTEGER NOT NULL DEFAULT 0,
  evaluable   INTEGER NOT NULL DEFAULT 0,
  counts_as_dlt INTEGER NOT NULL DEFAULT 0,
  assess_note TEXT,
  assessed_by TEXT,
  assessed_at TEXT,
  late        INTEGER NOT NULL DEFAULT 0, -- 在某个快照/决策之后才到达
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_data (
  id         TEXT PRIMARY KEY,
  cohort_id  TEXT NOT NULL,
  subject_id TEXT,
  kind       TEXT NOT NULL,            -- lab|followup|ae_assessment|other
  note       TEXT NOT NULL,
  status     TEXT NOT NULL,            -- open|resolved|imputed
  resolution TEXT,
  resolved_by TEXT,
  resolved_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rulesets (
  version   INTEGER PRIMARY KEY,
  spec      TEXT NOT NULL,
  active    INTEGER NOT NULL DEFAULT 0,
  published_by TEXT NOT NULL,
  published_at TEXT NOT NULL,
  note      TEXT
);

CREATE TABLE IF NOT EXISTS committee_members (
  member_id  TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  role       TEXT NOT NULL,            -- independent|sponsor
  hmac_key   TEXT NOT NULL,
  active     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS snapshots (
  id           TEXT PRIMARY KEY,
  cohort_id    TEXT NOT NULL,
  seq          INTEGER NOT NULL,       -- 快照自身日志序号
  revision     INTEGER NOT NULL,       -- 绑定的受试者集合修订号
  ruleset_version INTEGER NOT NULL,    -- 绑定的规则版本（旧快照永远用旧规则）
  material_seq INTEGER NOT NULL,       -- 构建时最后一个实质性事件序号
  window_end   TEXT,
  content_hash TEXT NOT NULL,          -- 规范载荷哈希，投票与证明锚定它
  superseded   INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL,
  created_by   TEXT NOT NULL,
  UNIQUE(cohort_id, seq)
);

CREATE TABLE IF NOT EXISTS snapshot_payloads (
  snapshot_id  TEXT PRIMARY KEY,
  content_hash TEXT NOT NULL,
  payload      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS votes (
  id           TEXT PRIMARY KEY,
  snapshot_id  TEXT NOT NULL,
  cohort_id    TEXT NOT NULL,
  member_id    TEXT NOT NULL,
  action       TEXT NOT NULL,          -- escalate|expand|stop|continue
  content_hash TEXT NOT NULL,          -- 必须等于当前快照哈希，否则按陈旧拒绝
  signature    TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  UNIQUE(snapshot_id, member_id)       -- 同一快照每人一票
);

CREATE TABLE IF NOT EXISTS vote_drafts (
  id           TEXT PRIMARY KEY,      -- 客户端生成的草稿 ID（幂等键）
  snapshot_id  TEXT NOT NULL,
  cohort_id    TEXT NOT NULL,
  member_id    TEXT NOT NULL,
  action       TEXT NOT NULL,
  content_hash TEXT NOT NULL,          -- 草稿锚定的快照指纹
  signature    TEXT NOT NULL,          -- 委员离线时对「动作+指纹」的 HMAC 签名
  status       TEXT NOT NULL,          -- submitted|expired（待提交只存在于客户端本地）
  vote_id      TEXT,                   -- submitted 时产生的票
  conflict_code TEXT,                  -- expired 的冲突原因码（队列 API 返回）
  conflict_detail TEXT,
  created_at   TEXT NOT NULL,          -- 服务端首次收到时间
  resolved_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
  id          TEXT PRIMARY KEY,
  cohort_id   TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  action      TEXT NOT NULL,
  outcome     TEXT NOT NULL,           -- 规则引擎建议
  child_cohort_id TEXT,
  proof_hash  TEXT NOT NULL,
  proof_bundle TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  created_by  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS holds (
  id         TEXT PRIMARY KEY,
  scope      TEXT NOT NULL,            -- trial|cohort
  trial_id   TEXT,
  cohort_id  TEXT,
  reason     TEXT NOT NULL,
  status     TEXT NOT NULL,            -- active|released
  released_reason TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  released_by TEXT,
  released_at TEXT
);

-- 监管稽核员（归档端点的唯一授权主体；与委员会/操作角色分离）
CREATE TABLE IF NOT EXISTS auditors (
  auditor_id TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  api_key    TEXT NOT NULL,
  active     INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

-- 决定归档包：请求时固定日志区间 [seq_from, seq_to] 与链头哈希；
-- 状态机 queued → building → ready|failed，ready 后可被新归档 superseded。
CREATE TABLE IF NOT EXISTS decision_archives (
  id           TEXT PRIMARY KEY,
  request_id   TEXT UNIQUE,            -- 客户端幂等键（可空）；同键不同参数即冲突
  decision_id  TEXT NOT NULL,
  cohort_id    TEXT NOT NULL,
  policy       TEXT NOT NULL,          -- 规范化后的导出策略 JSON
  policy_hash  TEXT NOT NULL,          -- 策略内容哈希：去重键的一部分
  status       TEXT NOT NULL,          -- queued|building|ready|failed|superseded
  seq_from     INTEGER NOT NULL,       -- 固定日志区间起点（恒为 1：完整前缀才可独立验链）
  seq_to       INTEGER NOT NULL,       -- 固定区间终点：请求当时的链头序号
  head_hash    TEXT NOT NULL,          -- 区间终点事件哈希（包独立验真的锚）
  progress     TEXT,                   -- 续传检查点 JSON（built_upto_seq + 分阶段部件）
  package      TEXT,                   -- 完成后的完整归档包 JSON（不可改写）
  package_hash TEXT,
  error        TEXT,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  finished_at  TEXT,
  superseded_by TEXT                   -- 取代本归档的新归档 id（旧包内容永不被改写）
);

CREATE INDEX IF NOT EXISTS idx_journal_cohort ON journal(cohort_id, seq);
CREATE INDEX IF NOT EXISTS idx_subjects_cohort ON subjects(cohort_id);
CREATE INDEX IF NOT EXISTS idx_ae_cohort ON adverse_events(cohort_id);
CREATE INDEX IF NOT EXISTS idx_pending_cohort ON pending_data(cohort_id, status);
CREATE INDEX IF NOT EXISTS idx_votes_snapshot ON votes(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_drafts_cohort ON vote_drafts(cohort_id);
CREATE INDEX IF NOT EXISTS idx_decisions_cohort ON decisions(cohort_id);
CREATE INDEX IF NOT EXISTS idx_archives_decision ON decision_archives(decision_id);
-- 相同决定 + 相同导出策略：全库至多一份「活跃」（未被取代）归档。
-- 并发同键请求由服务锁串行化后幂等回放，本索引是数据库层的最终保证。
CREATE UNIQUE INDEX IF NOT EXISTS idx_archives_active
  ON decision_archives(decision_id, policy_hash) WHERE superseded_by IS NULL;
"""

# 使旧快照失效的“实质性事件”：迟到 AE / AE 评估变更 / 替补 / 给药事实。
# 规则发布不属于队列实质事件——隔离通过快照绑定的 ruleset_version 实现。
MATERIAL_EVENT_TYPES = {
    "administration_recorded",
    "administration_blocked",
    "ae_reported",
    "ae_adjudicated",
    "subject_replaced",
}


def connect(db_path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


GENESIS_HASH = "0" * 64


def append_event(conn, event_type: str, actor: str, payload: dict,
                 cohort_id: str | None = None) -> dict:
    """在当前事务内追加一条哈希链事件并返回事件行字典。"""
    from .clock import now_iso
    from .crypto import canonical_hash

    last = conn.execute(
        "SELECT seq, event_hash FROM journal ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    seq = (last["seq"] + 1) if last else 1
    prev_hash = last["event_hash"] if last else GENESIS_HASH
    created_at = now_iso(conn)
    event_hash = canonical_hash(
        {
            "seq": seq,
            "event_type": event_type,
            "cohort_id": cohort_id,
            "actor": actor,
            "payload": payload,
            "prev_hash": prev_hash,
            "created_at": created_at,
        }
    )
    conn.execute(
        "INSERT INTO journal(seq,event_type,cohort_id,actor,payload,"
        "event_hash,prev_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (
            seq, event_type, cohort_id, actor,
            __import__("json").dumps(payload, ensure_ascii=False),
            event_hash, prev_hash, created_at,
        ),
    )
    return {
        "seq": seq,
        "event_type": event_type,
        "cohort_id": cohort_id,
        "actor": actor,
        "payload": payload,
        "prev_hash": prev_hash,
        "event_hash": event_hash,
        "created_at": created_at,
    }


def verify_chain(conn) -> dict:
    """重放校验整条哈希链。供决策证明校验与审计使用。"""
    from .crypto import canonical_hash
    import json

    prev = GENESIS_HASH
    rows = conn.execute("SELECT * FROM journal ORDER BY seq").fetchall()
    for r in rows:
        payload = json.loads(r["payload"])
        digest = canonical_hash(
            {
                "seq": r["seq"],
                "event_type": r["event_type"],
                "cohort_id": r["cohort_id"],
                "actor": r["actor"],
                "payload": payload,
                "prev_hash": r["prev_hash"],
                "created_at": r["created_at"],
            }
        )
        if r["prev_hash"] != prev:
            return {"ok": False, "events": r["seq"], "broken_at": r["seq"], "reason": "链断裂"}
        if digest != r["event_hash"]:
            return {"ok": False, "events": r["seq"], "broken_at": r["seq"], "reason": "哈希不匹配"}
        prev = r["event_hash"]
    return {"ok": True, "events": len(rows), "head": prev}
