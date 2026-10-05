"""时钟抽象。

默认使用真实 UTC 时间；演示/测试可通过 API 或服务方法设定“模拟当前时间”，
观察窗（now >= window_end）的判断完全依赖本模块，保证时间语义单一。
"""
from __future__ import annotations

from datetime import datetime, timezone


def now_utc(conn) -> datetime:
    row = conn.execute("SELECT value FROM kv WHERE key='clock_now'").fetchone()
    if row and row["value"]:
        return datetime.fromisoformat(row["value"])
    return datetime.now(timezone.utc)


def now_iso(conn) -> str:
    return now_utc(conn).isoformat()


def set_clock(conn, ts: str | datetime) -> str:
    """设定模拟当前时间（含时区的 ISO8601）。仅用于确定性演示与测试。"""
    if isinstance(ts, str):
        dt = datetime.fromisoformat(ts)
    else:
        dt = ts
    if dt.tzinfo is None:
        raise ValueError("时间戳必须带时区，建议使用 UTC")
    value = dt.astimezone(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO kv(key,value) VALUES('clock_now',?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (value,),
    )
    return value


def parse_iso(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        raise ValueError("时间戳必须带时区")
    return dt
