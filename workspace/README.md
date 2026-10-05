# 早期临床试验剂量递增安全决策平台

面向首次人体 / 剂量递增试验的安全决策系统。每个队列**冻结**给药方案、观察窗和受试者集合；
安全事件按严重度和可评估状态进入**版本化规则引擎**；只有**五道安全门**全部通过、
且**独立安全委员达到门槛**，才能递增（escalate）、扩展（expand）或停止（stop）。

零第三方依赖：Python 3.11 标准库（sqlite3 / http.server / hmac / hashlib）。

## 核心安全不变量

| 要求 | 实现机制 |
|---|---|
| 队列冻结给药方案/观察窗/受试者集合 | `freeze_cohort` 后剂量、窗不可改；受试者集合以 `revision` 编号，替补产生新修订 |
| 安全事件按严重度+可评估状态进入引擎 | AE 须经裁定（assessed + evaluable），规则门槛 `min_severity_dlt`（默认 ≥ grade3）才计 DLT |
| 观察窗完整 + 缺失数据处理完毕 + 委员门槛 | 五道安全门：窗口完整 / 缺失数据清零 / 事件全裁定 / 可评估集合完整 / ≥2 名在职独立委员 |
| **迟到 AE、替补、规则修订不得拼接快照** | 每次决策锚定单快照 `content_hash`；实质性事件（AE/裁定/替补/给药）使旧快照 `superseded`；规则集不可变、快照绑定 `ruleset_version`，修订永不重算历史快照 |
| **两名委员并发投票不得拼接** | 投票携带 `expected_version`（乐观并发）+ 服务级锁 + DB 层计数 CAS；后到者得到 409，必须刷新视图重试 |
| **断网草稿不得绕过快照核对** | 草稿离线签名（动作+快照指纹）存本地；恢复后服务端先核对快照仍有效（迟到事件/替补/规则换版/指纹）再一次写票；`draft_id` 幂等，重复提交只回放首次结果 |
| **紧急暂停立即阻断后续给药、保留已给药事实** | 暂停事务提交即生效（支持队列级/全试验级）；阻断的给药尝试以 `held_back=1` 留痕；`administrations` 表只追加，已给药行永不修改/删除 |
| 决策可证明、可审计 | 哈希链事件日志（seq/prev_hash/hash）+ 快照内容哈希 + 委员 HMAC 签名；决策证明含 11 项独立校验 |

规则约束：递增/扩展类决定不得超越引擎建议（`engine_disagreement`）；保守的 `stop` 永远允许；
暂停生效期间只接受 `stop` / `continue` 投票。

## 运行

```bash
# 启动（自带 Web 安全工作台 + REST API）
python3 -m app.server --db data/platform.db --port 8080
# 打开 http://127.0.0.1:8080 ，点「载入演示数据」

# 命令行一键演示全链路（含并发投票与紧急暂停）
python3 -m app.cli_demo

# 测试
python3 -m unittest tests.test_platform -v
```

## 决策流程

```
建试验 → 建队列(draft) → 入组 planned_n 人 → 冻结(方案/窗/集合)
  → 登记给药(只允许冻结剂量) → AE 上报/裁定 → 缺失数据登记/处理
  → [观察窗结束] → 构建快照（跑规则引擎+五门，计算 content_hash）
  → ≥2 名独立委员 HMAC 签名投票（expected_version 乐观并发）
  → 签发决定（校验：同一快照哈希/门槛/引擎/暂停/签名/哈希链）
  → escalate/expand: 关闭本队列并派生子队列草案；stop: 队列停止
```

## REST API 摘要

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/trials` `/api/cohorts` | 建试验/队列 |
| POST | `/api/cohorts/{id}/enroll` `/freeze` | 入组 / 冻结 |
| POST | `/api/cohorts/{id}/administrations` | 登记给药（暂停时返回 409 且留痕） |
| POST | `/api/cohorts/{id}/aes` `/api/aes/{id}/adjudicate` | AE 上报（首快照后自动标 late）/ 裁定 |
| POST | `/api/cohorts/{id}/pending` `/api/pending/{id}/resolve` | 缺失数据登记/处理（可标 imputed） |
| POST | `/api/subjects/{id}/replace` | 受试者替补（revision+1，旧快照失效） |
| POST | `/api/rules` | 发布规则集新版本（不可变，旧快照不受影响） |
| POST | `/api/cohorts/{id}/holds` `/api/holds/{id}/release` | 紧急暂停 / 解除 |
| POST | `/api/cohorts/{id}/snapshots` | 构建快照（引擎+五门+content_hash） |
| POST | `/api/snapshots/{id}/votes` | 委员投票（member_id/action/signature/expected_version） |
| POST | `/api/drafts` | 断网草稿一次性提交（draft_id 幂等；过期返回 409 + 冲突原因） |
| GET | `/api/drafts` `/api/cohorts/{id}/drafts` | 草稿队列：submitted/expired 状态与冲突原因 |
| POST | `/api/snapshots/{id}/decisions` | 签发决定并生成决策证明 |
| GET | `/api/decisions/{id}` `/verify` | 决定与证明 / 11 项独立校验 |
| GET | `/api/state` `/api/journal` | 全局状态 / 哈希链事件日志 |
| POST | `/api/clock` | 推进模拟时钟（确定性演示/测试） |
| POST | `/api/sign` | 演示用：委员 HMAC 本地签名端点 |

## 断网投票草稿

委员网络中断时，工作台把「决定动作 + 快照指纹（content_hash）」用本地 HMAC 签名存为
**本地草稿**（localStorage，待提交）；网络恢复后：

1. 先 `GET /api/snapshots/{id}` 核对快照仍然有效，再 `POST /api/drafts` 一次性提交；
2. 服务端权威复核：快照若已被**迟到事件、替补**推进（`snapshot_superseded`）或
   **规则换版**（`ruleset_advanced`，草稿特有检查——离线决定是在旧规则结论下作出的），
   草稿落库为**过期**并返回冲突原因，**不写入任何票**；
3. 同一 `draft_id` 重复提交只回放首次结果（submitted → 同一 `vote_id`；expired → 同一冲突），
   配合 `votes UNIQUE(snapshot_id, member_id)` 保证绝不产生第二张票；
4. 工作台展示三种状态：**待提交**（本地）/ **已提交** / **过期**（含服务端冲突原因）；
   队列 API `GET /api/cohorts/{id}/drafts` 返回同样内容。

实时投票与决策证明校验路径不受影响，继续可用。

## 决策证明（11 项校验）

`GET /api/decisions/{id}/verify` 独立重算：证明哈希未改、快照哈希锚定、快照载荷可重算、
快照未失效、五门全过、**规则引擎按绑定版本重算结论一致**、全部投票 HMAC 签名有效、
**每张票锚定同一快照哈希**、法定人数满足（≥2 票且 ≥2 独立）、事件哈希链完整、
动作未超越引擎。任一项失败即 `verified=false`。

## 代码结构

- `app/store.py` — SQLite schema、哈希链追加 `append_event`、`verify_chain`
- `app/services.py` — 领域服务：冻结/给药/暂停/AE/缺失/替补/规则/快照/投票/断网草稿/决定/证明
- `app/rules.py` — 版本化规则规格与引擎（严重度→DLT→bands→建议）
- `app/crypto.py` — 规范 JSON / SHA-256 / HMAC
- `app/clock.py` — 可注入时钟（观察窗判定唯一时间来源）
- `app/server.py` + `app/web/index.html` — REST API 与安全工作台（含断网模拟与草稿队列）
- `tests/test_platform.py` — 32 个不变量测试
