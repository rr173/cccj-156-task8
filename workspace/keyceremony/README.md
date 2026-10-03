# Key Management Ceremony Orchestration System

编排**根密钥全生命周期仪式**的系统：生成（GENERATE）、轮换（ROTATE）、
备份/份额恢复（BACKUP）、销毁（DESTROY）。每次仪式都强制固定参与角色、
门限份额、设备远程证明和严格的操作顺序；任何单人都无法重建密钥。

纯 Python 标准库实现（无第三方依赖），包含一个 RFC 8032 Ed25519 的独立实现。

---

## 1. 它保证什么

| 需求 | 实现方式 |
|---|---|
| **固定参与角色** | 四种固定角色：`ROOT_OWNER`（安全负责人）、`KEY_STEWARD`（HSM 托管员）、`WITNESS_SHAREHOLDER`（独立见证人）、`ENCLAVE_OPERATOR`（签名飞地操作员）。策略创建后不可变，仪式打开时冻结快照。任何单个组织角色凑不齐门限（策略校验强制）。 |
| **门限份额** | Feldman 可验证 Shamir 秘密分享（默认 3-of-4），份额域 = MODP-14 安全素数群的素数阶子群（`(q-1)/2` 阶），承诺 `C_j = g2^coeff_j`。每台设备独立验证自己的份额 `g2^s_i == Π C_j^(i^j)` 后才允许确认。 |
| **任何单人不能重建密钥** | 编排器在 GENERATE/ROTATE 中**从不接触份额明文**：多项式在编排端生成后，份额用各设备的封装公钥（素数子群 KEM + HKDF + HMAC AEAD，绑定 `仪式ID|设备ID` 上下文）逐个密封投递；确认只需设备签名声明 VSS 校验通过。签名种子只从同一常数项派生，私钥材料用服务主包装密钥单独封存。 |
| **设备证明** | 每台设备有身份密钥（Ed25519）、封装密钥（MODP）和软件度量（SHA256）。仪式先颁发挑战随机数，设备对 `(挑战, 当前度量, 封装公钥, 时间戳)` 签名报价；编排器校验签名、度量与注册值一致、封装公钥与注册一致、时间窗、子群成员关系，然后才投递份额。 |
| **操作顺序** | 严格阶段机：`OPEN → ATTESTED → DELIVERED → CONFIRMED → COMMIT → COMPLETED`，不可跳级、不可回退；动作信封带设备签名与一次性 nonce（重放/同 nonce 换载荷分别报 `DUPLICATE_ACTION` / `REPLAY_DETECTED`）；仪式有截止时间，超时自动 ABORT。 |
| **开始后参与者/策略变化必须废弃本轮并保留审计** | 策略修订（`revise_policy`）会自动 ABORT 所有使用旧策略的打开中仪式；手动 ABORT 擦除本轮所有秘密态（待定签名种子、入站恢复份额、投递信封），但审计链完整保留，之后可开新一轮。 |
| **新旧密钥交接窗口并存** | ROTATE 先生成 `STAGED` 后继版本；发布是对“当前 ACTIVE 版本”的**比较并交换（CAS）**。发布成功后旧版本变 `RETIRING`，两者在交接窗口（策略 `handover_seconds`）内并存。同一 purpose 同时只允许一个打开的轮换仪式、至多一个 RETIRING 版本。 |
| **签名方只用已激活版本** | `sign` 只使用 `ACTIVE`；对 STAGED/RETIRING/DESTROYED 签名抛 `CONFLICT_STATE`。 |
| **验证方继续识别历史版本** | `verify` 遍历该 purpose 所有已识别版本（STAGED/ACTIVE/RETIRING/DESTROYED），返回匹配版本及其状态；销毁只擦除私钥材料，公钥/指纹/承诺永久保留用于历史签名验证。 |
| **份额丢失可恢复** | BACKUP 仪式：存活者用旧承诺验证并提交份额（至少门限份），在**同一常数项**上重新随机化多项式，向恢复后名册分发新份额；`C0` 不变（绑定同一密钥），高次承诺全部更新，签名身份不变。 |
| **参与者掉线/永久丢失可恢复** | GENERATE/ROTATE/DESTROY 要求**全员到场**，掉线则本轮无法推进（可废弃重开）。永久丢失参与者时 BACKUP 可声明 `lost_participants` + 1:1 同角色替补（必须 `replaces` 指定丢失槽位），存活者 ≥ 门限即可；丢失超过 `n-t` 则按策略不可恢复。 |
| **重复确认可恢复** | 同一设备重复确认是幂等拒绝（`DUPLICATE_ACTION`），不改变状态；相同动作信封重放也是幂等拒绝。 |
| **轮换发布竞态不产生两个当前密钥** | 所有状态变更在跨线程 RLock + 跨进程 flock + 状态加载均在锁内的事务中；发布走 CAS。并发发布者恰好一个成功，其余得到 `409 RACE_LOST`，可用新的当前指针安全重试（成功方重试为幂等）。每个 purpose 任何时刻恰有一个 ACTIVE。 |
| **可验证记录导出** | `export.json`（策略快照、全部公钥版本、仪式、设备、参与者、完整审计）+ `audit.txt` + `SHA256SUMS`。导出整体由服务身份 Ed25519 签名；审计条目逐条哈希链接（`SHA256(prev ‖ payload ‖ ts ‖ seq)`）并逐条服务签名。离线校验器检查签名、哈希链、密钥生命周期溯源（每个版本都来自 COMPLETED 仪式）、销毁版本无私钥、单一 ACTIVE 不变量、交接一致性。 |

审计中**只出现**承诺、公钥、身份与哈希，份额明文、签名种子、恢复入站份额从不入审计。

---

## 1b. 值班员会话与四眼审批（网页端 / 服务端门禁）

上面的密码学仪式保证「任何单人不能重建密钥」；HTTP 服务层另外强制「任何单人不能
独自改规则、停流程、发布或清除」。**编排库本身不加门禁**——脚本、恢复控制台和
测试直接 `import kc.ceremony.Orchestrator` 仍可全量调用；门禁只存在于
`kc.server` 的 HTTP 表面。

| 需求 | 实现方式 |
|---|---|
| **登录令牌绑定人员/职责/终端/证明时效** | 登录先颁发一次性挑战，注册终端用钱包身份密钥对 `(挑战, 实时度量, 封装公钥, 时间戳)` 报价；服务端校验签名、度量、封装公钥、时窗后才签发令牌。令牌记录 `participant_id·role·device_id·measurement·quote_ts·expires_at`；原始令牌不落盘（只存其哈希标识 `token_id`）。终端撤销立即吊销其上全部在线会话。 |
| **查询按职责放行** | `authz.READ_SCOPES`：owner/witness 可看审计与导出包，steward/operator 不可；设备动作（attest/receive/confirm/submit-share）还要求令牌**本人终端**，驱动他人终端返回 `403 FORBIDDEN`。 |
| **四类高危动作须四眼** | 修改规则（`POLICY_CHANGE`）、终止活动流程（`ABORT_ACTIVE`）、发布新代（`PUBLISH_GENERATION`）、清除退役材料（`PURGE_RETIRED`，即 DESTROY 的 commit）在 HTTP 端不能直接调用，返回 `422 PROTECTED_OPERATION`。流程：发起人 `POST /api/tickets` → **另一人员、另一终端、互补职责** `POST /api/tickets/approve`，批准与执行在同一把存储锁内原子完成。 |
| **冻结规范化载荷摘要 + 截止时间** | 授权单保存 `canonical(JSON)`（排序、压缩）载荷的 SHA256 摘要与 `deadline`；批准时重算摘要，不一致即 `409 PAYLOAD_DRIFT` 并关闭授权单。 |
| **重复提交返回原授权单** | 同操作+同摘要存在 OPEN/EXECUTED 授权单时直接返回原单（`duplicate:true`），不新建。 |
| **并发批准最多执行一次** | 批准临界区在跨线程/跨进程锁内；6 路并发批准恰好 1 路成功，其余 `TICKET_CLOSED`。 |
| **失效即关闭、不落半成品** | 令牌失效/到期、终端撤销、载荷漂移、职责冲突、目标状态变化都会关闭授权单（记录机读 `closed_reason`），执行器在变更前完成校验，授权单从不留下执行一半的效果。 |
| **重新登录后继续** | 同人员在**同一注册终端**重新证明换发新令牌（旧令牌置 SUPERSEDED）后，其在途授权单仍可被批准；若终端撤销或无后继会话则关闭。 |
| **撤回** | 发起人可撤回自己在途的授权单（他人撤回 `403`）。 |
| **网页展示与操作** | 控制台展示登录身份（人员/职责/终端/证明度量/令牌标识/到期）、按职责可执行动作（无权限按钮禁用）、授权单表（双方、摘要、截止、决策链、执行结果）；支持发起、批准、撤回及退出/重新登录。 |
| **导出与离线核验** | 导出包新增 `sessions`（仅 token_id 等，绝无原始令牌）与 `auth_tickets`：双方身份、双方令牌标识、冻结摘要、完整决策链、执行结果。离线核验器校验：批准人≠发起人、终端不同、职责互补且在允许矩阵内、摘要稳定、执行效果在密钥/仪式状态中可见、每个执行/关闭/撤回都有哈希链审计记录；删改任一处都会被服务签名、审计链或 `four_eyes_tickets_ok` 检出。 |

互补职责矩阵（`kc/authz.py`）：

| 操作 | 可发起职责 | 可批准职责 |
|---|---|---|
| POLICY_CHANGE | ROOT_OWNER | WITNESS_SHAREHOLDER |
| ABORT_ACTIVE | ROOT_OWNER / KEY_STEWARD / ENCLAVE_OPERATOR | WITNESS_SHAREHOLDER / ROOT_OWNER |
| PUBLISH_GENERATION | ENCLAVE_OPERATOR / KEY_STEWARD | ROOT_OWNER |
| PURGE_RETIRED | KEY_STEWARD / ENCLAVE_OPERATOR | WITNESS_SHAREHOLDER / ROOT_OWNER |

登录与会话接口：`POST /api/session/login-challenge`、`POST /api/session/login`、
`POST /api/session/relogin`、`POST /api/session/logout`、`GET /api/session/me`、
`GET /api/tickets`、`POST /api/tickets[/approve|/withdraw]`、
`POST /api/devices/revoke`。服务端令牌通过 `Authorization: Bearer …` 传递。

---

## 1c. 可反复执行的跨区域灾备演练（隔离重建 / 只读镜像 / 租约切换 / 证据档案）

在**不触碰生产密钥材料**的前提下，反复证明某个恢复点能够在隔离区域重建服务、
承接只读校验流量，并安全完成故障切换与回切。原有命令行库与线上接口完全兼容；
新能力位于独立模块（`kc/regions.py`、`kc/drills.py`、`kc/evidence.py`），
演练引擎从不解封根材料——只复制**已加密封装对象**的描述符与哈希。

| 需求 | 实现方式 |
|---|---|
| **方案修订号 / 乐观并发** | 方案（plan）按修订号保存；两个浏览器同时编辑时，落后提交收到 `409 REVISION_CONFLICT`，载荷带 `base_revision/current_revision/base_snapshot/current_snapshot` 双方差异，绝不覆盖新版本。扫描后再改方案，旧扫描立即作废（状态回到 `DRAFT`）。 |
| **演练专用短期凭据 + 命名空间** | 启动即生成一次性 `drk_…` 凭据（仅创建响应返回，之后不再出现）与 `drill-<id>` 命名空间；凭据 `writes_allowed:false`、`production_referenceable:false`、只绑定隔离目标区域；过期不可再激活，必须终止后新开演练。 |
| **启动前清单扫描 → 固定蓝图** | 扫描核对快照清单、逐对象哈希、依赖版本、目标容量、加密封装（根材料必须 `sealed` + `kc-aead-v1`）与目标隔离策略（`AIRGAPPED` + 强制 `drill-` 命名空间 + 禁用生产凭据）；任何一项失败抛 `422 PREFLIGHT_FAILED`（列出全部问题）且**不创建任何资源**。通过后冻结固定恢复蓝图（含源/目标 `config_seq`、快照清单哈希）。 |
| **源快照/目标配置/蓝图变化即作废** | 蓝图钉住源/目标 `config_seq` 与恢复点 `manifest_hash`；源快照或目标配置一旦 `update_config()`，`latest_valid_scan` 立即返回空，启动演练抛 `409 BLUEPRINT_STALE`。 |
| **分阶段、幂等、可续跑引擎** | 固定阶段 `PREPARE → COPY → REBUILD_INDEX → SHADOW_START → PROBES → READY`，每阶段落持久化检查点与确定性幂等键 `SHA256(drill|stage|blueprint)`。崩溃 / 节点迁移 / 重复启动后从最后一个**已确认**阶段继续；资源按幂等键只建一次，对象不重复计入（测试在三个阶段注入崩溃并真实落盘重开）。 |
| **只读观察窗口 + 对比器** | 限时窗口内按方案比例（按请求关联号确定性选取，可复现）镜像只读校验请求；对比器记录请求关联号、双侧结果哈希、延迟与差异类别（`RESPONSE_MISMATCH/LATENCY/TIMEOUT`）。 |
| **写请求始终留在生产** | `SIGN/GENERATE/ROTATE/DESTROY/REVOKE/POLICY_CHANGE` 等写操作即使携带伪造的 `mirror_to_shadow` 标记也被明确拒绝（`POLICY_VIOLATION`），永远只走生产。窗口外的强制镜像同样被拒绝（`DRILL_FROZEN`）。 |
| **差异容错额度：非负整数，原子累计，超额才停用** | 方案字段 `diff_threshold` 必须是**非负整数**（拒绝负值、布尔、浮点与数字字符串）。系统在跨线程/跨进程存储锁内**原子累计不一致次数**，同一请求关联号无论重放多少次只计一次；仅当累计数**大于额度**时才冻结旁路（额度 0＝首个不一致即冻结；1＝容忍一个、第二个冻结；3＝容忍三个、第四个冻结）。计数在并发校验、服务重启（持久化 + 旧记录从差异清单回填）与人工 `resume` 解除后保持连续且不重复；冻结记录保留触发停用的关联号、当时额度与累计数。页面、HTTP 返回（`tolerance{diff_threshold,mismatch_count,trigger_request_id}`）、`mirror-stats` 与证据档案给出完全一致的额度、当前计数与触发关联号；离线核验器检查计数连续、关联号不重复、冻结快照与差异记录一致。 |
| **带期限的单持有者租约** | 仅当全部探针通过且仍满足 RTO 才能 `acquire lease`；多控制实例并发恰好一个成功，其余 `409 LEASE_CONTENTION`。租约只接管**只读校验入口**（`read_only_verification_ingress`），生产写入口保持不变。 |
| **统一收敛的回切状态机** | 租约丢失（到期）、区域恢复、窗口关闭、人工回切全部收敛到同一 `FAILED_BACK` 状态；重复提交回切返回**原结果**（同一 `failed_back_at`，幂等标记）。 |
| **受阻、可续跑的清理** | 终止先撤凭据、再删隔离资源、最后封存证据；清理中断后可继续。仍有镜像流量（窗口开）、有效租约或未归档差异时禁止删除关键资源，抛 `409 CLEANUP_BLOCKED` 并明确列出阻塞项；归档差异 / 关窗 / 释放租约后续跑完成。 |
| **可验证证据档案** | 证据含恢复点清单、蓝图摘要、阶段检查点、探针输入输出摘要、镜像对比统计、租约历史、回切与清理结果；清单逐节哈希 + 整体 `manifest_hash` + 服务身份 Ed25519 签名。离线检查器重算对象哈希与阶段顺序，检出伪造恢复点、跳过探针、重复阶段、窗口外镜像、租约重叠与证据缺口；旧格式 `kc-drill-evidence-v1` 仍可读取（结构归一化后校验）。 |

演练接口（HTTP 层按职责放行；库 `DrillsManager` 直调不加门禁，与既有设计一致）：

```
POST /api/drill-regions/{define|put-object|recovery-point}   # 区域/恢复点建模
POST /api/drill-plans            # 创建，或带 plan_id+base_revision 修订
POST /api/drill-plans/{id}/scan  # 清单扫描 → 固定蓝图
POST /api/drill-plans/{id}/start # 发短期凭据+命名空间，建演练
POST /api/drills/{id}/{run-to-ready|window|mirror|resume}
POST /api/drills/{id}/{lease|failover-status|failback}
POST /api/drills/{id}/{archive-differences|terminate|cleanup}
GET  /api/drill-plans /api/drills /api/drills/{id}
GET  /api/drills/{id}/evidence
```

职责矩阵新增 `drill:plan/scan/run/mirror/lease/failback/terminate` 能力与
`drills` 读域：owner/steward/operator 可设计、扫描、驱动与清理；**租约获取
（接管只读入口）仅 ROOT_OWNER**；witness 可只读查看演练与证据。导出包
新增 `drill_plans/drills/drill_evidence/drill_regions`，离线校验器增加
`drill_evidence_ok` 检查项。证据/审计中只出现哈希、封装描述符与公开标识，
短期凭据明文、根材料明文从不入库、不入审计（扫描也不写敏感内容）。

---

## 1d. 离线审计档案：增量见证与可恢复汇聚

各区域/节点把审计日志导出为**签名链分段**（`source` 来源标识、`seq` 单调
序号、`prev` 前序内容摘要、`payload_digest` 载荷摘要、来源 Ed25519 签名），
汇聚器逐段验签、按来源重建哈希链，并在**独立来源门限**达标、全部纳入来源
确认链连续且无未决冲突时形成可独立核验的**见证根**。新能力位于独立模块
（`kc/archive.py`、`kc/archive_verify.py`、`kc/archive_server.py`、
`kc/archive.html`），状态独立存于 `archive/state.json` 检查点。

| 需求 | 实现方式 |
|---|---|
| **校验签名与链关系** | 每个分段对四字段规范化 JSON 验来源 Ed25519；链按 `prev == 上一确认内容摘要` 逐 seq 推进，seq 1 的 `prev` 为全零。签名失败分段不入链，原样保留在 `invalid_segments` 证据中并返回 `BAD_SIGNATURE`。 |
| **乱序/重复/部分上传** | 未到前驱的分段作为候选持久化，缺口在视图中逐 seq 列出；前驱补齐后自动连续确认。完全相同的重复上传返回 `duplicate`，确认指针与计数不变（已确认分段绝不重复计入）。 |
| **同序号不同内容即隔离** | 同一 `(source, seq)` 出现第二个**有效签名但内容不同**的版本时，立即把来源置 `isolated`、开启冲突单并保留每个版本的完整签名证据；确认状态**不被污染**（停留在原链尖），其他来源继续汇聚。 |
| **持久化缺口/候选/确认位置** | 检查点 `archive/state.json` 记录每来源 `last_seq/last_digest/highest_seq`、全部候选版本、冲突单与历史发布；每次变更在共享 RLock + flock 内原子 rename 落盘。 |
| **崩溃/重启续跑** | 新进程打开同一目录即从检查点继续；`recover` 对所有非隔离来源重跑推进：已确认不重复计入，缺前驱不越过。隔离状态与冲突证据同样跨重启保留（测试覆盖）。 |
| **解除隔离须带理由的人工决策** | `resolve_conflict(conflict_id, accepted_digest, reason, decided_by)`，理由/决策人必填且必须选择证据中的版本。接受与当前确认不同的版本时，把冲突点及之后的确认**回滚**为 superseded，再从冲突点逐段重验链；不衔接的后续形成新缺口。拒绝版本永久留在证据，再次上传是幂等 `duplicate(rejected)`，不会重新隔离；但一个从未见过的第三版本仍会再次隔离。 |
| **多工作进程收敛** | 所有变更在跨线程/跨进程排他锁内“加载最新→计算→落盘”；线程池 4 路与进程池 4 路并发乱序投喂同一批分段，最终各来源收敛到同一确认位置与同一档案根。 |
| **门限 + 连续链 + 无未决冲突才能发布** | 发布前检查：非隔离且已确认 ≥1 的不同来源数 ≥ 配置门限（否则 `THRESHOLD_NOT_MET`，带 have/need）；全局不存在 OPEN 冲突（否则 `OPEN_CONFLICTS`）。 |
| **CAS / 单次提交发布** | 发布在同一把全局锁内比较当前确认位置：赢家创建清单、根含轮次/门限/各来源头/`prev_root` 并把轮次 +1；并发的输家（或无新确认的重复发布）拿到**已发布根**（`race_lost:true`），绝不产生第二个根。8 线程/6 进程并发恰好 1 个赢家。 |
| **迟到数据进下一轮、历史不可改写** | 发布后新确认属于下一轮，清单通过 `prev_root` 哈希链接；历史清单内嵌当轮全部已确认分段，之后再发布只追加不改写。 |
| **网页 / HTTP 展示与操作** | `python3 -m kc.archive_server --root ./kc-data --port 8090`：仪表盘展示每来源缺口、冲突（含全部版本摘要）、确认位置、隔离状态、当前轮次与历史发布根；支持注册来源（可一次性返回来源签名种子）、粘贴/批量上传分段、带理由的冲突处置、重启恢复、CAS 发布观察（3 秒自动刷新）。 |
| **离线验证器** | `python3 -m kc.archive_cli export --out bundle.json` 导出分段/检查点/冲突处置/发布清单；在无状态目录、无秘密的机器上 `python3 -m kc.archive_cli verify bundle.json` 重算所有来源链与每个见证根。明确检出：删段（`SEGMENT_DELETED`）、换段（`SEGMENT_SWAPPED`）、伪造签名（`FORGED_SIGNATURE`）、链断裂（`CHAIN_BROKEN`）、重复计入（`DOUBLE_COUNTED`）、越过缺口（`GAP_CROSSED`）、检查点不一致（`CHECKPOINT_MISMATCH`）、未决冲突下发布（`UNRESOLVED_PUBLISH`）、门限造假（`THRESHOLD_FALSIFIED`）、见证根篡改（`ROOT_TAMPERED`）、历史根被改写（`PREVIOUS_ROOT_REWRITTEN`）、无隔离记录的分叉（`CONFLICT_NOT_ISOLATED`）、处置后未重验链（`CONFLICT_CHAIN_FORK`）。每个历史清单按其**内嵌分段**独立重放，后续轮次增长不会冤枉旧快照。 |

档案接口（独立端口，建议绑定隔离/气隙网络；面向区域导出器的机器对机器
接口，默认无会话层）：

```
GET  /                                汇聚台页面
GET  /api/archive/status              缺口/冲突/确认位置/隔离/轮次/发布根
POST /api/archive/sources             {source, pubkey?}（省略 pubkey 则生成并一次性返回种子）
POST /api/archive/threshold           {threshold}
POST /api/archive/segments            单个分段或 {"segments":[...]}（可乱序/重复）
POST /api/archive/conflicts/resolve   {conflict_id, accepted_digest, reason, by}
POST /api/archive/recover             从检查点续跑
POST /api/archive/publish             CAS 发布（失败方返回 race_lost + 已发布根）
GET  /api/archive/publications        历史发布清单
GET  /api/archive/bundle              导出供离线核验的完整证据包
```

命令行：

```bash
python3 -m kc.archive_cli init      --root ./kc-data --threshold 2
python3 -m kc.archive_cli register  --root ./kc-data --source region-a   # 一次性返回种子
python3 -m kc.archive_cli mksample  --out a.json --source region-a --seed <b64> --count 4
python3 -m kc.archive_cli worker    a_late.json --root ./kc-data         # 独立工作进程
python3 -m kc.archive_cli recover   --root ./kc-data
python3 -m kc.archive_cli resolve   --root ./kc-data --conflict cfx-1 \
    --accept <digest> --reason "带外核验通过" --by alice
python3 -m kc.archive_cli publish   --root ./kc-data
python3 -m kc.archive_cli export    --root ./kc-data --out bundle.json
python3 -m kc.archive_cli verify    bundle.json
```

---

## 1e. 面向调用方的透明度日志（可公开核对的 Merkle 树 + Gossip 监督）

版本目录的每一次生命周期变更——**创建（初代 ACTIVE / 换代 STAGED）、启用
（handover ACTIVE）、交接退役（RETIRING）、抹除（DESTROYED）**——都生成一片
规范化叶子，叶子同时绑定：

```
purpose, version, version_id, 公钥 signing_pub + fingerprint,
state{prev, next}(状态摘要), ceremony_id, audit_ref（授权该变更的审计条目 hash）
```

叶子**只含公开材料**：公钥、指纹、状态摘要、仪式 id、审计引用；份额、签名种子、
服务封装材料永不进入叶子（叶子由编排器仅用公开字段构造）。叶子进入仅追加的
RFC 6962 式 Merkle 树；每次提交发布带服务身份 Ed25519 签名的 tree head
`{tree_size, root_hash, prev_head_hash, issued_at}`，head 之间以 `head_hash`
逐个头尾相接。

| 需求 | 实现方式 |
|---|---|
| **客户端仅凭旧 (size, root) 确认严格追加** | 包含证明与一致性证明的节点**位置完全由 `(index,size)`/`(old,new)` 递归派生**，服务端只能填兄弟哈希；验证器同时重算旧根与新根，旧根与客户端固定值比对（preimage 绑定）。截断历史、重排叶子、替换公钥、伪造状态跳转、拼入另一棵树的路径都失败。算法对树大小 0..260 的全部 `(index,size)`/`(old,new)` 组合穷举测试。 |
| **同一业务变更不重复入账** | 业务键 `audit_ref|version_id|event` 全局去重；同一审计事件被多构建器重复投递，返回**原叶子序号**，树大小只增长一次。 |
| **同一版本矛盾状态必须阻止新 head** | 每个 `(purpose,version)` 维护日志状态机（`NONE→CREATED/STAGED`、`STAGED→ACTIVATED`、`CREATED/ACTIVATED→RETIRED`、`RETIRED→ERASED`），且 `(purpose,version)` **永久绑定同一公钥/指纹**；prev 与日志现状不符或换钥即 `TRANSPARENCY_CONTRADICTION`，不挑选其一继续。 |
| **单一提交边界** | “分配序号 → 写叶子 → 更新树节点 → 发布 head”为一个事务。独立模式：`pending/<txn>.json` 意图 fsync → 追加叶子行 fsync → checkpoint 单次原子 rename。重开时在 flock 内恢复：叶子已持久化则**前滚**补发完整新 head，否则**回滚**截断悬空叶子；只能看到完整旧 head 或完整新 head。测试在“写叶子/更新节点/发布 head”附近（含 rename 后）用真实子进程 `os._exit` 注入中断。嵌入模式与编排器共用 `state.json` 原子 rename 边界。 |
| **多服务进程并发追加** | 独立构建器自带跨线程 RLock + flock，所有临时文件名带 pid+随机后缀，log 身份用 `O_CREAT\|O_EXCL` 原子认领；拿锁后先从磁盘重载再恢复。两个发布者争抢同一树大小时恰好一个生效，输方读到已生效结果（同业务键幂等）。测试 6 进程并发追加 12 个不同叶子 + 6 次重复投递，最终序号 0..16 确定无遗漏、head 链连续。 |
| **抹除后公开材料仍可查** | DESTROY 只零化私钥封装，叶子与公钥/指纹永久保留；旧代的包含证明、状态历史、历史签名验签照常。 |
| **Gossip split-view** | 浏览器/外部监控可免登录 `POST /api/transparency/observe` 提交自己见到的**已签名 head**。同树大小出现不同根（`SAME_SIZE_DIFFERENT_ROOT`），或更大 head 不能由本地较小 head 的一致性证明推出（`LARGER_HEAD_NOT_EXTENSION`），记录 split-view 事件并**冻结透明度发布**。被拒 head 原样保留为证据。 |
| **冻结不影响历史验签，但阻止新密钥激活** | 冻结期间 `sign/verify` 与全部历史验证照常；GENERATE/ROTATE 的物化 commit 与 handover 发布（含四眼批准路径）抛 `TRANSPARENCY_FROZEN`，杜绝“已激活但无透明度叶子”。 |
| **带原因的分支处置** | `POST /api/transparency/resolve`（仅 ROOT_OWNER）必须选**可证明延伸自本地链/最后可信 head** 的分支并填写原因；另一分支作为拒绝证据保留，随后重建从最后可信 head 开始的连续链，发布恢复。无原因/选择不可验证分支都被拒绝。 |
| **管理页面浏览器侧自行验算** | `/transparency` 展示当前 head、树大小、各用途最新公开版本、待记录状态事件、split-view 与处置记录。包含/一致性/head 签名全部在浏览器侧用 Web Crypto(SHA-256) 与内置纯 JS Ed25519(RFC 8032，含 SHA-512) **重新计算并明确显示通过/失败**，不把“接口返回成功”当结果；固定的可信 head 存 localStorage，刷新后保留。 |
| **独立检查程序** | `python -m kc.transparency_cli verify <export.json|section.json>` 输入叶子集合、head 链、签名、split 处置记录，重算全部根并校验生命周期。检出：缺叶(`MISSING_LEAF`)、重复业务事件(`DUPLICATE_BUSINESS_EVENT`)、叶子调序/换钥(`LEAF_REORDERED`)、错误包含证明(`BAD_INCLUSION_PROOF`)、断裂一致性(`BROKEN_CONSISTENCY`)、head 签名替换(`HEAD_SIGNATURE_REPLACED`)、同大小双根(`SAME_SIZE_TWO_ROOTS`)、跳过冲突直接发布(`PUBLISHED_DURING_SPLIT`)、密钥已激活但无叶子(`ACTIVATION_WITHOUT_LEAF`)、非法状态跳转(`ILLEGAL_LIFECYCLE_EDGE`)、换钥绑定(`CONTRADICTORY_KEY_BINDING`)、处置无效/拒绝证据缺失等。导出包整体校验新增 `transparency_ok`。 |

透明度公开接口（**均免登录**，任何调用方/监控都能核对；处置需 ROOT_OWNER 令牌）：

```
GET  /transparency                         管理页面（浏览器侧验算）
GET  /api/transparency/log-pub             日志签名公钥
GET  /api/transparency/status              head/树大小/各用途最新版本/待记录事件/split-view
GET  /api/transparency/head?size=n         指定树大小的已签名 head
GET  /api/transparency/leaves              全部公开叶子
GET  /api/transparency/inclusion?purpose=&version= | version_id= | audit_ref= | leaf_index=
                                           叶子 + 包含路径 + 签名 head
GET  /api/transparency/consistency?old_size=n
                                           从旧 head 到当前 head 的一致性路径
POST /api/transparency/observe             {head} 提交外部见到的已签名 head（gossip）
POST /api/transparency/resolve             {split_id, chosen_head, reason}（仅 ROOT_OWNER）
```

离线核验：

```bash
python -m kc.verify_export --from-store ./kc-data --outdir ./export
python -m kc.transparency_cli verify ./export/export.json
# transparency_ok 同时包含在 verify_export 的 [PASS] 清单中
```

---

## 1f. 签名入口的可核验用量预算（预算单 / 修订链 / 短租期保留 / 接管）

安全负责人按**用途 + 密钥版本**签发预算单：写明**调用主体、可签总次数、单批
上限、生效时间与截止时间、保留租期**。有预算单的用途，签名必须走

```
保留额度（唯一请求号 + 短租期 + 保留凭据）→ 产出签名（签名审计摘要）→ 保留结算为消费
```

三步各自追加一条哈希链 + 服务签名审计，并在追加后原子落盘 state.json。
没有预算单的用途**完全按原方式签名**（`Orchestrator.sign` 行为不变）。

| 需求 | 实现方式 |
|---|---|
| **先保留再签名、结算为消费** | `BudgetManager.hold → record_signature → settle`（`kc/budgets.py`）。全部变更在跨线程 RLock + 跨进程 flock 内「加载最新→判定→落盘」，**已结算 + 仍保留 ≤ 总量**，任何时刻可用量非负。 |
| **唯一请求号幂等** | 相同 `request_id` 再次提交绝不产生第二个签名或第二笔消费：已结算返回第一次的签名与结算记录；签名已写但未结算的重放自动补结算；租期内无签名的并发重放报 `REQUEST_IN_FLIGHT`。 |
| **最后额度并发争抢** | 线程池 8 路、真实进程（flock）6 路争抢总量 1：恰好 1 路成功，其余 `QUOTA_EXHAUSTED`，消费+保留恒等于总量。 |
| **短租期 + 进程退出接管** | 保留带 `lease_expires_at` 与 HMAC 保留凭据。接管者**只依据签名审计**判定：已有签名 → 结算（额度永不可再用）；无签名且租期已过 → 安全归还；租期未到 → 保持不动。`sweep_expired` 批量处理。 |
| **崩溃恢复不丢已 fsync 的决定** | 审计日志是权威记录：每步先 fsync 审计再 rename state.json；`BudgetManager.recover()` 从审计事件重建/推进记录，「审计已写、state 落后」的崩溃窗口被事件溯源补齐。 |
| **修订号递增 / 乐观并发** | 修订必须带 `base_revision`；旧修订提交返回 409 `REVISION_CONFLICT`，载荷带 `base/current_revision` 与双方快照数量差异，绝不覆盖较新决定。修订号必须严格 +1。 |
| **缩减下限** | 新总量不得小于 **已消费量 + 有效保留量**（`SHRINK_BELOW_CONSUMED_PLUS_HELD`，带 floor/双方数量）；恰好等于 floor 允许。 |
| **四类关闭条件拒绝新保留** | 预算暂停（`BUDGET_PAUSED`）、调用主体被撤销（`SUBJECT_REVOKED`）、密钥版本退役 RETIRING/DESTROYED/ABORTED（`KEY_VERSION_RETIRED`）、时间窗未生效/已结束（`BUDGET_NOT_YET_VALID/BUDGET_WINDOW_EXPIRED`）都拒绝新保留；**已完成签名继续验真**（verify 识别全部历史版本）。 |
| **跨主体挪用** | 保留的主体/用途/密钥版本必须与预算单一致；不同主体 403 `FORBIDDEN`，篡改档案被离线检查器判 `CROSS_SUBJECT_DIVERSION`。 |
| **人工处理悬挂保留** | 暂停/恢复/修订/主体管理仅 ROOT_OWNER（`budget:admin`/`budget:handle` 能力）。人工归还必须填写理由，审计记录**操作者、理由、处理前后的保留量**；已有签名审计的保留**不能释放**（`RESERVATION_HAS_SIGNATURE`），只能结算。 |
| **控制台与网络接口** | `/budgets` 页面与 `/api/budgets/status`（免登录只读）展示总量/可用/保留/消费/租期与每请求结算状态；带令牌接口支持创建、修订、暂停、恢复、接管、人工释放。凭据与签名不进入公开状态接口。 |
| **可验证档案** | 预算单、修订链、保留凭据、签名摘要、消费/归还记录全部在同一条哈希链审计中；导出包新增 `sign_budgets` 段，总核验新增 `sign_budgets_ok`。 |
| **离线检查器** | `kc.budget_verify`（`python -m kc.budget_cli verify-bundle export.json`）重放每次数量变化并重算各时点账本，检出：伪造预算 `FORGED_BUDGET`、重复消费 `DOUBLE_SPEND`、超额签名 `OVER_BUDGET`、跨主体挪用 `CROSS_SUBJECT_DIVERSION`、过期后保留 `RESERVATION_AFTER_WINDOW`、修订号回退 `REVISION_ROLLBACK`、缩减低于下限 `SHRINK_BELOW_FLOOR`、释放已有签名的保留 `RELEASE_WITH_SIGNATURE`、只有消费没有签名 `CONSUME_WITHOUT_SIGNATURE`、有签名却没有预算结算 `SIGNATURE_WITHOUT_SETTLEMENT`、引用不存在保留 `BAD_RESERVATION_CREDENTIAL`。 |

预算接口（HTTP 层按职责放行；库 `Orchestrator.budgets` 直调不加门禁）：

```
GET  /api/budgets/status                 # 免登录：总量/可用/保留/消费/租期/每请求状态
GET  /api/sign-budgets /api/sign-requests?budget_id=
POST /api/sign-budgets/subjects          # 注册调用主体（owner）
POST /api/sign-subjects/{id}/revoke      # 撤销主体
POST /api/sign-budgets                   # 创建预算单（owner）
POST /api/sign-budgets/{id}/revise       # 修订（base_revision 乐观并发）
POST /api/sign-budgets/{id}/{pause|resume}
POST /api/sign-requests/{id}/takeover    # 按签名审计判定 settle/release（签名者可调用）
POST /api/sign-requests/sweep            # 批量处理全部过期保留
POST /api/sign-requests/{id}/release     # 人工释放（owner，理由必填，有签名必拒）
POST /api/sign                           # 有预算单时必须带 request_id(+subject)，无预算单走旧路径
```

命令行：

```bash
python -m kc.budget_cli subject --root ./kc-data --id svc-billing --name Billing
python -m kc.budget_cli create  --root ./kc-data --purpose root-signing \
    --key kv_xxx --subject svc-billing --total 1000 --batch-cap 25 \
    --valid-until 2026-12-31T00:00:00Z --lease-seconds 30 --actor alice
python -m kc.budget_cli revise|pause|resume --root ./kc-data --budget bg_xxx ...
python -m kc.budget_cli takeover --root ./kc-data --request req-1
python -m kc.budget_cli release  --root ./kc-data --request req-1 \
    --operator alice --reason "worker host decommissioned"
python -m kc.budget_cli verify  --root ./kc-data
python -m kc.budget_cli verify-bundle export.json
```

`tests/test_budgets.py`（36 个场景：连续消耗到零、线程/进程争抢最后额度、
相同请求号重放、保留后退出且已/未签名、事件溯源恢复、缩减下限与并发修订冲突、
暂停恢复、主体撤销、时间窗、批量保留、凭据伪造、在途保护、退役/销毁旧版本
签名验真、无预算兼容、人工处理留痕、完整档案与 11 类被修改档案）与
`tests/budget_http_e2e.py` 覆盖全部验收项。审计中只出现主体/预算/请求标识、
消息与签名的摘要；签名私钥材料从不入预算审计。

---



## 2. 目录结构

```
kc/
  ed25519.py      纯 Python Ed25519（RFC 8032 向量验证）
  crypto.py       MODP-14 Feldman VSS、Shamir/Lagrange、KEM+AEAD 封装、HKDF、规范 JSON
  policy.py       固定角色、策略不可变快照、法定人数规则、阶段常量
  attestation.py  设备钱包（模拟 HSM）、注册记录、报价生成与校验
  ceremony.py     编排器：四仪式 × 六阶段状态机、恢复数学、CAS 发布
  directory.py    密钥版本目录：STAGED/ACTIVE/RETIRING/DESTROYED、签名与验证
  storage.py      文件锁（跨线程可重入 RLock + flock）、原子状态、哈希链审计
  regions.py      区域/命名空间/容量/隔离策略/恢复点清单（跨区域演练的区域模型）
  drills.py       灾备演练：修订方案、清单蓝图、分阶段幂等引擎、镜像对比、租约、受阻清理
  evidence.py     演练证据档案：签名清单 + 离线检查（伪造/跳探/重阶段/窗口外镜像/租约重叠）
  archive.py      离线审计档案：签名链分段汇聚、缺口/候选/冲突隔离、检查点恢复、CAS 见证发布
  archive_verify.py 档案离线验证器：删段/换段/伪造/断链/重复计入/越缺口/未决发布/根篡改
  archive_server.py 档案 HTTP API + 汇聚台（archive.html）
  archive_cli.py  档案命令行（init/register/mksample/worker/recover/resolve/publish/export/verify）
  transparency.py 调用方透明度日志：规范化公开叶子、RFC 6962 Merkle 树/包含/一致性、
                  签名 tree head、单事务原子提交（独立/嵌入）、多进程追加、gossip
                  split-view 冻结与带原因处置
  transparency_verify.py 独立检查器：重算全部根/证明/head 链/生命周期/双根/未登记激活
  transparency_cli.py 独立检查命令行（verify export.json|section.json）
  budgets.py      签名用量预算：预算单 + 递增修订链、调用主体、短租期保留、
                  保留凭据（HMAC）、签名审计、结算/归还、崩溃接管与事件溯源恢复
  budget_verify.py 预算离线检查器：重放每次数量变化，检出伪造/重复消费/超额/
                  跨主体挪用/过期保留/修订回退/释放已签名/只消费无签名等
  budget_cli.py   预算命令行（subject/create/revise/pause/resume/takeover/
                  sweep/release/verify/verify-bundle）
  budget.html     预算控制台 UI（预算单、计数器、租期、每请求状态、人工处理）
  transparency.html 透明度管理页面：浏览器侧 Web Crypto + 纯 JS Ed25519 自行验算
  sessions.py     终端证明登录：挑战/报价、绑定人员·职责·终端·时效的会话令牌
  authz.py        四眼授权单：冻结摘要/截止、互补职责矩阵、决策链、单次执行
  console.py      设备侧代理：证明→取件→验份额→签名确认
  fleet.py        模拟设备机群（每台设备一个 0600 钱包文件）
  export.py       记录导出与离线验证（含会话/四眼授权链核验）
  server.py       HTTP API + 控制台（ThreadingHTTPServer，会话+四眼门禁）
  console.html    仪式控制台 UI（登录身份/可执行动作/授权单面板）
  bootstrap.py    一键引导固定角色/设备/策略
  verify_export.py 导出/离线校验 CLI
tests/
  smoke_e2e.py        端到端冒烟
  test_ceremonies.py  21 个场景测试（证明、顺序、恢复、竞态、销毁、篡改检测…）
  test_edge.py        8 个边界测试（超时、VSS 失败、吊销、策略护栏、多用途、并发）
  test_authz.py       30 个会话/四眼测试（绑定、门禁、漂移、截止、撤销、并发单次、篡改导出）
  test_drills.py      37 个跨区域灾备演练场景（修订冲突、蓝图失效、分阶段崩溃续跑、
                      流量镜像隔离、差异冻结、租约竞争、回切幂等、受阻清理、证据篡改）
  test_archive.py     35 个审计档案场景（乱序补齐、重复幂等、同序冲突隔离与处置、
                      拒绝版本幂等、中断续跑、线程/进程收敛、门限拒绝、CAS 唯一发布、
                      迟到数据进下一轮、离线验证正常通过与 12 类篡改失败、HTTP 全流程）
  test_transparency.py 36 个透明度场景（Merkle 包含/一致性全几何穷举与篡改、公开性、
                      业务去重、矛盾状态/换钥阻止 head、多进程单序并发、四类中断
                      原子前滚/回滚、split-view 冻结/冻结期阻断激活/处置恢复/重启保留、
                      嵌入编排器两代证明与多次变更一致性、独立检查器 10 类检出）
  test_budgets.py     36 个签名用量预算场景（耗尽/线程与真实进程争抢/幂等重放/
                      保留后退出已签与未签/事件溯源恢复/修订冲突与缩减下限/暂停恢复/
                      撤销/时间窗/批量/凭据与在途保护/退役销毁旧签验真/无预算兼容/
                      人工留痕/完整档案 + 11 类篡改档案）
  http_e2e.py         HTTP 全流程含登录门禁、四类授权单、6 路并发批准、库直调不受限
  drill_http_e2e.py   演练 HTTP 全流程（区域/修订/扫描/续跑/镜像/冻结/租约/受阻清理/证据）
  budget_http_e2e.py  预算 HTTP 全流程（职责门禁、创建/修订/暂停、网络签名与重放、
                      12 路争抢、真实子进程崩溃接管、人工释放、免登录状态接口、
                      完整档案与被修改档案的离线检出）
  transparency_http_e2e.py 透明度 HTTP 全流程（公开证明、node 执行页面 JS 浏览器侧验算、
                      gossip 冻结、冻结期四眼发布被阻、历史验签可用、owner 带原因
                      处置后四眼发布恢复、一致性严格追加、拒绝分支留证）
```

## 3. 快速开始

```bash
# 1) 引导：4 个固定角色 + 设备钱包 + 3-of-4 策略
python3 -m kc.bootstrap --root ./kc-data
# 2) 启动控制台/API
python3 -m kc.server --root ./kc-data --port 8080
# 浏览器打开 http://127.0.0.1:8080/
```

控制台按钮对应一次仪式一步（每台设备独立证明、取件、验份额、确认）。

## 4. 一次完整仪式的操作顺序

GENERATE / ROTATE（DESTROY 无投递阶段；BACKUP 见第 6 节）：

1. `POST /api/ceremonies/open` — 冻结策略快照；同 purpose 不允许第二个打开中仪式。
2. 每台设备依次 `POST /api/ceremonies/{id}/attest`（全员，因为这三类仪式要求全员）。
   最后一份证明成功后阶段自动进入 `ATTESTED`，编排器随即分份并进入 `DELIVERED`。
3. 每台设备 `receive`：拉取**仅发给自己**的密封信封 → 设备内解封 → 对照公开
   Feldman 承诺验证份额。失败则设备拒绝确认（`vss_ok=false` 会被策略拒绝）。
4. 至少 **门限个不同参与者**确认，且**必须含 ROOT_OWNER**；到齐后进入 `CONFIRMED`。
   重复确认返回 `DUPLICATE_ACTION`，不影响继续。
5. `commit`：
   - GENERATE/ROTATE 物化密钥版本（GENERATE 直接 ACTIVE；ROTATE 先 STAGED）；
   - DESTROY 零化目标 RETIRING 版本的私钥材料。
6. ROTATE 额外 `publish`（带 `expected_active` 的 CAS）：旧版 → RETIRING，
   新版 → ACTIVE，交接窗口开始。竞态失败返回 `RACE_LOST`，刷新当前指针重试。
   **HTTP 端的 publish 必须经 PUBLISH_GENERATION 四眼授权单**（见第 1b 节）；
   库直调 `Orchestrator.publish_rotation` 不受此限。

## 5. 签名测试接口

```bash
curl -s -XPOST localhost:8080/api/sign   -d '{"purpose":"root-signing","message":"hello"}'
curl -s -XPOST localhost:8080/api/verify -d '{"purpose":"root-signing","message":"hello","sig":"..."}'
```

- 签名响应带 `version_id/version/status/fingerprint`；只有 ACTIVE 可签。
- 验证接受该 purpose 全部历史版本，返回匹配版本状态（`active:true/false`）；
  对 DESTROYED 版本的历史签名依然返回 `valid:true,status:DESTROYED`。

## 6. 份额丢失 / 参与者丢失恢复

```jsonc
// 打开 BACKUP：bruno 永久丢失，finn 以同角色替补
POST /api/ceremonies/open
{"kind":"BACKUP","policy_id":"pol-root-v1","purpose":"root-signing","actor":"alice",
 "lost_participants":["bruno"],
 "replacement_specs":[{"participant_id":"finn","role":"KEY_STEWARD",
                       "device_id":"dev_finn","replaces":"bruno"}]}
```

- 恢复名册（存活者+替补）全员 attest；
- 仅**存活者**（≥ 门限）用各自持有的旧仪式份额 `submit-share`，编排端逐份用
  当前密钥承诺校验，入站份额仅以服务包装密文短暂存放、完成后清除；
- 门限到达后在同一秘密上重建并重新分份（新随机多项式）；
- 恢复名册全员 receive、验份额、门限确认（含 owner）→ commit；
- 密钥 id 与签名公钥不变，承诺列更新、`share_meta` 指向新持有者。

纯粹的份额丢失（人还在、HSM 被擦）则 `lost_participants` 留空，全员提交/领取即可。

## 7. 可验证记录导出

```bash
# 从状态目录导出
python3 -m kc.verify_export --from-store ./kc-data --outdir ./export
# 在任意机器上离线核验（不需要状态目录或任何秘密）
python3 -m kc.verify_export ./export/export.json
# 也可 GET /api/export 获取签名包；GET /api/audit 查看链验证结果
```

输出 `[PASS] bundle_signature_ok / audit_chain_ok /
single_active_per_purpose / handover_consistent`。

## 8. HTTP API 摘要

除 `/health`、控制台页面和两个登录接口外，所有 API 都需要
`Authorization: Bearer <token>`（或 `X-Session-Token`）；令牌来自终端证明登录。
设备类接口要求令牌绑定的终端与请求的 `device_id` 相同。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/session/login-challenge` `/api/session/login` | 终端证明登录（无需令牌） |
| POST | `/api/session/relogin` `/api/session/logout` | 同终端重新登录续作 / 登出 |
| GET | `/api/session/me` `/api/tickets` | 当前身份/可执行动作 / 授权单列表 |
| POST | `/api/tickets` `/api/tickets/approve` `/api/tickets/withdraw` | 发起 / 批准执行 / 撤回授权单 |
| POST | `/api/devices/revoke` | 撤销终端（吊销其会话、关闭其在途授权单，仅 owner） |
| POST | `/api/participants` | 注册参与者并配发设备钱包（仅 owner） |
| POST | `/api/policies` | **已改为四眼**：直接调用返回 `PROTECTED_OPERATION`，走 POLICY_CHANGE 授权单 |
| POST | `/api/ceremonies/open` | 开仪式（按职责放行） |
| POST | `/api/ceremonies/{id}/attest` | 设备证明（仅本人终端） |
| POST | `/api/ceremonies/{id}/receive` | 取密封份额（仅本人终端） |
| POST | `/api/ceremonies/{id}/confirm` | 门限确认（仅本人终端） |
| POST | `/api/ceremonies/{id}/submit-share` | BACKUP 存活者提交旧份额（仅本人终端） |
| POST | `/api/ceremonies/{id}/commit` | 法定人数齐备后提交（DESTROY 走 PURGE_RETIRED 授权单） |
| POST | `/api/ceremonies/{id}/publish` | **已改为四眼**：PUBLISH_GENERATION 授权单批准时执行 CAS |
| POST | `/api/ceremonies/{id}/abort` | **已改为四眼**：ABORT_ACTIVE 授权单 |
| POST | `/api/sign` `/api/verify` | 签名测试接口（签名按职责放行；有预算单时 `/api/sign` 需带 `request_id`，见第 1f 节） |
| POST | `/api/sign-budgets[/subjects\|/{id}/revise\|/{id}/pause\|/{id}/resume]` | 预算单创建/修订/暂停/恢复（仅 owner） |
| POST | `/api/sign-subjects/{id}/revoke` | 撤销调用主体（仅 owner） |
| POST | `/api/sign-requests/sweep` `/api/sign-requests/{id}/takeover` | 过期保留批量/单个接管：按签名审计 settle 或 release |
| POST | `/api/sign-requests/{id}/release` | 人工释放悬挂保留（仅 owner，理由必填，有签名必拒） |
| GET | `/api/sign-budgets` `/api/sign-requests` | 预算与每请求结算状态（sign_budgets 读域） |
| GET | `/api/budgets/status` | **免登录**控制台数据（不含凭据/签名） |
| GET | `/api/keys` `/api/ceremonies` `/api/audit` `/api/export` | 只读视图（审计/导出仅 owner、witness） |

> 注意：这些门禁只在 HTTP 层。直接使用 `Orchestrator`（库）时，
> `create_policy/revise_policy`、`abort`、`publish_rotation`、`commit(DESTROY)`
> 等全部保持原样可用。

错误码：`POLICY_VIOLATION(422)`、`CONFLICT_STATE/DUPLICATE_ACTION/REPLAY_DETECTED/RACE_LOST(409)`、
`ATTESTATION_FAILED/AUTH_FAILED(401)`、`FORBIDDEN(403)`、
`PROTECTED_OPERATION(422)`、`TICKET_CLOSED/PAYLOAD_DRIFT/COMPLEMENTARY_DUTY_CONFLICT/TARGET_STATE_CHANGED(409)`、
`NOT_FOUND(404)`、`TAMPER_DETECTED(409)`。

## 9. 持久化与并发模型

- `state.json`：所有可变记录，锁内加载、原子临时文件 rename 落盘。
- `audit.log`：每行一个 JSON，追加写 + `fsync`，哈希链 + 服务签名。
- `.lock`：跨进程 flock；进程内按数据目录共享一把可重入 RLock。
  HTTP 服务多线程、多进程部署都被串行化，且每个请求在**锁内**读取最新状态。
- 重启后状态、密封私钥、审计链均可恢复；`tests/smoke_e2e.py` 覆盖重启验证。

## 10. 密码学说明（生产化注意）

本实现是**完整可运行的参考实现**，数学与协议真实（Ed25519 通过 RFC 8032 向量、
Feldman VSS 逐份验证、安全素数群子群一致性）。生产部署时建议：

- 份额多项式生成与签名运算放入真实 HSM/飞地；本系统的 `DeviceWallet` 是其软件模型；
- 用 FIPS 验证的模块化指数实现（当前为教学级纯 Python 2048 位运算）；
- 服务主包装密钥换成 KMS/HSM LMK；设备证明对接 TPM Quote/Nitro/TPM 证书链；
- 生产链路建议在终端证明登录之外再加 mTLS/传输加密。HTTP 层已实现终端证明
  会话（人员·职责·终端·时效绑定）、按职责放行与四眼授权单；库调用面按设计
  保持不加门禁（供受信恢复/自动化通道使用），生产暴露该面时应置于受控网络或
  再加一层调用方鉴权。

## 11. 测试

```bash
python3 tests/smoke_e2e.py
python3 -m unittest tests.test_ceremonies tests.test_edge tests.test_authz tests.test_drills tests.test_archive tests.test_transparency -v
python3 tests/http_e2e.py 8211          # 登录门禁 + 四类四眼授权单 + 6 路并发批准 + 库直调
python3 tests/drill_http_e2e.py 8212    # 跨区域灾备演练 HTTP 全流程
python3 tests/transparency_http_e2e.py 8213  # 透明度证明/浏览器验算/split 冻结处置
# 或一次跑完：
./run_tests.sh 8301 8302 8303
```

## 12. 一次四眼操作的示例（发布新代）

```bash
# 发起人 diego（ENCLAVE_OPERATOR，终端 dev_diego）先登录
curl -s -XPOST localhost:8080/api/session/login-challenge -d '{"device_id":"dev_diego"}'
TOK_D=$(curl -s -XPOST localhost:8080/api/session/login -d '{"device_id":"dev_diego"}' \
        | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
# 冻结规范化载荷 + 截止时间，创建授权单（重复提交返回原单）
T=$(curl -s -XPOST localhost:8080/api/tickets -H "Authorization: Bearer $TOK_D" \
    -d '{"operation":"PUBLISH_GENERATION",
         "payload":{"ceremony_id":"cer_xxx","expected_active":"kv_old"}}')
# 批准人 alice（ROOT_OWNER，另一人员、另一终端 dev_alice、互补职责）登录并批准；
# 批准瞬间在锁内做目标预检并执行 CAS，最多执行一次。
curl -s -XPOST localhost:8080/api/tickets/approve -H "Authorization: Bearer $TOK_A" \
    -d '{"ticket_id":"auth_..."}'
```

目标已被他路（含库直调）推进时，预检关闭授权单并返回 `TARGET_STATE_CHANGED`，
不会产生半成品；用最新状态创建新授权单即可。
