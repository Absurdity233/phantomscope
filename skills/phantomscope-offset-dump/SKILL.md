---
name: phantomscope-offset-dump
description: 用 phantomscope(DMA) 从活体进程 dump 出可跨重启复用的游戏偏移表；走 scan_value 收窄 → pointer_scan 找模块锚定链 → pointer_chain_replay 验证 → 输出 base+offsets 模板。当用户要"找偏移""dump 偏移链""基址+多级指针""更新后偏移失效"时触发。
---

# 游戏偏移 dump

目标产出**不是**一个绝对地址，而是一份 `base=模块+偏移, offsets=[...]` 的模板。
绝对地址在下一次启动就失效，模板不会。

## 前置

无硬件时先在合成目标上把流程走一遍（`--kind game` 是一个带 tick 的模拟 FPS 客户端，
血量每 20ms 掉 1，实体坐标持续漂移——正好是收窄扫描需要对抗的东西）：

```powershell
phantomscope chain --kind game --process firefight "firefight.exe+0x3008" "0,4" --value-type int32
# → value 100 (int32), template base=firefight.exe+0x3008 offsets=[0, 4]
```

输出里的 `template` 就是这份文档要你产出的东西。

```powershell
.\.venv\Scripts\python.exe tools\probe_backend.py fpga    # 先确认设备与各操作延迟
```

首次 `Vmm()` 初始化 20–40 秒是正常的；某个调用卡住就是设备状态问题，别怀疑工具。

## 第 1 步：确认数值本身

```jsonc
{"tool": "session_open", "arguments": {"device": "fpga"}}
{"tool": "attach", "arguments": {"process": "game.exe"}}
{"tool": "scan_value", "arguments": {"value": "100", "value_type": "int32", "label": "hp"}}
```

**关键：先让目标变化，再收窄。** 一次扫描会命中成千上万个 100，这不叫找到了。

```jsonc
// 掉血之后
{"tool": "scan_next", "arguments": {"key": "hp", "value": "95"}}
// 再变一次
{"tool": "scan_next", "arguments": {"key": "hp", "value": "88"}}
{"tool": "scan_results", "arguments": {"key": "hp"}}
```

剩 1–5 个才继续。剩几十个说明类型选错了（`float` / `double` / `int16` 都试一遍），
或者这个值根本不是本地存储的。

> **`scan_next` 也接受 `changed=true`** —— 不给具体数值，只保留"跟上一次不同"的地址。
> 对付每帧都在抖动的值（坐标、朝向）比猜数值有效。

## 第 2 步：反推模块锚定链

```jsonc
{"tool": "pointer_scan", "arguments": {"target": "0x21A000001F8", "max_depth": 3, "module": "game.exe"}}
```

- `max_depth` 每一层代价近似翻倍。**2–4 层覆盖绝大多数真实目标**，再深基本是对象数组，
  改用 `read_array(follow=true)` 遍历，比继续加深度划算得多。
- 加 `"module": "game.exe"` 只搜模块区域，快一个数量级，而且直接得到想要的东西。
- 返回里 `module_anchored: true` 的才是你要的。`false` 的锚在栈/堆上，重启必失效。

## 第 3 步：验证，不要假设

```jsonc
{"tool": "pointer_chain_replay", "arguments": {"candidates": "<上一步 returned JSON>", "value_type": "int32"}}
```

`matched: true` 才算通过。工具会**拒绝**非模块锚定的链并说明原因，这是特性不是障碍。

**真正可靠的验证是重启目标再跑一遍。** 工具能验证"这条链现在解得开"，
不能验证"下个版本还成立"——那需要 diff。

## 第 4 步：产出模板

```jsonc
{"tool": "resolve_pointer_chain", "arguments": {
  "base": "game.exe+0x2A1B3C0", "offsets": "0x10,0x38,0x8", "value_type": "int32"}}
```

返回的 `template` 就是最终交付物：

```json
{"base": "game.exe+0x2a1b3c0", "offsets": [16, 56, 8], "value_type": "int32"}
```

`levels[]` 里每一跳都带模块/区域/权限/是否可写——`writable: false` 说明那一段是只读的，
写入会被拒绝，得换别的路径。

## 版本更新后怎么修

```jsonc
{"tool": "load_file", "arguments": {"path": "old.exe", "key": "old"}}
{"tool": "load_file", "arguments": {"path": "new.exe", "key": "new"}}
{"tool": "diff_images", "arguments": {"left": "old", "right": "new", "min_similarity": 0.6}}
```

- `identical` 的函数地址不变 → 偏移照用
- `similar` 的函数长度变了 → 它后面的所有偏移要整体重算
- 链中某一跳的目标函数在 `removed` 里 → 那条链作废，重扫

`fingerprint` 给出归一化哈希，跨构建稳定，用它判断"是不是同一个函数"比看代码快。

## 常见坑

| 现象 | 原因 |
|---|---|
| 收窄后剩几十个 | 值类型错；或这个值是网络同步的，本地没有 |
| `pointer_scan` 特别慢 | 没加 `module=`；或 `max_depth` 太深 |
| 链解得开但值不对 | 命中的是另一个同值字段，回到第 1 步用更独特的数值 |
| 重启后链失效 | 用了 `module_anchored: false` 的链 |
| 写入报错 | 目标页只读（看 `levels[].writable`），或反作弊拦了写 |

## 硬件注意

DMA 写目标内存是**真写**。`write` 全部记日志，`patch_restore(all=true)` 全撤——
写错地址会崩目标，能回滚是唯一的安全网。改值前先 `snapshot` 一份。
