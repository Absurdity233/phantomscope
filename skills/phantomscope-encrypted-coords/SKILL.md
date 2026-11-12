---
name: phantomscope-encrypted-coords
description: 用 phantomscope(DMA) 处理游戏坐标/数值加密：区分明文与密文字段、定位加密函数、在 unicorn 快照里跑函数反推密钥、判断加密强度与可行性边界。当用户问"坐标加密怎么破""数值是密文""找解密函数""反推密钥"时触发。
---

# 对抗坐标/数值加密

先立一条事实：**DMA 读的是内存，不是密文。加密只影响"你看到什么形态"，不影响"能不能读到"。**

所以路线永远优先是「**找明文**」，其次才是「**解密码**」。

## 第 1 步：判断哪些字段是密文

本地移动用的坐标通常明文；发包用的密文。两者常常同时存在。

```jsonc
{"tool": "attach", "arguments": {"process": "game.exe"}}
// 走动的同时连续采样
{"tool": "trace_changes", "arguments": {
  "va": "0x21A00000100", "size": 512, "samples": 20, "interval": 0.02}}
```

| 采样特征 | 结论 |
|---|---|
| `float`，缓慢单调变化，只在移动/转向时变 | **明文坐标** |
| `int32`/`int64`，几乎每次采样都变，`flips` 极高 | 密文 / 滚动密钥字段 |
| 完全不动 | 静态配置或缓存 |
| 只在特定动作时突变 | 状态标志，不是坐标 |

`trace_changes` 的 `interpretations` 会同时给 int32/uint32/float/int64/double 读数——
**同一个字节序列读成 float 是坐标、读成 int64 是噪声**，这是最快的判别方式。

```jsonc
{"tool": "trace_value", "arguments": {"va": "<某个候选>", "value_type": "float", "samples": 30}}
```

`deltas` 平滑且单调 → 明文。跳变剧烈 → 密文或指针。

## 第 2 步：找到明文就到此为止

如果能找到明文坐标，**不需要解密任何东西**：

```jsonc
{"tool": "infer_struct", "arguments": {"va": "0x21A00000100", "count": 8, "stride": 0x200, "align": 4}}
```

`infer_struct` 会把 float 型字段标出来，`varies: true` 的是每实例数据。
拿到偏移后按 `phantomscope-offset-dump` 的流程固化成链。

## 第 3 步：找不到明文 → 定位加密函数

活体没有 xref，必须转静态：

```jsonc
{"tool": "capture_module", "arguments": {"module": "game.exe", "key": "g"}}
{"tool": "find_api", "arguments": {"key": "g", "needle": "Crypt"}}
{"tool": "crypto_constants", "arguments": {"key": "g"}}
{"tool": "search_immediates", "arguments": {"key": "g", "value": "0x9E3779B9"}}   // TEA/XXTEA delta
```

常见命中：

| 常量 | 算法 |
|---|---|
| `0x9E3779B9` / `0x61C88647` | TEA / XXTEA |
| AES S-box（`crypto_constants` 直接标出） | AES |
| `0x85EBCA6B` / `0xC2B2AE35` | MurmurHash（校验不是加密） |
| 大段高熵常量 + 循环 xor | 自定义轮密钥 |

配合 `find_api` 找 `RtlEncryptMemory` / `BCrypt*` / `CryptEncrypt`——用了系统加密库的话
直接就知道算法，但密钥还得找。

## 第 4 步：在快照里跑函数，反推密钥

这是这套工具在加密场景最实在的杀招：**不需要在目标里跑任何代码，不需要断点。**

```jsonc
{"tool": "emu_create", "arguments": {"key": "g", "stubs": true, "trace": true}}
// 把已知明文写进模拟器内存
{"tool": "emu_write", "arguments": {"key": "g", "va": "0x50000000", "data": "<明文字节 hex>"}}
{"tool": "emu_call", "arguments": {"key": "g", "va": "0x14002A1C0", "args": "0x50000000,0x50000008"}}
{"tool": "emu_read", "arguments": {"key": "g", "va": "0x50000008", "size": 16}}
```

拿同一时刻真实内存里的密文对一遍：

- **对得上** → 就是它。密钥在函数里，或者从全局读——`emu_regs` + `emu_read` 挖出来
- **对不上** → 抓错函数，或前置状态没设对。看 `emu_faults`

`stubs: true` 是必须的：快照只有镜像本体，`call [rip+IAT]` 会落到未映射地址。
stub 把每个导入槽换成 `mov eax,imm; ret`，让函数能跑完。

## 第 5 步：确认走的是哪条分支

加密函数几乎都有密钥长度 / 算法分支：

```jsonc
{"tool": "emu_coverage", "arguments": {"key": "g"}}
```

`forks` 里每个多后继地址就是一次真实的分支决策，`successors[].hits` 告诉你走了几次。
配合 `emu_reached` 确认某条路径根本没进——这比读反汇编猜快得多。

## 可行性边界（别猜，这里说清楚）

| 加密形态 | 能做 | 卡在哪 |
|---|---|---|
| 异或 / 简单加减 | ✅ 完整 | — |
| TEA / XXTEA / RC4 | ✅ 模拟器里跑函数即可 | 密钥可能在全局，需 `emu_read` |
| AES 每帧换密钥 | ⚠️ 能定位函数和密钥生成 | 密钥本身要跟着跑 |
| 每帧滚动密钥（帧同步） | ⚠️ 能观察，工作量大 | 要把密钥生成函数也模拟出来 |
| 内存里从无明文，只在寄存器一闪 | ❌ DMA 拿不到 | 只能 `snapshot` 后模拟整条路径 |
| 服务端权威 + 纯校验 | ❌ 改了也会被发现 | 这是协议问题，不是加密问题 |

**记住：改密文没有意义，即使补上都要重算校验链。** 找到明文位置才是终点。

## 常见坑

| 现象 | 原因 |
|---|---|
| 采样的 float 是 NaN/极大值 | 读错了偏移，不是加密 |
| `crypto_constants` 命中 MySQL/网络库常量 | 目标链接了第三方库，不是它的加密 |
| `emu_call` 立刻 fault at 0x0 | 少了 `stubs: true`，或参数是脏指针 |
| `emu_call` 返回但结果不对 | 前置状态没设（全局初始化没跑），先 `emu_call` 初始化函数 |
| 反推的密钥每次重启都变 | 密钥派生自进程/机器 ID，要连着派生函数一起看 |
