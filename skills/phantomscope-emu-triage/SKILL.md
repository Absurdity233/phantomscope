---
name: phantomscope-emu-triage
description: 用 phantomscope 的快照模拟器在没有调试器的情况下判断函数行为：emu_create(stubs) 跑函数拿返回值、emu_coverage 的 forks 判断走了哪条分支、emu_calls 看调了哪些 API 和参数、emu_faults 定位崩溃点、emu_stubs 驱动返回值做假设检验。当用户问"这个函数干什么""校验过没过""走哪条分支""为什么崩"时触发。
---

# 快照模拟器做函数级 triage

**这套东西的存在理由**：DMA 不能停线程、不能单步、没有寄存器上下文。
但把镜像抓到本地丢进 unicorn 之后，**爱怎么断怎么断**——代价是只有静态数据，没有运行时状态。

所以定位很清楚：**回答「这段代码在给定输入下做什么」，不回答「目标此刻在做什么」。**

## 第 0 步：准备

```jsonc
{"tool": "load_file", "arguments": {"path": "target.exe", "key": "t"}}
// 或者从活体抓（推荐——拿到的是真正在跑的镜像）
{"tool": "capture_module", "arguments": {"module": "target.exe", "key": "t"}}
{"tool": "emu_available", "arguments": {}}
```

## 第 1 步：一定要开 stubs

```jsonc
{"tool": "emu_create", "arguments": {"key": "t", "stubs": true, "trace": true}}
```

**不开 `stubs` 几乎必然立刻崩。** 原因：快照里只有镜像本身，没有它链接的 DLL。
`call qword ptr [rip+IAT]` 会跳到未映射地址，第一步就 fault。

`stubs: true` 把每个 IAT 槽改写成 `mov eax, imm; ret` 的桩，函数就能跑完。
每个桩的返回值可以自己定：

```jsonc
{"tool": "emu_stubs", "arguments": {"key": "t", "returns": "RegQueryValueExW=0,Sleep=0"}}
```

`trace: true` 打开执行记录（每条指令一次回调，慢，但 `emu_coverage` 需要它）。

## 第 2 步：调用

```jsonc
{"tool": "emu_call", "arguments": {"key": "t", "va": "0x140001A00", "args": "0x1234,0x50000"}}
```

x64 MS 调用约定，参数依次 `rcx, rdx, r8, r9`，多的压栈。
返回 `{retval, reason, return_address}`。

`reason` 的取值：

| reason | 含义 |
|---|---|
| `returned` | 正常 `ret` 到陷阱页，`retval` 有效 |
| `reached_target` | 跑到了 `run_until` 的目标地址 |
| `step_budget` | 步数用尽（可能是死循环或慢函数） |
| `fault: unmapped read_unmapped at 0x... (rip 0x...)` | **崩了，而且告诉你在哪崩** |

**fault 的 reason 会直接给出地址和 rip**，这比"返回 0 然后你猜"有用得多。

## 第 3 步：判断走了哪条分支 —— 这一步最值钱

```jsonc
{"tool": "emu_coverage", "arguments": {"key": "t"}}
```

```json
{"va": "0x140001a42", "hits": 1,
 "successors": [{"va": "0x140001a48", "hits": 1}, {"va": "0x140001a60", "hits": 0}]}
```

`forks` = **每个有两个以上后继的地址 = 实际做过的分支决策**。

- `successors[].hits` 全给出来 → 哪个分支走了、走了几次，一目了然
- 只走了一条 → 那个条件是真是假，不用推断
- `hits` 大于 1 → 循环体，能看迭代次数

这是**"校验过没过""switch 走了哪一支""解密走了哪条路径"的直接答案**，不需要读反汇编猜。

配合：

```jsonc
{"tool": "emu_reached", "arguments": {"key": "t", "addresses": "0x140001a48,0x140001a60"}}
```

给定地址表，分成到过 / 没到过。适合确认"某个处理函数根本没被调用"。

## 第 4 步：看它跟谁说话

```jsonc
{"tool": "emu_calls", "arguments": {"key": "t", "limit": 50}}
```

每个桩命中都记录 `{api, args}`。`RegQueryValueExW` 的第二个参数是键名、
`CreateFileW` 的第一个是路径——**参数全在，不用在反汇编里追构造过程。**

`emu_stub_list` 看当前每个桩会返回什么。

## 第 5 步：定位崩溃

```jsonc
{"tool": "emu_faults", "arguments": {"key": "t"}}
```

```json
{"kind": "unmapped", "access": "read_unmapped", "address": "0xdead0010",
 "size": 4, "rip": "0x7ff600001030"}
```

读三个信息：

1. **`address`** — 野指针。`0xdead0010` 说明基址是 `0xdead0000`，`+0x10` 是字段偏移
2. **`rip`** — 哪条指令干的。去 `disassemble` 看这条
3. **`size`** — 读宽度，能反推字段类型

常见成因：
- 参数是指针但你没给有效内存 → `emu_write` 造一块
- 全局对象没初始化 → 先 `emu_call` 初始化函数
- 真的就是这个 bug → 这就是结论

## 第 6 步：假设检验 —— 不改二进制验证"如果…会怎样"

```jsonc
// 如果 RegQueryValueEx 返回成功呢？
{"tool": "emu_stubs", "arguments": {"key": "t", "returns": "RegQueryValueExW=0"}}
{"tool": "emu_call", "arguments": {"key": "t", "va": "0x140001A00", "args": "0x1234,0"}}
{"tool": "emu_coverage", "arguments": {"key": "t"}}
```

对比前后 `forks` 的变化：分支翻了 → 确认这个 API 是校验关键点。
**不写磁盘、不改目标内存、不重启** 就能做这个判断，这是模拟器最大的用处。

同样的手法验证：
- `GetTickCount` 返回大值 → 试用期是否到期
- `CryptDecrypt` 返回 1 + 输出缓冲塞数据 → 解密分支是否走通
- 某个 `cmp` 一侧改成想要的值 → 分支是否翻转

## 第 7 步：造内存

```jsonc
{"tool": "emu_write", "arguments": {"key": "t", "va": "0x50000000", "data": "<hex>"}}
{"tool": "emu_read", "arguments": {"key": "t", "va": "0x50000000", "size": 64}}
{"tool": "emu_regs", "arguments": {"key": "t", "set": "rcx=0x50000000"}}
{"tool": "emu_watch", "arguments": {"key": "t", "va": "0x50000000", "size": 8, "kind": "write"}}
{"tool": "emu_events", "arguments": {"key": "t"}}
```

**`emu_watch` 是唯一能回答「哪条指令写了这个值」的手段。** DMA 侧做不到（`trace_changes`
只能告诉你什么变了），这里是快照，有单步、有 rip。这是这套工具相对纯 DMA 的关键补位。

## 单步与断点（快照里才有）

```jsonc
{"tool": "emu_step", "arguments": {"key": "t", "count": 10}}
{"tool": "emu_run", "arguments": {"key": "t", "until": "0x140001A60", "max_steps": 5000}}
{"tool": "emu_regs", "arguments": {"key": "t"}}
```

只在**已经缩小到具体函数**之后用。全程序单步是浪费时间。

## 什么时候模拟器帮不上

| 情况 | 原因 |
|---|---|
| 依赖真实内核/驱动行为 | 快照里没有 |
| 依赖多线程竞态 | 单线程模型 |
| 大量未映射的外部数据 | 要手工造，成本高 |
| 自我修改代码 | unicorn 能跑但 `emu_coverage` 会跟不上 |
| 反虚拟机检测 | 可以 `emu_regs` 改 CPUID 结果，但很费劲 |
| 长时间运行（> 百万步） | 太慢，改用活体采样 |

## 收尾

```jsonc
{"tool": "emu_close", "arguments": {"key": "t"}}
```

**必须关。** unicorn 每个实例持有原生引擎，一堆不关的模拟器会把内存吃光，
而且延迟释放会在下一次 `mem_map` 时炸掉。

## 常见坑

| 现象 | 原因 |
|---|---|
| 立刻 `fault at 0x0` | 没开 `stubs` |
| `retval` 是 0 但应该非 0 | 桩的默认返回值就是 0，用 `emu_stubs(returns=...)` 指定 |
| `coverage.forks` 为空 | 没开 `trace: true`，或函数真的没有分支 |
| `steps` 是 0 | 同上，追踪没开 |
| 结果永远一样 | 前置初始化没跑；先模拟 init 函数 |
| 模拟结果和真机不一样 | 快照是某一刻的静态副本，全局状态已经变了 |
