---
name: phantomscope-live-struct
description: 用 phantomscope(DMA) 在不暂停目标的前提下把内存还原成结构体和容器：read_object/infer_struct 推字段布局、detect_container/expand_container 展开 vector/TArray/string、read_array 遍历实体表、trace_value 区分常量与活状态。当用户要"还原结构体""这个对象是什么""读实体列表""vector 怎么展开""内存里长什么样"时触发。
---

# 活体内存还原成结构

这套流程的前提：**目标不能停。** 没有断点、没有单步、没有寄存器上下文。
所有结论都来自「读到的值 + 多次采样的一致性 + 指针是否落在已映射区域」。

## 第 1 步：先看形状

```jsonc
{"tool": "attach", "arguments": {"process": "game.exe"}}
{"tool": "read_object", "arguments": {"va": "0x21A00000120", "size": 128}}
```

返回三样东西，分别回答不同问题：

| 字段 | 用途 |
|---|---|
| `hexdump` | 眼睛看字节 |
| `strings` | **全缓冲区可打印串带偏移**（`ascii` 遇 0 就断，结构中间的字符串只有这里能看到） |
| `qwords[]` | 每个 qword 是否 `pointer_ok`，指向哪个模块（`points_to` / `target_module`） |

**`pointer_ok: true` 的 qword 是结构体里最容易确认的锚点**——一个值落在已映射区域且对齐，
它是指针的概率远高于它是整数。

想直接解码已知布局：

```jsonc
{"tool": "read_object", "arguments": {
  "va": "0x21A00000120", "size": 64,
  "fields": "0x0:int32,0x4:int32,0x8:float,0x10:char[16],0x20:pointer"}}
```

`char[n]` 给字符串，`hex[n]` 给原始字节。

## 第 2 步：推布局，要多个样本

```jsonc
{"tool": "infer_struct", "arguments": {
  "va": "0x21B00000000", "count": 8, "stride": 0x20, "align": 4}}
```

**`count=1` 几乎没有价值。** 单个样本无法区分「指针」和「刚好在这个范围的整数」。

判定规则（工具已经实现，但你要读懂它的输出）：

| 观察 | 推断 | 可信度 |
|---|---|---|
| 每次都是已映射地址 | `pointer` | 高 |
| 高 32 位恒为 0 | `int32` | 高 |
| 每次都是 0 | `zero`（padding / 未使用） | 高 |
| 值域合理且能读成 float | `float` | 中（看 `alternatives`） |
| 在样本间变化 | `varies: true` → 每实例数据 | — |
| 样本间恒定 | 共享常量 / 静态数据 | — |

**`alternatives` 一定要看。** `int32` 后面可能挂着 `float 1.5` 或
`pointer (qword at 0x18 spans ...)`——后者是 `align=4` 时漏掉指针的典型情况，
切到 `align=8` 重跑。

`c_struct` 直接给可粘贴的 C 声明。**它标注了是启发式结果**，别当成 ground truth。

### stride 从哪来

不知道 stride 时，从容器里拿（下一步），或者：

```jsonc
{"tool": "read_array", "arguments": {"base": "<第一个元素>", "stride": 0x20, "count": 8}}
```

试几个常见 stride（`0x10` / `0x18` / `0x20` / `0x28` / `0x30`），看哪个让第二列出现合理值
（连续 id、递增指针）。**能整除且字段对齐合理的那个才对。**

## 第 3 步：容器

```jsonc
{"tool": "detect_container", "arguments": {"va": "0x21A00000180"}}
```

返回的是**假设列表，每个都带验证证据**，不是结论：

| `kind` | 布局 | 怎么确认 |
|---|---|---|
| `std::vector<T>` | `{begin, end, capacity}` | 三个都映射，`begin ≤ end ≤ capacity` |
| `TArray<T>` | `{data, count(int32), capacity(int32)}` | 后两个高位为 0 且 `count ≤ capacity` |
| `std::string`（SSO） | 16 字节内联 + size@0x10 + cap@0x18 | length ≤ 16 且字节可打印 |
| `std::string`（堆） | 指针 + size@0x10 + cap@0x18 | 指针映射且内容可打印 |
| `{ptr, count, capacity}` | 裸容器 | 兜底，`confidence: weak` |

**关键看 `element_size_source`：**

- `explicit` — 你给的，最可靠
- `pointer_rhythm` — 从元素内部的指针节奏推出来的（`int,int,int,ptr` 重复 → 0x20），**这是真信号**
- `alignment` — 只是能整除的推测，**可能是错的**

`counts` 列出所有候选大小对应的数量。100 个元素还是 400 个，看这里。

展开：

```jsonc
{"tool": "expand_container", "arguments": {
  "va": "0x21A00000180", "fields": "0x0:int32,0x4:int32,0x8:char[12],0x18:pointer"}}
```

一步拿回所有元素。这就是实体列表的常规读法。

## 第 4 步：数组和指针表

```jsonc
// 连续对象
{"tool": "read_array", "arguments": {"base": "0x21B00000000", "stride": 0x20, "count": 16,
  "fields": "0x0:int32,0x8:char[12]"}}

// 指针数组（Entity**）——游戏管理器几乎都是这个形状
{"tool": "read_array", "arguments": {"base": "0x21A000001C0", "stride": 8, "count": 16,
  "follow": true, "object_size": 0x20, "fields": "0x0:int32,0x4:int32"}}
```

`follow: true` 会逐个解引用并 dump 目标对象。坏指针**逐条报错不中断**——
一个元素失效不影响其余，这对运行中的目标很重要（对象随时可能被释放）。

## 第 5 步：分清静态和活状态

```jsonc
{"tool": "trace_value", "arguments": {"va": "0x21B00000000", "value_type": "int32", "samples": 20}}
```

| 结果 | 含义 |
|---|---|
| `constant: true` | 不动：配置、共享常量，或**你读错了偏移** |
| 少量离散变化 | 状态机、枚举 |
| 单调递增 | 计时器、帧计数、序列号 |
| 快速抖动 + 值域合理 | 真实数值（坐标、朝向、速度） |

```jsonc
// 一整段一起看，找出哪个字段在动
{"tool": "trace_changes", "arguments": {"va": "0x21A00000100", "size": 256, "samples": 16}}
```

`interpretations` 会把同一段字节读成 `int32` / `uint32` / `float` / `int64` / `double`。
**哪个读数合理，那个字段就是什么类型** —— 这是比 `infer_struct` 更直接的判型方式，因为它在运动。

## 第 6 步：把代码和内存合成一张结构体

前面几步只是在看数据。真正可用的结构体要两边对齐——静态知道**哪些偏移存在**，
动态知道**里面是什么**：

```powershell
phantomscope merge --process target.exe target.exe 0x140001A00 0x21A00000120 \
  --size 0x50 --stride 0x50 --count 8 --align 4
```

```jsonc
{"tool": "live_struct_layout", "arguments": {
  "key": "t", "function": "0x140001A00", "object_va": "0x21A00000120",
  "size": 80, "stride": 80, "count": 8, "align": 4}}
```

输出里每一行都来自两边之一或两边：

| 情况 | 含义 |
|---|---|
| `confirmed_by_code` + `confirmed_by_data` | 代码碰过、数据也读到了 —— **可信** |
| 只在 `code_only_offsets` | 代码碰了但样本里读不到：要么写入早于采样，要么采样的不是这个对象 |
| 只在 `data_only_offsets` | 数据里有、这个函数没碰：真实成员，别的地方在用 |

两个自动判断值得注意：

- **float 胜过访问宽度**。`mov eax, [rcx+0x10]` 看着像 dword 操作，
  但 `10.0f` 不是 `1092616192`。当每次采样都能读成合理 float 时，声明成 `float`
- **相邻 float 合成向量**。三个相隔 4 字节的 float 就是坐标或朝向，
  工具会给出 `float pos_x[3]` 的建议

名字只编码证据（`ptr_` / `text_` / `state_` / `const_`），**不会**凭空叫 `health`——
猜错的字段名会让你停止验证，比 `field_4` 有害得多。

## 完整示例：从地址到可用的结构

```jsonc
// 1. 数值定位
{"tool": "scan_value", "arguments": {"value": "100", "value_type": "int32", "label": "hp"}}
{"tool": "scan_next", "arguments": {"key": "hp", "value": "95"}}
// 2. 看所在对象
{"tool": "read_object", "arguments": {"va": "<命中>", "size": 256}}
// 3. 找同类对象推断布局
{"tool": "detect_container", "arguments": {"va": "0x21A00000180"}}
{"tool": "expand_container", "arguments": {"va": "0x21A00000180", "element_size": 0x20}}
{"tool": "infer_struct", "arguments": {"va": "<第一个元素>", "stride": 0x20, "count": 8, "align": 8}}
// 4. 固化：链 + 偏移
{"tool": "pointer_scan", "arguments": {"target": "<hp 地址>", "module": "game.exe", "max_depth": 3}}
{"tool": "resolve_pointer_chain", "arguments": {"base": "game.exe+0x2A1B3C0",
  "offsets": "0x10,0x38,0x8", "value_type": "int32"}}
```

最后拿到 `template` 就是可复用的偏移表。

## 常见坑

| 现象 | 原因 |
|---|---|
| `infer_struct` 满是 `int64` | `align` 默认 8；结构体里是 int32 就切 `align=4` |
| `infer_struct` 满是 `zero` | 读的区域是未初始化页，或 stride 错了 |
| `pointer_rhythm` 没命中 | 元素内没有指针；只能靠 `element_size` 显式给 |
| 容器 count 大得离谱 | `element_size` 太小；看 `counts` 比较其他候选 |
| `follow` 大量报错 | 元素已被释放/是空槽；正常，过滤掉坏的就行 |
| `trace_value` 永远 constant | 偏移错，或这个字段只在特定事件更新 |
| 结构看起来"对"但游戏里无效 | 读到的是副本/快照结构，真正生效的在别处 |

## 这套能力的诚实边界

- **不是类型系统**：没有调试符号，一切都是启发式。`confidence` 与 `alternatives` 就是给你的免责声明。
- **非原子**：读多个字段之间目标可能在改，没有快照语义。
- **容器元素大小不可证**：`std::vector<T>` 只存字节跨度，`T` 的大小必须从别处推。
- **C++ 虚表只给地址**：`rtti` 只在 x64 MSVC 布局下工作，加壳/裁剪后基本失效。
