---
name: phantomscope-unpack-dump
description: 用 phantomscope(DMA) 从活体进程脱壳并 dump 出可分析的镜像：packing_report 判断壳 → 等目标自己解壳 → export_module 落盘成 IDA 能开的 PE（含 demap）→ capture_module 送进静态引擎做伪C/字符串/加密常量分析。当用户说"脱壳""dump 内存镜像""样本加壳了""提取解壳后的代码"时触发。
---

# 活体脱壳与镜像 dump

核心思路：**不写脱壳机，让程序自己脱。**

DMA 的优势在这里最明显——它在旁边看，程序看不见它，所以反调试/反虚拟机完全不触发。

## 第 1 步：先判断到底有没有壳

```jsonc
{"tool": "load_file", "arguments": {"path": "sample.exe", "key": "s"}}
{"tool": "packing_report", "arguments": {"key": "s"}}
```

看几个具体信号，不要只看总分：

| 信号 | 含义 |
|---|---|
| 节区熵 > 7.0 | 压缩或加密的载荷 |
| `writable + executable` 节 | 运行时会自我修改 |
| 导入表极短（个位数） | 正常程序不会这样，是壳的 loader |
| `entry_point` 不在第一个可执行节 | 典型壳 |
| TLS 回调存在 | 常见于先于入口点执行的反调试 |
| 有 overlay 且很大 | 壳把原始文件塞在末尾 |

`score >= 6` 且命中上面两三条 → 走活体脱壳。`score <= 3` → 直接静态分析，别浪费时间。

## 第 2 步：活体脱壳

```jsonc
{"tool": "session_open", "arguments": {"device": "fpga"}}
{"tool": "attach", "arguments": {"process": "sample.exe"}}
```

### 怎么知道壳已经解完了

这是整件事的关键，没有断点可用，所以靠**证据**，不靠猜：

```jsonc
// A. 内存里的代码比磁盘上多得多
{"tool": "modules", "arguments": {}}
{"tool": "regions", "arguments": {}}
```

- 出现 `rwx` 区域且大小接近原文件 → 解壳后的镜像
- 模块 `size` 比磁盘 PE 大很多 → 运行时扩展过

```jsonc
// B. 入口点附近的字节已经不像壳了
{"tool": "read", "arguments": {"va": "<entry>", "size": 64, "dump": true}}
```

壳的入口是一片无意义的高熵字节；解壳后是标准函数序言（`sub rsp,` / `push rbp` / `mov [rsp+..]`）。

```jsonc
// C. 静态侧看它有没有"长出来"
{"tool": "capture_module", "arguments": {"module": "sample.exe", "key": "probe"}}
{"tool": "packing_report", "arguments": {"key": "probe"}}
{"tool": "functions", "arguments": {"key": "probe", "limit": 20}}
{"tool": "imports", "arguments": {"key": "probe"}}
```

**判据：`packing_report` 分数显著下降 + `imports` 从个位数涨到几十个 + `functions` 发现了成百上千个函数。**
三条同时满足，壳就解完了。隔几秒重复一次，直到稳定。

> 有些壳会在解完后擦掉痕迹，或者延迟解密。多采样几次，看 `functions` 数量变化趋势。

## 第 3 步：落盘

```jsonc
{"tool": "export_module", "arguments": {
  "module": "sample.exe", "path": "C:\\work\\unpacked.exe"}}
```

**这一步不做 demap，dump 出来的文件 IDA 会拒收。** `export_module` 已经处理了：
头部保留，每个节从虚拟地址搬到声明的 raw 偏移。

输出里 `layout: "file"` 就是可加载的。`raw: true` 保留原样（要字节精确副本时用）。

验证：

```jsonc
{"tool": "load_file", "arguments": {"path": "C:\\work\\unpacked.exe", "key": "u"}}
{"tool": "packing_report", "arguments": {"key": "u"}}
{"tool": "functions", "arguments": {"key": "u", "limit": 20}}
```

能加载、函数数量合理 → 成功。

## 第 4 步：在解壳后的镜像上做正经分析

```jsonc
{"tool": "decompile", "arguments": {"key": "u", "va": "0x140001000"}}
{"tool": "api_calls", "arguments": {"key": "u"}}
{"tool": "strings", "arguments": {"key": "u", "contains": "http"}}
{"tool": "crypto_constants", "arguments": {"key": "u"}}
{"tool": "rtti", "arguments": {"key": "u"}}
```

```jsonc
// 运行时才出现的字符串，磁盘上没有
{"tool": "scan_strings", "arguments": {"needle": "", "min_length": 8, "encoding": "both"}}
```

`scan_strings` 是脱壳场景的重要补充：**很多壳连字符串都是在解壳后才构造的**，
`strings` 扫磁盘镜像一个都看不到，扫活体内存全都在。

## 什么时候不该活体脱壳

| 情况 | 替代 |
|---|---|
| 没有目标机 / 不能运行 | 静态硬脱壳，手动找 OEP 重建 IAT（工作量大） |
| 反 DMA（检测 PCIe 设备） | 这条路断了，走静态 |
| 壳只在特定条件下解（要联网/要授权） | 先满足条件再 dump |
| .NET / Java / Electron | 不需要这套，用 dnSpy / jadx / asar |

## 边界

- **IAT 可能没重建**：脱壳后 `imports` 若仍很少，说明壳把 IAT 加密了，运行时才填。
  `export_module` 拿到的是**已填好的 IAT**，这正是活体 dump 比静态脱壳强的核心原因。
- **重定位**：如果模块被重定位过（`base` 不是 preferred），dump 出来的文件里的绝对地址是错的。
  用 `image_summary` 看 `relocations`，需要时在 IDA 里设对应 base。
- **多模块**：主模块 + 注入的 DLL 要分别 dump，别指望一个文件装下所有东西。

## 常见坑

| 现象 | 原因 |
|---|---|
| dump 的文件 IDA 报 invalid | 忘了 demap（用 `raw: true` 了） |
| dump 出来函数数量没变 | 壳还没解完，回到第 2 步多等一会 |
| `imports` 仍然很少 | IAT 还没填完，或壳用 syscall 直接调用 |
| 文件能加载但反汇编是乱码 | 壳留下了垃圾字节，或 dump 在解壳中途 |
| 模块 size 是 0 | 后端拿不到模块大小，用 `regions` 手工确定范围再 `read` |
