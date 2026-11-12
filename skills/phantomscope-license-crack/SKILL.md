---
name: phantomscope-license-crack
description: 用 phantomscope 定位并绕过软件许可校验：triage 查壳 → 定位校验函数（字符串/API/立即数）→ 用 emu_coverage 的 forks 判断走哪支 → 内存试改或静态打补丁 → 跨版本用 diff_images 找同一逻辑。当用户说"破解软件""绕过注册验证""去试用限制""找校验函数""打补丁"时触发。
---

# 软件许可校验定位与绕过

核心方法：**不要读整个程序，先让程序告诉你校验在哪。**

## 第 1 步：triage，先看有没有壳

```jsonc
{"tool": "load_file", "arguments": {"path": "target.exe", "key": "t"}}
{"tool": "packing_report", "arguments": {"key": "t"}}
```

`score` 高 + `verdict` 指向加密节 → 有壳。有壳时静态分析全是噪声，两条路：

1. **活体脱壳**（推荐）：让程序自己跑起来解壳，然后 `export_module` 把解壳后的镜像落盘
2. 硬脱壳：`entry_point` → 找 OEP → 重建 IAT（工作量大，先试第 1 条）

```jsonc
// 活体路线
{"tool": "attach", "arguments": {"process": "target.exe"}}
{"tool": "export_module", "arguments": {"module": "target.exe", "path": "unpacked.exe"}}
{"tool": "load_file", "arguments": {"path": "unpacked.exe", "key": "u"}}
```

`export_module` 会 demap，输出的文件 IDA/Ghidra 直接能开。这是脱壳最后也最容易翻车的一步，
不做 demap 的 dump 文件所有工具都拒收。

## 第 2 步：定位校验，三个入口

### 入口 A：字符串

```jsonc
{"tool": "string_xrefs", "arguments": {"key": "t", "contains": "licen"}}
{"tool": "string_xrefs", "arguments": {"key": "t", "contains": "expired"}}
{"tool": "string_xrefs", "arguments": {"key": "t", "contains": "invalid"}}
```

`string_xrefs` 直接给出**引用这个字符串的代码地址**——一个"Licence expired"只被一处引用，
那就是校验函数，比读反汇编快一个数量级。

### 入口 B：API

```jsonc
{"tool": "find_api", "arguments": {"key": "t", "needle": "RegQueryValueEx"}}
{"tool": "find_api", "arguments": {"key": "t", "needle": "GetTickCount"}}   // 时间/试用
{"tool": "find_api", "arguments": {"key": "t", "needle": "Crypt"}}          // 密钥校验
{"tool": "api_calls", "arguments": {"key": "t", "va": "0x140001A00"}}       // 某个函数跟谁说话
```

`api_calls` 是**最快的函数分类器**：一个函数如果同时调 `RegOpenKey` + `CryptDecrypt` +
`MessageBoxW`，它几乎肯定是许可校验。

### 入口 C：立即数

```jsonc
{"tool": "search_immediates", "arguments": {"key": "t", "value": "30"}}      // 30 天试用
{"tool": "search_immediates", "arguments": {"key": "t", "value": "0x5265"}}  // 'Re'
```

## 第 3 步：读懂校验逻辑

```jsonc
{"tool": "decompile", "arguments": {"key": "t", "va": "0x140001A00"}}
```

`confidence` 和 `notes` 会说明降级原因。**每一行都带原始指令**，所以拿不准就去
`disassemble` 对一遍——伪 C 是提高阅读速度的工具，不是事实来源。

## 第 4 步：让模拟器告诉你走哪支

这是最关键的一步，比断点快：

```jsonc
{"tool": "emu_create", "arguments": {"key": "t", "stubs": true, "trace": true}}
{"tool": "emu_call", "arguments": {"key": "t", "va": "0x140001A00", "args": "0x1234,0"}}
{"tool": "emu_coverage", "arguments": {"key": "t"}}
```

`forks` 输出形如：

```json
{"va": "0x140001a42", "hits": 1,
 "successors": [{"va": "0x140001a48", "hits": 1}, {"va": "0x140001a60", "hits": 0}]}
```

→ 在 `0x140001a42` 处只走了 `0x140001a48`（通过分支），`0x140001a60` 一次没走。
**这就是"校验过没过"的直接答案，不需要任何推断。**

配合：

```jsonc
{"tool": "emu_reached", "arguments": {"key": "t", "addresses": "0x140001a48,0x140001a60"}}
{"tool": "emu_faults", "arguments": {"key": "t"}}      // 崩在哪个解引用
{"tool": "emu_calls", "arguments": {"key": "t"}}       // 实际调了哪些 API、参数是什么
```

`emu_calls` 会告诉你 `RegQueryValueExW` 查的是哪个键名——一次调用全给出来，
不用在反汇编里追参数构造。

### 关键技巧：驱动返回值走另一条路

不用改二进制就能验证"如果这个 API 返回成功会怎样"：

```jsonc
{"tool": "emu_stubs", "arguments": {"key": "t", "returns": "RegQueryValueExW=0"}}
{"tool": "emu_call", "arguments": {"key": "t", "va": "0x140001A00", "args": "0x1234,0"}}
{"tool": "emu_coverage", "arguments": {"key": "t"}}
```

返回 0（ERROR_SUCCESS）后 `forks` 变了 → 确认这就是校验的关键 API。
**这是不修改磁盘文件、不写目标内存就能做的假设检验。**

## 第 5 步：改

### 内存试改（先验证再落盘）

```jsonc
{"tool": "write", "arguments": {"va": "0x7FF6A2B41042", "data": "EB", "note": "flip jne->jmp"}}
// 立刻测试行为
{"tool": "patch_list", "arguments": {}}
{"tool": "patch_restore", "arguments": {"all": true}}      // 不满意全撤
```

试改的价值：**改错不会毁掉文件，一个调用就还原。**

### 静态补丁

```jsonc
{"tool": "patch_apply", "arguments": {"key": "t", "va": "0x140001A42", "bytes": "EB 1C",
  "note": "skip the failure branch"}}
{"tool": "static_patch_list", "arguments": {}}
{"tool": "save_image", "arguments": {"key": "t", "path": "target_patched.exe"}}
{"tool": "static_patch_restore", "arguments": {"key": "t", "all": true}}   // 不满意全撤
```

`patch_apply` 改的是**镜像本身**（`disassemble` 看到的地址就是补丁地址），
并且会丢弃该镜像的函数索引缓存，所以 `decompile` / `disassemble` 立刻反映补丁后的字节。
`save_image` 再 demap 成文件，IDA 和 pefile 都能开。

补丁前记下原字节。`0x74`(je) → `0xEB`(jmp) 跳过失败分支；`0x75`(jne) → `EB` 同理；
把 `test eax,eax` 后的条件跳转直接 NOP 掉也行，但**NOP 会改变后续指令对齐假设**，优先跳转改写。

## 第 6 步：跨版本复现

版本一更新，地址全变。别重新找——对齐：

```jsonc
{"tool": "diff_images", "arguments": {"left": "old", "right": "new", "min_similarity": 0.6}}
{"tool": "match_functions", "arguments": {"left": "old", "right": "new"}}
{"tool": "fingerprint", "arguments": {"key": "old", "va": "0x140001A00"}}
```

| `diff_images` 结果 | 含义 |
|---|---|
| `identical` | 校验函数没动，偏移直接换算 |
| `similar` | 逻辑改了，重新 `decompile` 对照 |
| `removed` | 校验被删除或挪走 |
| `added` | 新校验，重新走第 2 步 |

`fingerprint` 的归一化哈希跨构建稳定，是判断"是不是同一个函数"最可靠的手段。

## 常见坑

| 现象 | 原因 |
|---|---|
| `emu_call` 立刻 fault at 0x0 | 少了 `stubs: true` |
| `emu_call` 正常返回但结果永远不变 | 前置初始化没跑，先 `emu_call` 初始化函数 |
| `forks` 为空 | 没开 `trace: true`，或函数没有分支 |
| 补丁后程序不启动 | 改了指令长度；跳转偏移要重算 |
| 修补后仍失败 | 有第二处校验（常见：启动时 + 定时心跳），`find_api` 找 `SetTimer`/`CreateThread` |
| 字符串搜不到 | 字符串加密或运行时解密 → `scan_strings` 扫活体内存 |

## 边界

- **VMProtect / Themida 级别虚拟化**：静态几乎无意义，靠模拟器硬跟，工作量按天算
- **服务端校验**：本地改成什么样都没用，这是协议问题
- **硬件狗 / TPM 绑定**：需要硬件在环，DMA 帮不上
