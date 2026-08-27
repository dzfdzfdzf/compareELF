# compareELF

比较同一套源码分别通过 Make 和 Bazel 构建得到的两个 ELF，输出精简的语义差异 summary JSON。

工具只判断约定的 ELF 运行契约、符号、函数清单、启动/退出回调、安全属性和 ABI 是否一致，不要求两个文件字节完全相同，也不比较已配对函数的机器指令。

## 运行要求

- Python 3
- GNU `readelf`
- `abidiff`：比较共享库时用于检查函数签名和类型布局

## 对比命令

第一个参数是 Make 产物，第二个参数是 Bazel 产物：

```bash
python3 elfcompare.py path/to/make.elf path/to/bazel.elf
```

保存 summary：

```bash
python3 elfcompare.py path/to/make.elf path/to/bazel.elf > summary.json
```

## Summary JSON

没有发现语义差异时：

```json
{
  "make": "/abs/path/make.elf",
  "bazel": "/abs/path/bazel.elf",
  "findings": []
}
```

发现语义差异时：

```json
{
  "make": "/abs/path/make.so",
  "bazel": "/abs/path/bazel.so",
  "compiler_version_mismatch": {
    "section": ".comment",
    "make": ["GCC: (GNU) 8.5.0"],
    "bazel": ["GCC: (GNU) 12.2.0"]
  },
  "findings": [
    {
      "category": "dependency",
      "section": ".dynamic",
      "name": "dynamic.needed",
      "left": ["libc.so.6"],
      "right": ["libc.so.6", "libstdc++.so.6"]
    },
    {
      "category": "function-removed",
      "section": ".text",
      "name": "foo",
      "left": "<present>",
      "right": "<missing>",
      "detail": "A Make function is absent from Bazel."
    }
  ]
}
```

字段含义：

| 字段 | 含义 |
|---|---|
| `make` | Make 产物的绝对路径 |
| `bazel` | Bazel 产物的绝对路径 |
| `compiler_version_mismatch` | 可选；两侧 `.comment` 中的编译器/汇编器版本字符串不同，仅用于解释差异，不单独判失败 |
| `findings` | 已确认的语义差异列表 |
| `category` | 差异类型 |
| `section` | 差异的主要 ELF 证据位置；动态表统一写成 `.dynamic` |
| `name` | 发生变化的属性、符号、函数或回调 |
| `left` | Make 侧的值 |
| `right` | Bazel 侧的值 |
| `detail` | 可选的差异说明 |

`left` 永远表示 Make，`right` 永远表示 Bazel。

## Category

| Category | 代表什么 |
|---|---|
| `elf` | ELF 基础格式契约不同，例如 Class、Data、Machine、Type、OS/ABI、ABI Version 或 Flags 不同 |
| `runtime` | loader 或 TLS 运行契约不同，例如 program interpreter 或 TLS 属性不同 |
| `dependency` | `.dynamic` 中的 `DT_NEEDED`、SONAME、RPATH、RUNPATH 或动态 flags 不同 |
| `import-added` | Bazel 新增动态导入符号，即新增了运行时外部符号依赖 |
| `import-removed` | Make 存在的动态导入符号在 Bazel 中消失；`*_chk`、`__stack_chk_fail` 等变化也归在这里，不重复输出 security |
| `import-changed` | 同名动态导入符号的 type、binding、visibility 或版本化身份不同 |
| `export-added` | Bazel 新增非 WEAK 动态导出符号 |
| `export-removed` | Make 对外提供的动态导出符号在 Bazel 中消失 |
| `export-changed` | 同名动态导出符号的 type、binding、visibility、定义状态或对象大小不同 |
| `runtime-version` | Bazel 提高或新增运行时符号版本要求，例如从 `GLIBC_2.17` 提高到 `GLIBC_2.38` |
| `function-added` | `readelf -sW` 能稳定识别的普通非 WEAK 函数只存在于 Bazel |
| `function-removed` | `readelf -sW` 能稳定识别的普通函数只存在于 Make |
| `startup-callback` | `.preinit_array`、`.init_array` 或 `.fini_array` 的回调数量、函数或顺序不同 |
| `runtime-data` | 被工具纳入语义比较的运行时数据内容不同 |
| `security` | 直接安全属性降低或发生不可安全分类的变化，例如 BIND_NOW、GNU_STACK、RELRO、IBT、SHSTK、BTI 或 PAC；不会根据符号名重复推断 security |
| `abi` | `abidiff` 发现同名导出接口的函数签名或结构体/类类型布局不同；单纯 export 增删不重复输出 ABI |

## 退出码

| 退出码 | 含义 |
|---:|---|
| `0` | 已完成的检查没有发现语义差异 |
| `1` | 发现语义差异 |
| `2` | 输入文件无效、无法读取或不是受支持的 ELF |
| `3` | 必需工具缺失、外部工具失败、两侧 strip 状态不一致或证据不足，不能判定一致 |

CI 中退出码 `1` 和 `3` 都不应作为通过。
