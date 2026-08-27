# compareELF

`compareELF` compares ELF artifacts built from the same source by Make and Bazel and writes a compact semantic-difference summary as JSON. It does not require byte-for-byte equality and does not compare machine instructions inside matched functions.

## Files

`elfcompare.py` is the command-line entry point and contains the native ELF parser.  
`elfcompare_tools.py` runs supporting tools, performs semantic comparisons, and builds the summary JSON.

## Requirements

- Python 3
- GNU `readelf`
- `abidiff` for shared-library function-signature and type-layout checks

## Usage

The first argument is the Make artifact and the second is the Bazel artifact:

```bash
python3 elfcompare.py path/to/make.elf path/to/bazel.elf
```

Save the summary to a file:

```bash
python3 elfcompare.py path/to/make.elf path/to/bazel.elf > summary.json
```

## Summary JSON

When no semantic difference is found:

```json
{
  "make": "/abs/path/make.elf",
  "bazel": "/abs/path/bazel.elf",
  "findings": []
}
```

When differences are found:

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

### Fields

| Field | Meaning |
|---|---|
| `make` | Absolute path of the Make artifact |
| `bazel` | Absolute path of the Bazel artifact |
| `compiler_version_mismatch` | Optional `.comment` compiler/assembler strings; explanatory only and not a semantic failure by itself |
| `findings` | Confirmed semantic differences |
| `category` | Difference category |
| `section` | Primary ELF evidence location; the dynamic table is reported as `.dynamic` |
| `name` | Changed property, symbol, function, or callback |
| `left` | Make-side value |
| `right` | Bazel-side value |
| `detail` | Optional explanation |

`left` always means Make and `right` always means Bazel.

## Categories

| Category | Meaning |
|---|---|
| `elf` | Base ELF contract changed, such as Class, Data, Machine, Type, OS/ABI, ABI Version, or Flags |
| `runtime` | Loader or TLS runtime contract changed, such as the program interpreter or TLS properties |
| `dependency` | `.dynamic` dependencies, SONAME, RPATH, RUNPATH, or dynamic flags changed |
| `import-added` | Bazel adds a dynamic imported symbol and therefore a runtime symbol dependency |
| `import-removed` | A Make dynamic import is absent from Bazel; changes involving `*_chk` or `__stack_chk_fail` remain import findings and are not duplicated as security findings |
| `import-changed` | Type, binding, visibility, or versioned identity of a dynamic import changed |
| `export-added` | Bazel adds a non-WEAK dynamic export |
| `export-removed` | A dynamic export provided by Make is absent from Bazel |
| `export-changed` | Type, binding, visibility, definition state, or object size of a dynamic export changed |
| `runtime-version` | Bazel raises or adds a runtime symbol-version requirement, for example from `GLIBC_2.17` to `GLIBC_2.38` |
| `function-added` | An ordinary non-WEAK function identifiable by `readelf -sW` exists only in Bazel |
| `function-removed` | An ordinary function identifiable by `readelf -sW` exists only in Make |
| `startup-callback` | Callback count, identity, or order differs in `.preinit_array`, `.init_array`, or `.fini_array` |
| `runtime-data` | Runtime data included in semantic comparison differs |
| `security` | A direct hardening property regressed or changed ambiguously, such as BIND_NOW, GNU_STACK, RELRO, IBT, SHSTK, BTI, or PAC |
| `abi` | `abidiff` reports a function-signature or structure/class layout change; pure export additions/removals are not duplicated here |

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | Completed checks found no semantic difference |
| `1` | A semantic difference was found |
| `2` | An input cannot be read, is invalid, or is not a supported ELF |
| `3` | A required tool failed or evidence is insufficient, including asymmetric stripping |

CI should reject both exit code `1` and exit code `3`.
