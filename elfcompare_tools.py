"""External-tool orchestration for Make-to-Bazel ELF comparisons."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, replace
from enum import Enum
from typing import (
    AbstractSet,
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)


EXIT_CONSISTENT = 0
EXIT_DIFFERENT = 1
EXIT_ERROR = 2
EXIT_INCOMPLETE = 3

PT_INTERP = 3
PT_TLS = 7
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
ET_REL = 1
SHT_NOBITS = 8
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15
SHT_PREINIT_ARRAY = 16
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
EM_386 = 3
EM_X86_64 = 62
EM_AARCH64 = 183
STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_GNU_UNIQUE = 10
STT_FUNC = 2
STT_GNU_IFUNC = 10

INITIALIZATION_RELOCATION_WIDTHS = {
    EM_386: {1: 4, 6: 4, 8: 4, 42: 4},
    EM_X86_64: {1: 8, 6: 8, 8: 8, 37: 8},
    EM_AARCH64: {257: 8, 1025: 8, 1027: 8, 1032: 8},
}

DATA_RELOCATION_WIDTHS = {
    EM_386: {1: 4, 2: 4, 6: 4, 7: 4, 8: 4},
    EM_X86_64: {1: 8, 2: 4, 4: 4, 8: 8, 10: 4, 11: 4},
    EM_AARCH64: {257: 8, 258: 4, 260: 8, 261: 4, 1027: 8},
}

DATA_SECTION_PATTERNS = (
    ".rodata",
    ".rodata.*",
    ".data",
    ".data.*",
    ".sdata",
    ".sdata.*",
    ".bss",
    ".bss.*",
    ".sbss",
    ".sbss.*",
    ".tdata",
    ".tdata.*",
    ".tbss",
    ".tbss.*",
)

OMITTED_REPORT_CATEGORIES = frozenset(
    {
        "data-symbol",
        "function",
        "function-target",
        "function-boundary",
        "unattributed-data",
        "unattributed-relocation",
    }
)

# Internal findings keep precise implementation-oriented categories.  Reports
# expose a smaller vocabulary that describes what changed without leaking the
# parser or ELF table that produced the evidence.
PUBLIC_CATEGORY_NAMES = {
    "symbols-exported-added": "export-added",
    "symbols-exported-removed": "export-removed",
    "symbols-exported-changed": "export-changed",
    "symbols-imported-added": "import-added",
    "symbols-imported-removed": "import-removed",
    "symbols-imported-changed": "import-changed",
    "dynamic": "dependency",
    "version-floor": "runtime-version",
    "initialization-array": "startup-callback",
    "data": "runtime-data",
    "security-weakened": "security",
}

PUBLIC_PASSTHROUGH_CATEGORIES = frozenset(
    {
        "elf",
        "runtime",
        "function-added",
        "function-removed",
        "security",
        "abi",
    }
)

PUBLIC_FINDING_CATEGORIES = (
    frozenset(PUBLIC_CATEGORY_NAMES.values()) | PUBLIC_PASSTHROUGH_CATEGORIES
)

PUBLIC_CATEGORY_SECTIONS = {
    "elf": "<elf-header>",
    "runtime": "<program-headers>",
    "dependency": ".dynamic",
    "import-added": "<dynamic-symbol-table>",
    "import-removed": "<dynamic-symbol-table>",
    "import-changed": "<dynamic-symbol-table>",
    "export-added": "<dynamic-symbol-table>",
    "export-removed": "<dynamic-symbol-table>",
    "export-changed": "<dynamic-symbol-table>",
    "runtime-version": "<version-requirements>",
    "function-added": "<executable-sections>",
    "function-removed": "<executable-sections>",
    "runtime-data": "<runtime-data-sections>",
    "abi": "<abi-type-information>",
}

EvidenceLocation = Union[str, Dict[str, str]]


class ParsedContract(dict):
    """Address-independent ELF contract plus non-semantic source metadata."""

    def __init__(self) -> None:
        super().__init__()
        self.source_sections: Dict[str, str] = {}

HEADER_KEYS = (
    "Class",
    "Data",
    "OS/ABI",
    "ABI Version",
    "Type",
    "Machine",
    "Flags",
)

DYNAMIC_STRING_TAGS = {
    "NEEDED",
    "SONAME",
    "RPATH",
    "RUNPATH",
    "AUDIT",
    "DEPAUDIT",
    "FILTER",
    "AUXILIARY",
}

DYNAMIC_FLAG_TAGS = {
    "FLAGS",
    "FLAGS_1",
    "FEATURE_1",
    "POSFLAG_1",
    "TEXTREL",
    "BIND_NOW",
    "SYMBOLIC",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    path: str
    left: Any
    right: Any
    detail: Optional[str] = None
    section: Optional[EvidenceLocation] = None

    def as_dict(self) -> Dict[str, Any]:
        result = {
            "severity": self.severity,
            "category": self.category,
            "path": self.path,
            "left": self.left,
            "right": self.right,
        }
        if self.detail:
            result["detail"] = self.detail
        if self.section:
            result["section"] = self.section
        return result


@dataclass(frozen=True)
class FindingGroup:
    severity: str
    category: str
    count: int
    examples: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "count": self.count,
            "examples": list(self.examples),
        }

    @classmethod
    def from_dict(cls, item: Dict[str, Any]) -> "FindingGroup":
        return cls(
            severity=str(item["severity"]),
            category=str(item["category"]),
            count=int(item["count"]),
            examples=tuple(str(path) for path in item.get("examples", [])),
        )

    def displayed_examples(self) -> str:
        examples = [
            path if len(path) <= 72 else path[:69] + "..."
            for path in self.examples[:2]
        ]
        return ", ".join(examples)


@dataclass(frozen=True, order=True)
class DynamicSymbol:
    name: str
    symbol_type: str
    binding: str
    visibility: str
    definition: str
    size: Optional[int]

    @classmethod
    def from_contract_item(cls, item: Sequence[Any]) -> "DynamicSymbol":
        return cls(str(item[0]), str(item[1]), str(item[2]), str(item[3]), str(item[4]), item[5])

    def as_tuple(self) -> Tuple[Any, ...]:
        return (
            self.name,
            self.symbol_type,
            self.binding,
            self.visibility,
            self.definition,
            self.size,
        )


class DynamicSymbolChangeKind(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


@dataclass(frozen=True)
class DynamicSymbolChange:
    name: str
    kind: DynamicSymbolChangeKind
    left: Tuple[DynamicSymbol, ...]
    right: Tuple[DynamicSymbol, ...]

    def left_value(self) -> Any:
        return (
            [item.as_tuple() for item in self.left]
            if self.left
            else "<missing>"
        )

    def right_value(self) -> Any:
        return (
            [item.as_tuple() for item in self.right]
            if self.right
            else "<missing>"
        )


@dataclass(frozen=True)
class UnattributedDataSummary:
    normalized_size: int
    printable_strings: Tuple[bytes, ...]
    printable_strings_sha256: str
    opaque_size: int
    opaque_sha256: str

    def as_dict(self, strings_equal: bool) -> Dict[str, Any]:
        return {
            "normalized_size": self.normalized_size,
            "printable_string_count": len(self.printable_strings),
            "printable_strings_sha256": self.printable_strings_sha256,
            "opaque_size": self.opaque_size,
            "opaque_sha256": self.opaque_sha256,
            "printable_strings_equal": strings_equal,
        }


@dataclass(frozen=True)
class _SymbolRange:
    start: int
    end: int
    size: int
    name: str


@dataclass
class _SymbolTargetIndex:
    """Resolve relocation targets without rescanning every ELF symbol."""

    exact_names: Dict[Tuple[Optional[int], int], str]
    ranges: Dict[Optional[int], Tuple[_SymbolRange, ...]]
    starts: Dict[Optional[int], Tuple[int, ...]]
    prefix_max_ends: Dict[Optional[int], Tuple[int, ...]]

    @classmethod
    def build(cls, elf: Any, symbols: Sequence[Any]) -> "_SymbolTargetIndex":
        exact_groups: Dict[Tuple[Optional[int], int], List[Any]] = {}
        range_groups: Dict[
            Optional[int], Dict[Tuple[int, int], List[Any]]
        ] = {}
        for symbol in symbols:
            if (
                not symbol.name
                or symbol.shndx <= 0
                or symbol.shndx >= len(elf.sections)
            ):
                continue
            scope = symbol.shndx if elf.type == ET_REL else None
            exact_groups.setdefault((scope, symbol.value), []).append(symbol)
            if symbol.size:
                range_groups.setdefault(scope, {}).setdefault(
                    (symbol.value, symbol.size), []
                ).append(symbol)

        exact_names = {}
        for key, aliases in exact_groups.items():
            preferred, _ = _preferred_function_aliases(aliases)
            exact_names[key] = min(symbol.name for symbol in preferred)

        frozen_ranges: Dict[Optional[int], Tuple[_SymbolRange, ...]] = {}
        starts: Dict[Optional[int], Tuple[int, ...]] = {}
        prefix_max_ends: Dict[Optional[int], Tuple[int, ...]] = {}
        for scope, groups in range_groups.items():
            items = []
            for (start, size), aliases in groups.items():
                preferred, _ = _preferred_function_aliases(aliases)
                items.append(
                    _SymbolRange(
                        start,
                        start + size,
                        size,
                        min(symbol.name for symbol in preferred),
                    )
                )
            ordered = tuple(
                sorted(items, key=lambda item: (item.start, item.size, item.name))
            )
            maxima: List[int] = []
            maximum = 0
            for item in ordered:
                maximum = max(maximum, item.end)
                maxima.append(maximum)
            frozen_ranges[scope] = ordered
            starts[scope] = tuple(item.start for item in ordered)
            prefix_max_ends[scope] = tuple(maxima)
        return cls(exact_names, frozen_ranges, starts, prefix_max_ends)

    def target(self, scope: Optional[int], address: int) -> Optional[str]:
        exact = self.exact_names.get((scope, address))
        if exact is not None:
            return exact
        ranges = self.ranges.get(scope, ())
        starts = self.starts.get(scope, ())
        prefix_max_ends = self.prefix_max_ends.get(scope, ())
        index = bisect_right(starts, address) - 1
        candidates: List[_SymbolRange] = []
        while index >= 0 and prefix_max_ends[index] > address:
            candidate = ranges[index]
            if candidate.start <= address < candidate.end:
                candidates.append(candidate)
            index -= 1
        if not candidates:
            return None
        target = min(candidates, key=lambda item: (item.size, item.name))
        offset = address - target.start
        suffix = f"+0x{offset:x}" if offset else ""
        return target.name + suffix


class SymbolBinding(str, Enum):
    LOCAL = "LOCAL"
    GLOBAL = "GLOBAL"
    WEAK = "WEAK"
    UNIQUE = "UNIQUE"


_PUBLIC_FUNCTION_BINDINGS = frozenset(
    {SymbolBinding.GLOBAL, SymbolBinding.WEAK, SymbolBinding.UNIQUE}
)


@dataclass(frozen=True)
class FunctionLocation:
    section: Optional[str]
    address: int


@dataclass(frozen=True, order=True)
class FunctionIdentity:
    scope: str
    aliases: Tuple[str, ...]
    fallback: str
    occurrence: int = 1

    def label(self) -> str:
        base = self.fallback or ", ".join(self.aliases)
        return base if self.occurrence == 1 else f"{base}#{self.occurrence}"


@dataclass(frozen=True)
class FunctionSymbolMetadata:
    size: int
    binding: SymbolBinding
    boundary_reliable: bool
    names: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "binding", SymbolBinding(self.binding))


@dataclass
class FunctionBlock:
    name: str
    start: int
    instructions: List[str]
    binding: Optional[SymbolBinding]
    boundary_reliable: bool
    degraded_name: bool
    size: int = 0
    aliases: Tuple[str, ...] = ()
    section: Optional[str] = None


@dataclass(frozen=True)
class InitializationArrayEntry:
    identity: Optional[Tuple[str, ...]]
    raw_value: int
    relocation: Optional[Dict[str, Any]]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "identity": list(self.identity) if self.identity is not None else None,
            "raw": f"0x{self.raw_value:x}",
            "relocation": self.relocation,
        }


@dataclass
class CommandResult:
    name: str
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    def as_dict(self, output_file: Optional[str] = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "name": self.name,
            "command": self.command,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
        }
        if output_file:
            result["output_file"] = output_file
        if self.stderr.strip():
            result["stderr_excerpt"] = self.stderr.strip()[:1000]
        return result


class ToolRunner:
    def __init__(self, timeout: int = 300):
        self.timeout = timeout

    def run(self, name: str, command: Sequence[str]) -> CommandResult:
        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        try:
            completed = subprocess.run(
                list(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="backslashreplace",
                timeout=self.timeout,
                env=environment,
                check=False,
            )
            return CommandResult(
                name,
                list(command),
                completed.returncode,
                completed.stdout,
                completed.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode(errors="backslashreplace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode(errors="backslashreplace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return CommandResult(name, list(command), 124, stdout, stderr, True)
        except OSError as exc:
            return CommandResult(name, list(command), 127, "", str(exc))


def resolve_command(explicit: Optional[str], fallback: str) -> Optional[List[str]]:
    words = shlex.split(explicit) if explicit else [fallback]
    if not words:
        return None
    executable = shutil.which(words[0])
    if executable is None:
        return None
    return [executable] + words[1:]


def discover_tools(args: Any) -> Dict[str, Optional[List[str]]]:
    prefix = args.tool_prefix or ""
    elf_diff = resolve_command(args.elf_diff, "elf_diff")
    if elf_diff is None and not args.elf_diff and importlib.util.find_spec("elf_diff"):
        elf_diff = [sys.executable, "-m", "elf_diff"]
    return {
        "readelf": resolve_command(args.readelf, prefix + "readelf"),
        "eu-elfcmp": resolve_command(args.eu_elfcmp, "eu-elfcmp"),
        "abidiff": resolve_command(args.abidiff, "abidiff"),
        "elf_diff": elf_diff,
        "diffoscope": resolve_command(args.diffoscope, "diffoscope"),
    }


def _normalize_space(value: str) -> str:
    return " ".join(value.strip().split())


def _dynamic_value(value: str) -> str:
    bracketed = re.search(r"\[([^]]*)\]", value)
    if bracketed:
        return bracketed.group(1)
    value = re.sub(r"^.*?Flags:\s*", "", value)
    return _normalize_space(value)


@dataclass(frozen=True)
class _ReadelfSymbolRow:
    table: str
    value: int
    size: int
    symbol_type: str
    binding: str
    visibility: str
    ndx: str
    name: str


def _readelf_symbol_rows(output: str) -> List[_ReadelfSymbolRow]:
    """Parse symbol rows shared by dynamic-contract and function checks."""

    rows: List[_ReadelfSymbolRow] = []
    current_table: Optional[str] = None
    pattern = re.compile(
        r"\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+"
        r"(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$"
    )
    for line in output.splitlines():
        table = re.match(
            r"Symbol table ['\"]([^'\"]+)['\"]", line.strip()
        )
        if table:
            current_table = table.group(1)
            continue
        if current_table is None:
            continue
        match = pattern.match(line)
        if not match:
            continue
        value, size, symbol_type, binding, visibility, ndx, name = (
            match.groups()
        )
        rows.append(
            _ReadelfSymbolRow(
                table=current_table,
                value=int(value, 16),
                size=int(size),
                symbol_type=symbol_type,
                binding=binding,
                visibility=visibility,
                ndx=ndx,
                name=re.sub(r"\s+\(\d+\)$", "", name).strip(),
            )
        )
    return rows


def parse_readelf_contract(
    output: str,
    dynamic_symbol_sections: Optional[AbstractSet[str]] = None,
) -> ParsedContract:
    """Extract address-independent runtime and dynamic-symbol properties."""
    contract = ParsedContract()
    source_sections = contract.source_sections
    lines = output.splitlines()
    dynamic_values: Dict[str, List[str]] = {}
    imported: List[Tuple[Any, ...]] = []
    exported: List[Tuple[Any, ...]] = []
    version_provider: Optional[str] = None
    version_requirements: Dict[str, List[str]] = {}
    in_version_needs = False
    gnu_property_features: Dict[str, bool] = {}
    dynamic_symbol_source = "<dynamic-symbol-table>"
    version_needs_source = "<version-requirements>"
    current_note_source = "<gnu-property-notes>"
    gnu_property_source = "<gnu-property-notes>"

    for line in lines:
        stripped = line.strip()
        for key in HEADER_KEYS:
            prefix = key + ":"
            if stripped.startswith(prefix):
                contract_key = "elf." + key.lower().replace("/", "_").replace(" ", "_")
                contract[contract_key] = _normalize_space(stripped[len(prefix) :])
                source_sections[contract_key] = "<elf-header>"
                break

        interpreter = re.search(r"Requesting program interpreter:\s*([^]]+)\]", line)
        if interpreter:
            contract["runtime.interpreter"] = interpreter.group(1).strip()
            source_sections["runtime.interpreter"] = "<program-headers>"

        if stripped.startswith("GNU_STACK"):
            tokens = stripped.split()
            flags = next((item for item in reversed(tokens) if re.fullmatch(r"[RWE]+", item)), "")
            contract["security.gnu_stack"] = flags
            source_sections["security.gnu_stack"] = "<program-headers>"
        elif stripped.startswith("GNU_RELRO"):
            contract["security.gnu_relro"] = True
            source_sections["security.gnu_relro"] = "<program-headers>"
        elif stripped.startswith("TLS"):
            tokens = stripped.split()
            flags = next((item for item in reversed(tokens) if re.fullmatch(r"[RWE]+", item)), "")
            contract["runtime.tls"] = flags or "present"
            source_sections["runtime.tls"] = "<program-headers>"

        note_source = re.match(r"Displaying notes found in:\s*(\S+)", stripped)
        if note_source:
            raw_source = note_source.group(1)
            current_note_source = (
                raw_source if raw_source.startswith(".") else "<note-segment>"
            )
            if "gnu.property" in raw_source:
                gnu_property_source = current_note_source

        dynamic = re.search(r"\(([A-Z0-9_]+)\)\s*(.*)$", line)
        if dynamic:
            tag, value = dynamic.groups()
            if tag in DYNAMIC_STRING_TAGS or tag in DYNAMIC_FLAG_TAGS:
                dynamic_values.setdefault(tag, []).append(_dynamic_value(value))

        property_match = re.search(
            r"\b(x86|AArch64) feature:\s*(.*)$", line, re.IGNORECASE
        )
        if property_match:
            architecture, raw_features = property_match.groups()
            prefix = "x86" if architecture.lower() == "x86" else "aarch64"
            for feature in re.split(r"[,\s]+", raw_features.strip()):
                normalized = feature.strip().lower()
                if normalized in ("ibt", "shstk", "bti", "pac"):
                    property_key = f"security.gnu_property.{prefix}_{normalized}"
                    gnu_property_features[property_key] = True
                    source_sections[property_key] = current_note_source
                    gnu_property_source = current_note_source

        if stripped.startswith("Version needs section"):
            in_version_needs = True
            version_provider = None
            version_section = re.search(r"Version needs section ['\"]([^'\"]+)", stripped)
            if version_section:
                version_needs_source = version_section.group(1)
        elif stripped.startswith(("Version definition section", "Version symbols section")):
            in_version_needs = False
            version_provider = None
        if in_version_needs:
            version_file = re.search(r"\bFile:\s*(\S+)", line)
            if version_file and "Version:" in line:
                version_provider = version_file.group(1)
            version_name = re.search(r"\bName:\s*(\S+)", line)
            if version_name and version_provider:
                version_requirements.setdefault(version_provider, []).append(
                    version_name.group(1)
                )

    for symbol in _readelf_symbol_rows(output):
        if (
            dynamic_symbol_sections is not None
            and symbol.table not in dynamic_symbol_sections
        ):
            continue
        if (
            not symbol.name
            or symbol.name == "0"
            or symbol.binding not in ("GLOBAL", "WEAK", "UNIQUE")
        ):
            continue
        dynamic_symbol_source = symbol.table
        definition = (
            "UND"
            if symbol.ndx == "UND"
            else symbol.ndx
            if symbol.ndx in ("ABS", "COM")
            else "DEF"
        )
        size_value: Optional[int] = (
            symbol.size
            if symbol.symbol_type in ("OBJECT", "TLS")
            else None
        )
        item = (
            symbol.name,
            symbol.symbol_type,
            symbol.binding,
            symbol.visibility,
            definition,
            size_value,
        )
        (imported if definition == "UND" else exported).append(item)

    contract.setdefault("security.gnu_relro", False)
    contract.setdefault("security.gnu_stack", "<absent>")
    bind_now = False
    for tag, values in sorted(dynamic_values.items()):
        if tag == "BIND_NOW":
            bind_now = True
            continue
        normalized_values: List[str] = []
        for value in values:
            tokens = value.split()
            if tag == "FLAGS" and "BIND_NOW" in tokens:
                bind_now = True
                tokens = [token for token in tokens if token != "BIND_NOW"]
            if tag == "FLAGS_1" and "NOW" in tokens:
                bind_now = True
                tokens = [token for token in tokens if token != "NOW"]
            if tokens:
                normalized_values.append(" ".join(tokens))
        if normalized_values:
            contract_key = "dynamic." + tag.lower()
            contract[contract_key] = normalized_values
            source_sections[contract_key] = ".dynamic"
    contract["security.bind_now"] = bind_now
    source_sections["security.bind_now"] = ".dynamic"
    machine = str(contract.get("elf.machine", "")).lower()
    if "x86-64" in machine or "80386" in machine:
        for feature in ("ibt", "shstk"):
            contract[f"security.gnu_property.x86_{feature}"] = (
                gnu_property_features.get(
                    f"security.gnu_property.x86_{feature}", False
                )
            )
            source_sections.setdefault(
                f"security.gnu_property.x86_{feature}",
                gnu_property_source,
            )
    elif "aarch64" in machine:
        for feature in ("bti", "pac"):
            contract[f"security.gnu_property.aarch64_{feature}"] = (
                gnu_property_features.get(
                    f"security.gnu_property.aarch64_{feature}", False
                )
            )
            source_sections.setdefault(
                f"security.gnu_property.aarch64_{feature}",
                gnu_property_source,
            )
    contract["symbols.imported"] = sorted(set(imported))
    contract["symbols.exported"] = sorted(set(exported))
    source_sections["symbols.imported"] = dynamic_symbol_source
    source_sections["symbols.exported"] = dynamic_symbol_source
    contract["versions.required"] = {
        provider: sorted(set(names))
        for provider, names in sorted(version_requirements.items())
    }
    source_sections["versions.required"] = version_needs_source
    return contract


def _version_key(name: str) -> Tuple[str, Tuple[int, ...]]:
    match = re.match(r"^(.*?)(\d+(?:\.\d+)+)$", name)
    if not match:
        return name, ()
    return match.group(1), tuple(int(part) for part in match.group(2).split("."))


def _version_floors(names: Sequence[str]) -> Dict[str, Tuple[int, ...]]:
    floors: Dict[str, Tuple[int, ...]] = {}
    for name in names:
        family, version = _version_key(name)
        if version:
            floors[family] = max(floors.get(family, ()), version)
    return floors


def _compare_version_requirements(
    left: Dict[str, List[str]], right: Dict[str, List[str]]
) -> List[Finding]:
    findings: List[Finding] = []
    for provider in sorted(set(left) | set(right)):
        left_names = set(left.get(provider, []))
        right_names = set(right.get(provider, []))
        left_floors = _version_floors(left_names)
        right_floors = _version_floors(right_names)
        raised = {
            family: (left_floors.get(family), floor)
            for family, floor in right_floors.items()
            if floor > left_floors.get(family, ())
        }
        new_unversioned = {
            name for name in right_names - left_names if not _version_key(name)[1]
        }
        severity = "FAIL" if raised or new_unversioned else "INFO"
        if left_names != right_names:
            findings.append(
                Finding(
                    severity,
                    "version-floor",
                    f"versions.required.{provider}",
                    sorted(left_names),
                    sorted(right_names),
                    "Bazel raises or adds a runtime symbol-version requirement."
                    if severity == "FAIL"
                    else "Bazel does not raise the maximum runtime version floor.",
                )
            )
    return findings


def _dynamic_symbols_by_name(
    items: Sequence[Tuple[Any, ...]],
) -> Dict[str, List[DynamicSymbol]]:
    by_name: Dict[str, List[DynamicSymbol]] = {}
    for item in items:
        symbol = DynamicSymbol.from_contract_item(item)
        by_name.setdefault(symbol.name, []).append(symbol)
    return by_name


def _dynamic_symbol_changes(
    left: Sequence[Tuple[Any, ...]], right: Sequence[Tuple[Any, ...]]
) -> List[DynamicSymbolChange]:
    left_by_name = _dynamic_symbols_by_name(left)
    right_by_name = _dynamic_symbols_by_name(right)
    changes: List[DynamicSymbolChange] = []
    for name in sorted(set(left_by_name) | set(right_by_name)):
        left_items = tuple(sorted(left_by_name.get(name, [])))
        right_items = tuple(sorted(right_by_name.get(name, [])))
        if left_items == right_items:
            continue
        if not left_items:
            kind = DynamicSymbolChangeKind.ADDED
        elif not right_items:
            kind = DynamicSymbolChangeKind.REMOVED
        else:
            kind = DynamicSymbolChangeKind.CHANGED
        changes.append(
            DynamicSymbolChange(name, kind, left_items, right_items)
        )
    return changes


def _compare_exported_symbols(
    left: Sequence[Tuple[Any, ...]], right: Sequence[Tuple[Any, ...]]
) -> List[Finding]:
    findings: List[Finding] = []
    for change in _dynamic_symbol_changes(left, right):
        if change.kind == DynamicSymbolChangeKind.ADDED:
            weak_only = all(item.binding == "WEAK" for item in change.right)
            findings.append(
                Finding(
                    "INFO" if weak_only else "FAIL",
                    "symbols-exported-added-weak"
                    if weak_only
                    else "symbols-exported-added",
                    change.name,
                    change.left_value(),
                    change.right_value(),
                    "Bazel adds only WEAK template/compiler-emitted exports."
                    if weak_only
                    else "Bazel adds an exported symbol; strict semantic consistency requires an identical export surface.",
                )
            )
        elif change.kind == DynamicSymbolChangeKind.REMOVED:
            findings.append(
                Finding(
                    "FAIL",
                    "symbols-exported-removed",
                    change.name,
                    change.left_value(),
                    change.right_value(),
                    "An export available to Make-built consumers is absent from Bazel.",
                )
            )
        else:
            findings.append(
                Finding(
                    "FAIL",
                    "symbols-exported-changed",
                    change.name,
                    change.left_value(),
                    change.right_value(),
                    "The exported symbol's type, binding, visibility, definition, or object size changed.",
                )
            )
    return findings


def _compare_imported_symbols(
    left: Sequence[Tuple[Any, ...]], right: Sequence[Tuple[Any, ...]]
) -> List[Finding]:
    findings: List[Finding] = []
    for change in _dynamic_symbol_changes(left, right):
        if change.kind == DynamicSymbolChangeKind.ADDED:
            findings.append(
                Finding(
                    "FAIL",
                    "symbols-imported-added",
                    change.name,
                    change.left_value(),
                    change.right_value(),
                    "Bazel introduces a runtime symbol reference absent from Make.",
                )
            )
        elif change.kind == DynamicSymbolChangeKind.REMOVED:
            findings.append(
                Finding(
                    "FAIL",
                    "symbols-imported-removed",
                    change.name,
                    change.left_value(),
                    change.right_value(),
                    "A Make runtime symbol reference is absent from Bazel; this can indicate a compiler, feature-macro, or implementation change.",
                )
            )
        else:
            findings.append(
                Finding(
                    "FAIL",
                    "symbols-imported-changed",
                    change.name,
                    change.left_value(),
                    change.right_value(),
                    "The imported symbol's type, binding, visibility, or versioned identity changed.",
                )
            )
    return findings


def _compare_needed_dependencies(
    left_value: Any,
    right_value: Any,
    allow_extra_needed: Sequence[str],
    allow_needed_reorder: bool,
) -> List[Finding]:
    if not isinstance(left_value, list) or not isinstance(right_value, list):
        if left_value == right_value:
            return []
        return [Finding("FAIL", "dynamic", "dynamic.needed", left_value, right_value)]
    allowed = set(allow_extra_needed)
    accepted = [
        item for item in right_value if item in allowed and item not in left_value
    ]
    filtered_right = [item for item in right_value if item not in accepted]
    equal_after_policy = (
        sorted(filtered_right) == sorted(left_value)
        if allow_needed_reorder
        else filtered_right == left_value
    )
    if equal_after_policy:
        if accepted or right_value != left_value:
            return [
                Finding(
                    "INFO",
                    "dynamic",
                    "dynamic.needed",
                    left_value,
                    right_value,
                    "Accepted by explicit DT_NEEDED policy.",
                )
            ]
        return []
    return [Finding("FAIL", "dynamic", "dynamic.needed", left_value, right_value)]


def _compare_security_property(key: str, left: Any, right: Any) -> Finding:
    strengthened = False
    weakened = False
    if key in ("security.bind_now", "security.gnu_relro") or key.startswith(
        "security.gnu_property."
    ):
        if isinstance(left, bool) and isinstance(right, bool):
            strengthened = not left and right
            weakened = left and not right
    elif key == "security.gnu_stack":
        left_flags = set(left) if isinstance(left, str) else set()
        right_flags = set(right) if isinstance(right, str) else set()
        if left_flags - {"E"} == right_flags - {"E"}:
            strengthened = "E" in left_flags and "E" not in right_flags
            weakened = "E" not in left_flags and "E" in right_flags

    if strengthened:
        return Finding(
            "INFO",
            "security-strengthened",
            key,
            left,
            right,
            "Bazel enables a security hardening property absent from Make.",
        )
    if weakened:
        return Finding(
            "FAIL",
            "security-weakened",
            key,
            left,
            right,
            "Bazel disables a security hardening property enabled by Make.",
        )
    return Finding(
        "FAIL",
        "security",
        key,
        left,
        right,
        "The security property changed, but the direction is not safely classifiable.",
    )


def _contract_source_key(finding: Finding) -> str:
    if finding.category == "version-floor":
        return "versions.required"
    if finding.category.startswith("symbols-imported-"):
        return "symbols.imported"
    if finding.category.startswith("symbols-exported-"):
        return "symbols.exported"
    return finding.path


def _contract_findings_with_sections(
    findings: Sequence[Finding],
    left_sources: Dict[str, str],
    right_sources: Dict[str, str],
) -> List[Finding]:
    located: List[Finding] = []
    for finding in findings:
        if finding.category.startswith("symbols-imported-"):
            public_category = "import-changed"
        elif finding.category.startswith("symbols-exported-"):
            public_category = "export-changed"
        elif finding.category.startswith("security-"):
            public_category = "security"
        else:
            public_category = PUBLIC_CATEGORY_NAMES.get(
                finding.category, finding.category
            )
        fallback = _finding_section(finding.as_dict(), public_category)
        source_key = _contract_source_key(finding)
        left_section = left_sources.get(source_key, fallback)
        right_section = right_sources.get(source_key, fallback)
        section: EvidenceLocation = (
            left_section
            if left_section == right_section
            else {"make": left_section, "bazel": right_section}
        )
        located.append(replace(finding, section=section))
    return located


def compare_contracts(
    left: Dict[str, Any],
    right: Dict[str, Any],
    allow_extra_needed: Sequence[str] = (),
    allow_needed_reorder: bool = False,
) -> List[Finding]:
    left_sources = getattr(left, "source_sections", {})
    right_sources = getattr(right, "source_sections", {})
    findings = _compare_version_requirements(
        left.get("versions.required", {}), right.get("versions.required", {})
    )
    findings.extend(
        _compare_imported_symbols(
            left.get("symbols.imported", []), right.get("symbols.imported", [])
        )
    )
    findings.extend(
        _compare_exported_symbols(
            left.get("symbols.exported", []), right.get("symbols.exported", [])
        )
    )
    if "dynamic.needed" in left or "dynamic.needed" in right:
        findings.extend(
            _compare_needed_dependencies(
                left.get("dynamic.needed", "<absent>"),
                right.get("dynamic.needed", "<absent>"),
                allow_extra_needed,
                allow_needed_reorder,
            )
        )
    handled = {
        "versions.required",
        "symbols.imported",
        "symbols.exported",
        "dynamic.needed",
    }
    for key in sorted((set(left) | set(right)) - handled):
        left_value = left.get(key, "<absent>")
        right_value = right.get(key, "<absent>")
        if left_value != right_value:
            if key.startswith("security."):
                findings.append(
                    _compare_security_property(key, left_value, right_value)
                )
            else:
                category = key.split(".", 1)[0]
                findings.append(
                    Finding("FAIL", category, key, left_value, right_value)
                )
    return _contract_findings_with_sections(
        findings, left_sources, right_sources
    )


_FUNCTION_HEADER = re.compile(r"^\s*([0-9a-fA-F]+)\s+<(.+)>:\s*$")
_SECTION_HEADER = re.compile(r"^Disassembly of section (.+):\s*$")
_ADDRESS_PREFIX = re.compile(r"^\s*([0-9a-fA-F]+):\s*")
_RAW_BYTES = re.compile(r"^(?:(?:[0-9a-fA-F]{2})\s+){2,}")
_SYMBOL_ADDRESS_PREFIX = re.compile(r"(?<![\w])(?:0x)?[0-9a-fA-F]+\s*(?=<)")
_RIP_RELATIVE = re.compile(r"-?0x[0-9a-fA-F]+\(%rip\)")
_ADDRESS_COMMENT = re.compile(r"\s*#\s*(?:0x)?[0-9a-fA-F]+\s*<(.+)>\s*$")
_TRAILING_SYMBOL_OFFSET = re.compile(r"[+-]0x[0-9a-fA-F]+$")
_GCC_DERIVED_FUNCTION_SUFFIX = re.compile(
    r"(?:"
    r"\.(?:part|isra|constprop|clone)\.\d+|\.cold(?:\.\d+)?|"
    r"\s+\[clone \.(?:(?:part|isra|constprop|clone)\.\d+|cold(?:\.\d+)?)\]"
    r")$"
)


def _gcc_function_family_name(name: str) -> str:
    family = name
    while True:
        normalized = _GCC_DERIVED_FUNCTION_SUFFIX.sub("", family)
        if normalized == family:
            return family
        family = normalized


def _is_gcc_derived_only_function(block: FunctionBlock) -> bool:
    names = block.aliases or (block.name,)
    return all(_gcc_function_family_name(name) != name for name in names)


def _ignore_one_sided_gcc_derived_function(block: FunctionBlock) -> bool:
    return (
        block.binding not in _PUBLIC_FUNCTION_BINDINGS
        and _is_gcc_derived_only_function(block)
    )


def _is_plt_section(name: str) -> bool:
    return name in (".plt", ".iplt") or name.startswith(
        (".plt.", ".iplt.")
    )


def normalize_instruction(line: str) -> str:
    line = _ADDRESS_PREFIX.sub("", line)
    line = _RAW_BYTES.sub("", line)
    address_comment = _ADDRESS_COMMENT.search(line)
    if address_comment and _RIP_RELATIVE.search(line):
        line = _RIP_RELATIVE.sub(f"RIPREL<{address_comment.group(1)}>", line)
        line = _ADDRESS_COMMENT.sub("", line)
    line = _SYMBOL_ADDRESS_PREFIX.sub("", line)
    line = re.sub(r"\s+#\s*(?:0x)?[0-9a-fA-F]+\s*$", "", line)
    return _normalize_space(line)


def _is_safe_nop(instruction: str) -> bool:
    return bool(
        re.fullmatch(r"(?:(?:data16|cs)\s+)*nop[wlq]?(?:\s+.*)?", instruction)
        or re.fullmatch(r"xchg[wql]?\s+%ax\s*,\s*%ax", instruction)
    )


def _preferred_function_aliases(symbols: Sequence[Any]) -> Tuple[List[Any], SymbolBinding]:
    for raw_binding, binding in (
        (STB_GLOBAL, SymbolBinding.GLOBAL),
        (STB_GNU_UNIQUE, SymbolBinding.UNIQUE),
        (STB_WEAK, SymbolBinding.WEAK),
        (STB_LOCAL, SymbolBinding.LOCAL),
    ):
        selected = [symbol for symbol in symbols if symbol.binding == raw_binding]
        if selected:
            return selected, binding
    return list(symbols), SymbolBinding.LOCAL


def function_symbol_metadata(
    elf: Any,
) -> Dict[FunctionLocation, FunctionSymbolMetadata]:
    grouped: Dict[Tuple[int, int], List[Any]] = {}
    functions_by_section: Dict[int, List[int]] = {}
    for symbol in elf.symbols():
        if (
            symbol.type in (STT_FUNC, STT_GNU_IFUNC)
            and symbol.name
            and 0 < symbol.shndx < len(elf.sections)
        ):
            grouped.setdefault((symbol.shndx, symbol.value), []).append(symbol)
            functions_by_section.setdefault(symbol.shndx, []).append(symbol.value)

    next_function: Dict[Tuple[int, int], Optional[int]] = {}
    for section_index, addresses in functions_by_section.items():
        unique_addresses = sorted(set(addresses))
        for index, address in enumerate(unique_addresses):
            next_function[(section_index, address)] = (
                unique_addresses[index + 1]
                if index + 1 < len(unique_addresses)
                else None
            )

    result: Dict[FunctionLocation, FunctionSymbolMetadata] = {}
    ambiguous_keys = set()
    for (section_index, address), symbols in grouped.items():
        identity_symbols, binding = _preferred_function_aliases(symbols)
        sizes = {symbol.size for symbol in identity_symbols}
        size = next(iter(sizes)) if len(sizes) == 1 else 0
        reliable = size > 0
        if reliable:
            section = elf.sections[section_index]
            relative_start = (
                address if elf.type == ET_REL else address - section.addr
            )
            following = next_function[(section_index, address)]
            reliable = (
                relative_start >= 0
                and relative_start + size <= section.size
                and (following is None or address + size <= following)
            )
        names = tuple(sorted({symbol.name for symbol in identity_symbols}))
        if elf.type == ET_REL:
            section_name = getattr(elf.sections[section_index], "name", "")
            if not section_name:
                continue
            result_key = FunctionLocation(section_name, address)
        else:
            result_key = FunctionLocation(None, address)
        if result_key in ambiguous_keys:
            continue
        if result_key in result:
            del result[result_key]
            ambiguous_keys.add(result_key)
            continue
        result[result_key] = FunctionSymbolMetadata(
            size, binding, reliable, names
        )
    return result


def parse_readelf_function_symbols(
    output: str, elf: Any
) -> Dict[FunctionIdentity, FunctionBlock]:
    """Build the comparable function inventory from ``readelf -sW`` output.

    Symbol values are used only to join aliases and recover the owning
    executable section.  Function identity is name based, so layout/address
    changes do not become findings.
    """

    binding_values = {
        "LOCAL": SymbolBinding.LOCAL,
        "GLOBAL": SymbolBinding.GLOBAL,
        "WEAK": SymbolBinding.WEAK,
        "UNIQUE": SymbolBinding.UNIQUE,
    }
    binding_order = (
        SymbolBinding.GLOBAL,
        SymbolBinding.UNIQUE,
        SymbolBinding.WEAK,
        SymbolBinding.LOCAL,
    )
    grouped: Dict[
        Tuple[int, int], List[Tuple[str, int, SymbolBinding]]
    ] = {}
    for symbol in _readelf_symbol_rows(output):
        if (
            symbol.symbol_type not in ("FUNC", "IFUNC")
            or symbol.binding not in binding_values
        ):
            continue
        if not symbol.ndx.isdigit():
            continue
        section_index = int(symbol.ndx)
        if not (0 < section_index < len(elf.sections)):
            continue
        section = elf.sections[section_index]
        if not (section.flags & SHF_EXECINSTR) or _is_plt_section(section.name):
            continue
        if not symbol.name or symbol.name == "0":
            continue
        grouped.setdefault((section_index, symbol.value), []).append(
            (
                symbol.name,
                symbol.size,
                binding_values[symbol.binding],
            )
        )

    native_metadata = function_symbol_metadata(elf)
    functions: Dict[FunctionIdentity, FunctionBlock] = {}
    occurrences: Dict[FunctionIdentity, int] = {}
    for (section_index, address), symbols in sorted(grouped.items()):
        section = elf.sections[section_index]
        location = FunctionLocation(
            section.name if elf.type == ET_REL else None,
            address,
        )
        metadata = native_metadata.get(location)
        if metadata is not None:
            binding = metadata.binding
            aliases = metadata.names
            size = metadata.size
        else:
            binding = next(
                candidate
                for candidate in binding_order
                if any(item[2] == candidate for item in symbols)
            )
            preferred = [item for item in symbols if item[2] == binding]
            aliases = tuple(sorted({item[0] for item in preferred}))
            sizes = {item[1] for item in preferred}
            size = next(iter(sizes)) if len(sizes) == 1 else 0

        original_name = aliases[0]
        scope = (
            section.name
            if elf.type == ET_REL and binding == SymbolBinding.LOCAL
            else ""
        )
        base_identity = FunctionIdentity(scope, aliases, "", 1)
        occurrence = occurrences.get(base_identity, 0) + 1
        occurrences[base_identity] = occurrence
        identity = FunctionIdentity(scope, aliases, "", occurrence)
        functions[identity] = FunctionBlock(
            name=original_name,
            start=address,
            instructions=[],
            binding=binding,
            boundary_reliable=True,
            degraded_name=False,
            size=size,
            aliases=aliases,
            section=section.name,
        )
    return functions


def _function_comparison_name(name: str) -> Tuple[str, bool]:
    offset = _TRAILING_SYMBOL_OFFSET.search(name)
    if not offset:
        return name, False
    return name[: offset.start()] + "<UNRESOLVED_FUNCTION_OFFSET>", True


def parse_objdump_function_blocks(
    output: str,
    metadata: Dict[FunctionLocation, FunctionSymbolMetadata],
    assume_boundaries_reliable: bool = False,
) -> Dict[FunctionIdentity, FunctionBlock]:
    functions: Dict[FunctionIdentity, FunctionBlock] = {}
    occurrences: Dict[FunctionIdentity, int] = {}
    current: Optional[FunctionBlock] = None
    current_section: Optional[str] = None
    for line in output.splitlines():
        section_header = _SECTION_HEADER.match(line)
        if section_header:
            current_section = section_header.group(1)
            current = None
            continue
        header = _FUNCTION_HEADER.match(line)
        if header:
            if current_section and _is_plt_section(current_section):
                current = None
                continue
            start = int(header.group(1), 16)
            original_name = header.group(2)
            scoped_location = (
                FunctionLocation(current_section, start)
                if current_section
                else None
            )
            symbol = metadata.get(scoped_location) if scoped_location else None
            section_scoped = symbol is not None
            if symbol is None:
                symbol = metadata.get(FunctionLocation(None, start))
            normalized_name, degraded_name = _function_comparison_name(
                original_name
            )
            is_section_local = (
                section_scoped
                and symbol is not None
                and symbol.binding == SymbolBinding.LOCAL
            )
            scope = (current_section or "") if is_section_local else ""
            base_identity = FunctionIdentity(
                scope=scope,
                aliases=symbol.names if symbol and symbol.names else (),
                fallback="" if symbol and symbol.names else normalized_name,
                occurrence=1,
            )
            occurrence = occurrences.get(base_identity, 0) + 1
            occurrences[base_identity] = occurrence
            identity = FunctionIdentity(
                scope=base_identity.scope,
                aliases=base_identity.aliases,
                fallback=base_identity.fallback,
                occurrence=occurrence,
            )
            current = FunctionBlock(
                name=original_name,
                start=start,
                instructions=[],
                binding=symbol.binding if symbol else None,
                boundary_reliable=(
                    symbol.boundary_reliable
                    if symbol
                    else assume_boundaries_reliable
                ),
                degraded_name=degraded_name,
                size=symbol.size if symbol else 0,
                aliases=symbol.names if symbol else (),
                section=current_section,
            )
            functions[identity] = current
            continue
        instruction_match = _ADDRESS_PREFIX.match(line)
        if current is None or not instruction_match:
            continue
        address = int(instruction_match.group(1), 16)
        if (
            current.boundary_reliable
            and current.size > 0
            and address >= current.start + current.size
        ):
            continue
        instruction = normalize_instruction(line)
        if instruction and not _is_safe_nop(instruction):
            current.instructions.append(instruction)
    return functions


def parse_objdump_functions(output: str) -> Dict[str, List[str]]:
    """Compatibility view used by callers that do not provide ELF symbols."""
    return {
        identity.label(): block.instructions
        for identity, block in parse_objdump_function_blocks(
            output, {}, assume_boundaries_reliable=True
        ).items()
    }


def _function_blocks(
    functions: Dict[Any, Any]
) -> Dict[FunctionIdentity, FunctionBlock]:
    blocks: Dict[FunctionIdentity, FunctionBlock] = {}
    for name, value in functions.items():
        identity = (
            name
            if isinstance(name, FunctionIdentity)
            else FunctionIdentity("", (), str(name))
        )
        binding = value.binding if isinstance(value, FunctionBlock) else None
        is_public = binding in _PUBLIC_FUNCTION_BINDINGS
        if identity.aliases and binding == SymbolBinding.LOCAL:
            aliases = tuple(
                sorted(
                    {
                        _gcc_function_family_name(alias)
                        for alias in identity.aliases
                    }
                )
            )
            if aliases != identity.aliases:
                identity = FunctionIdentity("", aliases, identity.fallback)
        elif not identity.aliases and not is_public:
            family = _gcc_function_family_name(identity.fallback)
            if family != identity.fallback:
                identity = FunctionIdentity(identity.scope, (), family)
        if isinstance(value, FunctionBlock):
            block = value
        else:
            block = FunctionBlock(
                name=str(name),
                start=0,
                instructions=list(value),
                binding=None,
                boundary_reliable=True,
                degraded_name=False,
                aliases=(),
            )
        existing = blocks.get(identity)
        if existing is None or (
            _is_gcc_derived_only_function(existing)
            and not _is_gcc_derived_only_function(block)
        ):
            blocks[identity] = block
    return blocks


def _function_path(
    key: FunctionIdentity,
    left: Optional[FunctionBlock],
    right: Optional[FunctionBlock],
) -> str:
    if left and right and left.name != right.name:
        return f"{left.name} <-> {right.name}"
    block = left or right
    return block.name if block else key.label()


def _compare_one_sided_function(
    key: FunctionIdentity, block: FunctionBlock, side: str
) -> Finding:
    path = _function_path(
        key,
        block if side == "left" else None,
        block if side == "right" else None,
    )
    if side == "right" and block.binding == SymbolBinding.WEAK:
        return Finding(
            "INFO",
            "function-added-weak",
            path,
            "<missing>",
            "<present>",
            "Bazel adds a WEAK function body already classified as an informational export addition.",
            section=block.section,
        )

    direction_is_conclusive = (
        side == "left"
        and block.binding in (
            SymbolBinding.GLOBAL,
            SymbolBinding.UNIQUE,
            SymbolBinding.WEAK,
        )
    ) or (
        side == "right"
        and block.binding in (SymbolBinding.GLOBAL, SymbolBinding.UNIQUE)
    )
    if direction_is_conclusive or (
        not block.degraded_name and block.boundary_reliable
    ):
        return Finding(
            "FAIL",
            "function-removed" if side == "left" else "function-added",
            path,
            "<present>" if side == "left" else "<missing>",
            "<missing>" if side == "left" else "<present>",
            "A Make function is absent from Bazel."
            if side == "left"
            else "Bazel adds a non-WEAK function.",
            section=block.section,
        )

    return Finding(
        "ERROR",
        "function-boundary",
        path,
        "<present>" if side == "left" else "<missing>",
        "<missing>" if side == "left" else "<present>",
        (
            f"The {'Make' if side == 'left' else 'Bazel'}-only objdump block "
            "has an unstable stripped name or lacks a reliable st_size boundary."
        ),
        section=block.section,
    )


def _pair_function_blocks(
    left: Dict[FunctionIdentity, FunctionBlock],
    right: Dict[FunctionIdentity, FunctionBlock],
) -> Tuple[
    List[Tuple[FunctionIdentity, FunctionBlock, FunctionBlock]],
    Dict[FunctionIdentity, FunctionBlock],
    Dict[FunctionIdentity, FunctionBlock],
]:
    left_remaining = dict(left)
    right_remaining = dict(right)
    pairs: List[Tuple[FunctionIdentity, FunctionBlock, FunctionBlock]] = []
    for key in sorted(set(left_remaining) & set(right_remaining)):
        pairs.append((key, left_remaining.pop(key), right_remaining.pop(key)))

    while True:
        candidates: Dict[FunctionIdentity, List[FunctionIdentity]] = {}
        reverse_candidates: Dict[FunctionIdentity, List[FunctionIdentity]] = {}
        for left_key, left_block in left_remaining.items():
            left_aliases = set(left_key.aliases or left_block.aliases)
            if not left_aliases:
                continue
            for right_key, right_block in right_remaining.items():
                right_aliases = set(
                    right_key.aliases or right_block.aliases
                )
                if left_aliases.intersection(right_aliases):
                    candidates.setdefault(left_key, []).append(right_key)
                    reverse_candidates.setdefault(right_key, []).append(left_key)
        unique_pairs = [
            (left_key, right_keys[0])
            for left_key, right_keys in candidates.items()
            if len(right_keys) == 1
            and len(reverse_candidates.get(right_keys[0], [])) == 1
        ]
        if not unique_pairs:
            break
        for left_key, right_key in sorted(unique_pairs):
            left_block = left_remaining.pop(left_key)
            right_block = right_remaining.pop(right_key)
            pairs.append((left_key, left_block, right_block))
    return pairs, left_remaining, right_remaining


def compare_functions(left: Dict[str, Any], right: Dict[str, Any]) -> List[Finding]:
    left_blocks = _function_blocks(left)
    right_blocks = _function_blocks(right)
    findings: List[Finding] = []
    _, left_remaining, right_remaining = _pair_function_blocks(
        left_blocks, right_blocks
    )
    for key, left_block in sorted(left_remaining.items()):
        if _ignore_one_sided_gcc_derived_function(left_block):
            continue
        findings.append(_compare_one_sided_function(key, left_block, "left"))
    for key, right_block in sorted(right_remaining.items()):
        if _ignore_one_sided_gcc_derived_function(right_block):
            continue
        findings.append(_compare_one_sided_function(key, right_block, "right"))
    return findings


def compiler_comments(elf: Any) -> List[str]:
    """Return unique non-empty strings recorded in ELF .comment sections."""

    values = set()
    for section in elf.sections:
        if section.name != ".comment":
            continue
        for raw_value in elf.section_data(section).split(b"\0"):
            value = raw_value.decode(
                "utf-8", errors="backslashreplace"
            ).strip()
            if value:
                values.add(value)
    return sorted(values)


def compiler_comment_mismatch(
    left_elf: Any, right_elf: Any
) -> Optional[Dict[str, List[str]]]:
    """Describe differing compiler comments without affecting the verdict."""

    left = compiler_comments(left_elf)
    right = compiler_comments(right_elf)
    if left == right or (not left and not right):
        return None
    return {"make": left, "bazel": right}


def _initialization_array_sections(
    elf: Any, ignored_patterns: Sequence[str]
) -> Dict[Tuple[int, int], Any]:
    section_types = {SHT_INIT_ARRAY, SHT_FINI_ARRAY, SHT_PREINIT_ARRAY}
    sections: Dict[Tuple[int, int], Any] = {}
    occurrences: Dict[int, int] = {}
    for section in elf.sections:
        if section.type not in section_types or _matches_any(
            section.name, ignored_patterns
        ):
            continue
        occurrence = occurrences.get(section.type, 0)
        occurrences[section.type] = occurrence + 1
        sections[(section.type, occurrence)] = section
    return sections


def _initialization_array_label(key: Tuple[int, int]) -> str:
    section_type, occurrence = key
    base = {
        SHT_PREINIT_ARRAY: ".preinit_array",
        SHT_INIT_ARRAY: ".init_array",
        SHT_FINI_ARRAY: ".fini_array",
    }[section_type]
    return base if occurrence == 0 else f"{base}#{occurrence + 1}"


def _paired_section_location(
    left_section: Any,
    right_section: Any,
    fallback: str,
) -> EvidenceLocation:
    left_location = left_section.name if left_section is not None else fallback
    right_location = right_section.name if right_section is not None else fallback
    if left_location == right_location:
        return left_location
    return {"make": left_location, "bazel": right_location}


CallbackToken = Tuple[Tuple[str, ...], int]


def _callback_tokens(
    entries: Sequence[InitializationArrayEntry],
) -> List[CallbackToken]:
    """Give repeated callback identities stable occurrence numbers."""

    occurrences: Dict[Tuple[str, ...], int] = {}
    tokens: List[CallbackToken] = []
    for entry in entries:
        if entry.identity is None:
            continue
        occurrence = occurrences.get(entry.identity, 0)
        occurrences[entry.identity] = occurrence + 1
        tokens.append((entry.identity, occurrence))
    return tokens


def _callback_finding_path(name: str, token: CallbackToken) -> str:
    identity, occurrence = token
    label = identity[0] if identity else "<unnamed>"
    if occurrence:
        label += f"#{occurrence + 1}"
    return f"{name}.callback[{label}]"


def _callback_value(token: CallbackToken, index: int) -> Dict[str, Any]:
    return {"index": index, "function": list(token[0])}


def _callback_lcs_pairs(
    left: Sequence[CallbackToken], right: Sequence[CallbackToken]
) -> List[Tuple[int, int]]:
    """Return an order-preserving maximum match, comparing identities only."""

    lengths = [
        [0] * (len(right) + 1)
        for _ in range(len(left) + 1)
    ]
    for left_index in range(len(left) - 1, -1, -1):
        for right_index in range(len(right) - 1, -1, -1):
            if left[left_index][0] == right[right_index][0]:
                lengths[left_index][right_index] = (
                    1 + lengths[left_index + 1][right_index + 1]
                )
            else:
                lengths[left_index][right_index] = max(
                    lengths[left_index + 1][right_index],
                    lengths[left_index][right_index + 1],
                )

    pairs: List[Tuple[int, int]] = []
    left_index = 0
    right_index = 0
    while left_index < len(left) and right_index < len(right):
        if left[left_index][0] == right[right_index][0]:
            pairs.append((left_index, right_index))
            left_index += 1
            right_index += 1
        elif lengths[left_index + 1][right_index] >= lengths[left_index][
            right_index + 1
        ]:
            left_index += 1
        else:
            right_index += 1
    return pairs


def _initialization_array_entries(
    elf: Any, section: Any
) -> Tuple[List[InitializationArrayEntry], Optional[str]]:
    pointer_size = 4 if elf.display_class == "ELF32" else 8
    if section.entsize not in (0, pointer_size):
        return [], (
            f"entry size {section.entsize} does not match the ELF pointer size "
            f"{pointer_size}"
        )
    if section.size % pointer_size:
        return [], (
            f"section size {section.size} is not a multiple of pointer size "
            f"{pointer_size}"
        )

    metadata = function_symbol_metadata(elf)
    known_function_names = {
        symbol.name
        for symbol in elf.symbols()
        if symbol.name and symbol.type in (STT_FUNC, STT_GNU_IFUNC)
    }
    section_relocations = [
        relocation
        for relocation in elf.relocations()
        if relocation.target_section_index == section.index
    ]
    unsupported_relocations = [
        relocation
        for relocation in section_relocations
        if INITIALIZATION_RELOCATION_WIDTHS.get(elf.machine, {}).get(
            relocation.type
        )
        != pointer_size
    ]
    if unsupported_relocations:
        samples = ", ".join(
            f"relocation type {relocation.type} at 0x{relocation.offset:x}"
            for relocation in unsupported_relocations[:5]
        )
        return [], (
            f"unsupported pointer relocation for {elf.display_class} "
            f"machine {elf.machine}: {samples}"
        )
    invalid_offsets = [
        relocation.offset
        for relocation in section_relocations
        if relocation.offset < 0
        or relocation.offset >= section.size
        or relocation.offset % pointer_size
    ]
    if invalid_offsets:
        return [], (
            "relocation offsets do not identify pointer slots: "
            + ", ".join(f"0x{offset:x}" for offset in invalid_offsets[:5])
        )
    relocations_by_offset: Dict[int, List[Any]] = {}
    for relocation in section_relocations:
        relocations_by_offset.setdefault(relocation.offset, []).append(
            relocation
        )
    duplicate_offsets = [
        offset
        for offset, relocations in relocations_by_offset.items()
        if len(relocations) != 1
    ]
    if duplicate_offsets:
        return [], (
            "multiple relocations identify the same pointer slot: "
            + ", ".join(f"0x{offset:x}" for offset in duplicate_offsets[:5])
        )

    byteorder = "little" if elf.display_endian == "little" else "big"
    data = elf.section_data(section)
    entries: List[InitializationArrayEntry] = []
    for offset in range(0, section.size, pointer_size):
        raw_value = int.from_bytes(
            data[offset : offset + pointer_size], byteorder=byteorder
        )
        relocations = relocations_by_offset.get(offset, [])
        identity, relocation_evidence = _resolve_initialization_target(
            elf,
            metadata,
            known_function_names,
            relocations[0] if relocations else None,
            raw_value,
        )
        entries.append(
            InitializationArrayEntry(
                identity,
                raw_value,
                relocation_evidence,
            )
        )
    return entries, None


def _resolve_initialization_target(
    elf: Any,
    metadata: Dict[FunctionLocation, FunctionSymbolMetadata],
    known_function_names: AbstractSet[str],
    relocation: Any,
    raw_value: int,
) -> Tuple[Optional[Tuple[str, ...]], Optional[Dict[str, Any]]]:
    if relocation is None:
        if elf.type == ET_REL:
            return None, None
        target = metadata.get(FunctionLocation(None, raw_value))
        return (target.names if target and target.names else None), None

    addend = (
        relocation.addend
        if relocation.addend is not None
        else raw_value
    )
    evidence = {
        "type": relocation.type,
        "symbol": relocation.symbol_name or "<none>",
        "addend": addend,
    }
    location: Optional[FunctionLocation] = None
    if (
        elf.type == ET_REL
        and 0 < relocation.symbol_section_index < len(elf.sections)
    ):
        target_section = elf.sections[relocation.symbol_section_index]
        location = FunctionLocation(
            target_section.name,
            relocation.symbol_value + addend,
        )
    elif elf.type != ET_REL:
        location = FunctionLocation(None, relocation.symbol_value + addend)
    target = metadata.get(location) if location is not None else None
    if target and target.names:
        return target.names, evidence
    if relocation.symbol_name not in known_function_names:
        return None, evidence
    if addend > 0:
        suffix = f"+0x{addend:x}"
    elif addend < 0:
        suffix = f"-0x{-addend:x}"
    else:
        suffix = ""
    return (relocation.symbol_name + suffix,), evidence


def compare_initialization_arrays(
    left_elf: Any,
    right_elf: Any,
    ignored_patterns: Sequence[str],
) -> List[Finding]:
    """Compare ordered preinit/init/fini function-pointer tables."""

    findings: List[Finding] = []
    left_sections = _initialization_array_sections(left_elf, ignored_patterns)
    right_sections = _initialization_array_sections(right_elf, ignored_patterns)
    for key in sorted(set(left_sections) | set(right_sections)):
        left_section = left_sections.get(key)
        right_section = right_sections.get(key)
        name = _initialization_array_label(key)
        section_location = _paired_section_location(
            left_section,
            right_section,
            "<callback-array-sections>",
        )
        left_entries, left_error = (
            _initialization_array_entries(left_elf, left_section)
            if left_section is not None
            else ([], None)
        )
        right_entries, right_error = (
            _initialization_array_entries(right_elf, right_section)
            if right_section is not None
            else ([], None)
        )
        if left_error or right_error:
            findings.append(
                Finding(
                    "ERROR",
                    "initialization-array-coverage",
                    name,
                    left_error or "valid pointer table",
                    right_error or "valid pointer table",
                    "The callback table could not be parsed safely.",
                    section=section_location,
                )
            )
            continue
        if len(left_entries) != len(right_entries):
            findings.append(
                Finding(
                    "FAIL",
                    "initialization-array",
                    f"{name}.count",
                    len(left_entries),
                    len(right_entries),
                    "The number of ordered loader callbacks changed.",
                    section=section_location,
                )
            )
        unresolved = False
        for index in range(max(len(left_entries), len(right_entries))):
            left_entry = left_entries[index] if index < len(left_entries) else None
            right_entry = (
                right_entries[index] if index < len(right_entries) else None
            )
            if all(
                entry is None or entry.identity is not None
                for entry in (left_entry, right_entry)
            ):
                continue
            unresolved = True
            findings.append(
                Finding(
                    "ERROR",
                    "initialization-array-coverage",
                    f"{name}[{index}]",
                    left_entry.as_dict() if left_entry is not None else "<missing>",
                    right_entry.as_dict() if right_entry is not None else "<missing>",
                    "At least one callback target cannot be resolved to a stable function identity; compare unstripped artifacts.",
                    section=section_location,
                )
            )
        if unresolved:
            continue

        left_tokens = _callback_tokens(left_entries)
        right_tokens = _callback_tokens(right_entries)
        lcs_pairs = _callback_lcs_pairs(left_tokens, right_tokens)
        matched_left = {left_index for left_index, _ in lcs_pairs}
        matched_right = {right_index for _, right_index in lcs_pairs}
        unmatched_left: Dict[Tuple[str, ...], List[int]] = {}
        unmatched_right: Dict[Tuple[str, ...], List[int]] = {}
        for index, token in enumerate(left_tokens):
            if index not in matched_left:
                unmatched_left.setdefault(token[0], []).append(index)
        for index, token in enumerate(right_tokens):
            if index not in matched_right:
                unmatched_right.setdefault(token[0], []).append(index)

        reordered_pairs: List[Tuple[int, int]] = []
        removed_indices: List[int] = []
        added_indices: List[int] = []
        for identity in set(unmatched_left) | set(unmatched_right):
            left_indices = unmatched_left.get(identity, [])
            right_indices = unmatched_right.get(identity, [])
            paired_count = min(len(left_indices), len(right_indices))
            reordered_pairs.extend(
                zip(
                    left_indices[:paired_count],
                    right_indices[:paired_count],
                )
            )
            removed_indices.extend(left_indices[paired_count:])
            added_indices.extend(right_indices[paired_count:])

        for index in sorted(removed_indices):
            token = left_tokens[index]
            findings.append(
                Finding(
                    "FAIL",
                    "initialization-array",
                    _callback_finding_path(name, token),
                    _callback_value(token, index),
                    "<missing>",
                    "A loader callback present in Make is absent from Bazel.",
                    section=section_location,
                )
            )
        for index in sorted(added_indices):
            token = right_tokens[index]
            findings.append(
                Finding(
                    "FAIL",
                    "initialization-array",
                    _callback_finding_path(name, token),
                    "<missing>",
                    _callback_value(token, index),
                    "A loader callback absent from Make is present in Bazel.",
                    section=section_location,
                )
            )
        for left_index, right_index in sorted(reordered_pairs):
            token = left_tokens[left_index]
            findings.append(
                Finding(
                    "FAIL",
                    "initialization-array",
                    _callback_finding_path(name, token),
                    _callback_value(token, left_index),
                    _callback_value(right_tokens[right_index], right_index),
                    "The relative order of this loader callback changed.",
                    section=section_location,
                )
            )
    return findings


def _matches_any(name: str, patterns: Sequence[str]) -> bool:
    import fnmatch

    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _normalize_paths(raw: bytes, maps: Sequence[Tuple[str, str]]) -> bytes:
    normalized = raw
    for source, destination in sorted(
        maps, key=lambda item: len(item[0]), reverse=True
    ):
        normalized = normalized.replace(
            source.encode("utf-8", errors="surrogateescape"),
            destination.encode("utf-8", errors="surrogateescape"),
        )
    return normalized


def _mask_data_slots(
    raw: bytes, slot_widths: Dict[int, int]
) -> bytes:
    if not slot_widths:
        return raw
    masked = bytearray(raw)
    for start, width in slot_widths.items():
        if not 0 <= start < len(masked):
            continue
        end = min(start + width, len(masked))
        masked[start:end] = b"\0" * (end - start)
    return bytes(masked)


def _normalized_data_digest(
    raw: bytes,
    pointer_size: int,
    byteorder: str,
    address_names: Dict[int, str],
    masked_slot_widths: Optional[Dict[int, int]] = None,
) -> str:
    normalized = _mask_data_slots(raw, masked_slot_widths or {})
    digest = hashlib.sha256()
    cursor = 0
    while cursor + pointer_size <= len(normalized):
        chunk = normalized[cursor : cursor + pointer_size]
        value = int.from_bytes(chunk, byteorder=byteorder, signed=False)
        target = address_names.get(value)
        if target:
            digest.update(
                b"PTR\0"
                + target.encode("utf-8", errors="backslashreplace")
                + b"\0"
            )
        else:
            digest.update(b"RAW\0" + chunk)
        cursor += pointer_size
    digest.update(normalized[cursor:])
    return digest.hexdigest()


def _unattributed_data_summary(raw: bytes) -> UnattributedDataSummary:
    strings: List[bytes] = []
    opaque = bytearray(raw)
    for match in re.finditer(rb"[\x20-\x7e]+\0", raw):
        strings.append(match.group()[:-1])
        opaque[match.start() : match.end()] = b"\0" * (match.end() - match.start())
    strings.sort()
    opaque_bytes = bytes(opaque).rstrip(b"\0")
    string_digest = hashlib.sha256(b"\0".join(strings)).hexdigest()
    return UnattributedDataSummary(
        normalized_size=len(raw.rstrip(b"\0")),
        printable_strings=tuple(strings),
        printable_strings_sha256=string_digest,
        opaque_size=len(opaque_bytes),
        opaque_sha256=hashlib.sha256(opaque_bytes).hexdigest(),
    )


def _selected_data_sections(
    elf: Any, ignored_patterns: Sequence[str]
) -> Dict[str, Any]:
    return {
        section.name: section
        for section in elf.sections
        if section.index != 0
        and section.flags & SHF_ALLOC
        and _matches_any(section.name, DATA_SECTION_PATTERNS)
        and not _matches_any(section.name, ignored_patterns)
    }


def _relocation_width(elf: Any, relocation: Any) -> int:
    return DATA_RELOCATION_WIDTHS.get(elf.machine, {}).get(
        relocation.type, 0
    )


def _section_data_cached(
    elf: Any, section: Any, cache: Optional[Dict[int, bytes]]
) -> bytes:
    if cache is None:
        return elf.section_data(section)
    data = cache.get(section.index)
    if data is None:
        data = elf.section_data(section)
        cache[section.index] = data
    return data


def _relocation_effective_addend(
    elf: Any,
    relocation: Any,
    section_data_cache: Optional[Dict[int, bytes]] = None,
) -> Optional[int]:
    if relocation.addend is not None:
        return relocation.addend
    width = _relocation_width(elf, relocation)
    if not width or not 0 <= relocation.target_section_index < len(elf.sections):
        return None
    section = elf.sections[relocation.target_section_index]
    data = _section_data_cached(elf, section, section_data_cache)
    start = relocation.offset
    end = start + width
    if start < 0 or end > len(data):
        return None
    byteorder = "little" if elf.display_endian == "little" else "big"
    signed_types = {
        EM_386: {2},
        EM_X86_64: {2, 4, 11},
        EM_AARCH64: {260, 261},
    }
    return int.from_bytes(
        data[start:end],
        byteorder=byteorder,
        signed=relocation.type in signed_types.get(elf.machine, set()),
    )


def _relocation_string_target(
    elf: Any,
    relocation: Any,
    path_maps: Sequence[Tuple[str, str]],
    addend: Optional[int] = None,
    section_data_cache: Optional[Dict[int, bytes]] = None,
) -> Optional[str]:
    if addend is None:
        addend = _relocation_effective_addend(
            elf, relocation, section_data_cache
        )
    if addend is None:
        return None
    target_section = None
    target_offset = None
    if (
        elf.type == ET_REL
        and 0 < relocation.symbol_section_index < len(elf.sections)
    ):
        target_section = elf.sections[relocation.symbol_section_index]
        if target_section.flags & SHF_EXECINSTR:
            return None
        target_offset = relocation.symbol_value + addend
    else:
        address = relocation.symbol_value + addend
        candidates = [
            candidate
            for candidate in elf.sections
            if candidate.index != 0
            and candidate.flags & SHF_ALLOC
            and not candidate.flags & SHF_EXECINSTR
            and candidate.type != SHT_NOBITS
            and candidate.addr <= address < candidate.addr + candidate.size
        ]
        if candidates:
            target_section = min(candidates, key=lambda item: item.size)
            target_offset = address - target_section.addr
    if target_section is None or target_offset is None:
        return None
    data = _section_data_cached(elf, target_section, section_data_cache)
    if not (0 <= target_offset < len(data)):
        return None
    end = data.find(b"\0", target_offset, min(len(data), target_offset + 4096))
    if end < 0:
        return None
    value = _normalize_paths(data[target_offset:end], path_maps)
    if not value or any(byte < 0x20 or byte > 0x7E for byte in value):
        return None
    return "string:" + value.decode("ascii")


def _relocation_symbol_target(
    elf: Any,
    relocation: Any,
    symbol_targets: _SymbolTargetIndex,
    addend: Optional[int] = None,
    section_data_cache: Optional[Dict[int, bytes]] = None,
) -> Optional[str]:
    if addend is None:
        addend = _relocation_effective_addend(
            elf, relocation, section_data_cache
        )
    if addend is None:
        return None
    address = relocation.symbol_value + addend
    scoped_section = (
        relocation.symbol_section_index if elf.type == ET_REL else None
    )
    target = symbol_targets.target(scoped_section, address)
    if target is None:
        return None
    return f"symbol:{target}"


def _relocation_target_identity(
    elf: Any,
    relocation: Any,
    path_maps: Sequence[Tuple[str, str]],
    symbol_targets: _SymbolTargetIndex,
    section_data_cache: Optional[Dict[int, bytes]] = None,
) -> Tuple[Any, bool]:
    addend = _relocation_effective_addend(
        elf, relocation, section_data_cache
    )
    string_target = _relocation_string_target(
        elf, relocation, path_maps, addend, section_data_cache
    )
    if string_target is not None:
        return string_target, True
    if relocation.symbol_name:
        if addend is None:
            return f"symbol:{relocation.symbol_name}", False
        suffix = f"{addend:+#x}" if addend else ""
        return f"symbol:{relocation.symbol_name}{suffix}", True
    symbol_target = _relocation_symbol_target(
        elf, relocation, symbol_targets, addend, section_data_cache
    )
    if symbol_target is not None:
        return symbol_target, True
    return addend, False


def _unowned_relocation_target(
    elf: Any,
    relocation: Any,
    path_maps: Sequence[Tuple[str, str]],
    section_data_cache: Optional[Dict[int, bytes]] = None,
) -> Any:
    """Preserve conservative legacy evidence when no data owner is known."""

    addend = _relocation_effective_addend(
        elf, relocation, section_data_cache
    )
    string_target = _relocation_string_target(
        elf, relocation, path_maps, addend, section_data_cache
    )
    return string_target if string_target is not None else addend


def _bounded_relocation_detail(
    left: Sequence[Tuple[Any, ...]],
    right: Sequence[Tuple[Any, ...]],
    describe: Callable[[str, Tuple[Any, ...]], str],
    limit_per_side: int,
    footer: Optional[str] = None,
) -> str:
    left_only = sorted(set(left) - set(right), key=repr)
    right_only = sorted(set(right) - set(left), key=repr)
    lines = [
        describe("Make", item) for item in left_only[:limit_per_side]
    ]
    lines.extend(
        describe("Bazel", item) for item in right_only[:limit_per_side]
    )
    omitted = max(0, len(left_only) - limit_per_side) + max(
        0, len(right_only) - limit_per_side
    )
    if omitted:
        lines.append(f"... {omitted} more unmatched relocation(s)")
    if footer:
        lines.append(footer)
    return "\n".join(lines)


def unattributed_relocation_detail(
    left: Sequence[Tuple[Any, ...]],
    right: Sequence[Tuple[Any, ...]],
    limit_per_side: int = 5,
) -> str:
    """Render actionable samples for relocations outside named data symbols."""

    def describe(side: str, item: Tuple[Any, ...]) -> str:
        section, offset, relocation_type, symbol, target = item
        target_text = f", target={target}" if target is not None else ""
        return (
            f"{side}-only {section}+0x{offset:x}: type={relocation_type}, "
            f"symbol={symbol or '<none>'}{target_text}"
        )

    return _bounded_relocation_detail(
        left,
        right,
        describe,
        limit_per_side,
        "Relocations differ outside named data symbols; ownership cannot be "
        "normalized safely.",
    )


def data_symbol_relocation_detail(
    left: Sequence[Tuple[Any, ...]],
    right: Sequence[Tuple[Any, ...]],
    limit_per_side: int = 5,
) -> str:
    """Render bounded semantic relocation differences within one data object."""

    def describe(side: str, item: Tuple[Any, ...]) -> str:
        offset, relocation_type, symbol, target = item
        target_text = f", target={target}" if target is not None else ""
        return (
            f"{side}-only slot+0x{offset:x}: type={relocation_type}, "
            f"symbol={symbol or '<none>'}{target_text}"
        )

    return _bounded_relocation_detail(
        left, right, describe, limit_per_side
    )


def compare_data_sections(
    left_elf: Any,
    right_elf: Any,
    ignored_patterns: Sequence[str],
    left_path_maps: Sequence[Tuple[str, str]] = (),
    right_path_maps: Sequence[Tuple[str, str]] = (),
    dynamic_symbols_only: bool = False,
) -> List[Finding]:
    findings: List[Finding] = []
    left_sections = _selected_data_sections(left_elf, ignored_patterns)
    right_sections = _selected_data_sections(right_elf, ignored_patterns)

    def symbol_records(
        elf: Any, sections: Dict[str, Any], path_maps: Sequence[Tuple[str, str]]
    ) -> Tuple[
        Dict[Tuple[Any, ...], Dict[str, Any]],
        Dict[str, List[Tuple[int, int]]],
        List[Tuple[Any, ...]],
    ]:
        all_symbols = elf.dynamic_symbols() if dynamic_symbols_only else elf.symbols()
        all_relocations = [
            relocation
            for relocation in elf.relocations()
            if elf.sections[relocation.target_section_index].name in sections
        ]
        symbol_targets = _SymbolTargetIndex.build(elf, all_symbols)
        address_groups: Dict[int, List[Any]] = {}
        for symbol in all_symbols:
            if symbol.name and 0 < symbol.shndx < len(elf.sections):
                address_groups.setdefault(symbol.value, []).append(symbol)
        address_names = {}
        for address, aliases in address_groups.items():
            preferred, _ = _preferred_function_aliases(aliases)
            address_names[address] = min(
                symbol.name for symbol in preferred
            )
        indexed_relocations: Dict[
            int, List[Tuple[int, int, Any]]
        ] = {}
        for index, relocation in enumerate(all_relocations):
            indexed_relocations.setdefault(
                relocation.target_section_index, []
            ).append((relocation.offset, index, relocation))
        relocation_offsets: Dict[int, Tuple[int, ...]] = {}
        for section_index, items in indexed_relocations.items():
            items.sort(key=lambda item: (item[0], item[1]))
            relocation_offsets[section_index] = tuple(
                item[0] for item in items
            )
        owned_relocation_indices = set()
        section_data_cache: Dict[int, bytes] = {}
        occurrences: Dict[Tuple[Any, ...], int] = {}
        records: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        covered: Dict[str, List[Tuple[int, int]]] = {}
        byteorder = "little" if elf.display_endian == "little" else "big"
        pointer_size = 4 if elf.display_class == "ELF32" else 8

        for symbol in all_symbols:
            if (
                symbol.type not in (1, 6)  # STT_OBJECT, STT_TLS
                or not symbol.name
                or symbol.size == 0
                or symbol.shndx <= 0
                or symbol.shndx >= len(elf.sections)
            ):
                continue
            section = elf.sections[symbol.shndx]
            if section.name not in sections:
                continue
            relative = symbol.value if elf.type == 1 else symbol.value - section.addr
            if relative < 0 or relative + symbol.size > section.size:
                findings.append(
                    Finding(
                        "ERROR",
                        "data",
                        f"symbol:{symbol.name}",
                        "valid section range",
                        f"offset={relative}, size={symbol.size}",
                    )
                )
                continue
            covered.setdefault(section.name, []).append((relative, relative + symbol.size))
            section_relocations = indexed_relocations.get(symbol.shndx, [])
            offsets = relocation_offsets.get(symbol.shndx, ())
            first = bisect_left(offsets, relative)
            last = bisect_left(offsets, relative + symbol.size)
            owned_entries = section_relocations[first:last]
            owned_relocation_indices.update(
                index for _, index, _ in owned_entries
            )
            owned_relocations = [
                relocation for _, _, relocation in owned_entries
            ]
            if section.type == SHT_NOBITS:
                digest = hashlib.sha256(f"zero:{symbol.size}".encode()).hexdigest()
                raw = None
            else:
                raw_buffer = bytearray(
                    _section_data_cached(
                        elf, section, section_data_cache
                    )[relative : relative + symbol.size]
                )
                for relocation in owned_relocations:
                    width = _relocation_width(elf, relocation)
                    start = relocation.offset - relative
                    if not width:
                        # The unknown slot is excluded from confirmed byte
                        # differences, but remains an explicit coverage error.
                        width = pointer_size
                    if width:
                        end = min(start + width, len(raw_buffer))
                        raw_buffer[start:end] = b"\0" * (end - start)
                raw = _normalize_paths(bytes(raw_buffer), path_maps)
                digest = _normalized_data_digest(
                    raw, pointer_size, byteorder, address_names
                )
            relocation_records = []
            resolved_relocations = []
            unresolved_relocations = []
            unsupported_relocations = []
            uncertain_slot_widths: Dict[int, int] = {}
            for relocation in owned_relocations:
                target, resolved = _relocation_target_identity(
                    elf,
                    relocation,
                    path_maps,
                    symbol_targets,
                    section_data_cache,
                )
                record = (
                    relocation.offset - relative,
                    relocation.type,
                    relocation.symbol_name,
                    target,
                )
                relocation_records.append(record)
                relocation_width = _relocation_width(elf, relocation)
                slot = relocation.offset - relative
                if not relocation_width:
                    unsupported_relocations.append(record)
                    uncertain_slot_widths[slot] = max(
                        uncertain_slot_widths.get(slot, 0), pointer_size
                    )
                elif resolved:
                    resolved_relocations.append(record)
                else:
                    unresolved_relocations.append(record)
                    uncertain_slot_widths[slot] = max(
                        uncertain_slot_widths.get(slot, 0), relocation_width
                    )
            symbol_relocations = tuple(
                sorted(relocation_records, key=repr)
            )
            unresolved_relocations_tuple = tuple(
                sorted(unresolved_relocations, key=repr)
            )
            resolved_relocations_tuple = tuple(
                sorted(resolved_relocations, key=repr)
            )
            unsupported_relocations_tuple = tuple(
                sorted(unsupported_relocations, key=repr)
            )
            content_digest = digest
            if symbol_relocations:
                relocation_digest = hashlib.sha256()
                relocation_digest.update(digest.encode())
                relocation_digest.update(repr(symbol_relocations).encode())
                digest = relocation_digest.hexdigest()
            base_key = (symbol.name, symbol.type, symbol.binding)
            occurrence = occurrences.get(base_key, 0)
            occurrences[base_key] = occurrence + 1
            key = base_key + (occurrence,)
            records[key] = {
                "section": section.name,
                "section_flags": section.flags,
                "size": len(raw) if raw is not None else symbol.size,
                "sha256": digest,
                "content_sha256": content_digest,
                "relocations": symbol_relocations,
                "resolved_relocations": resolved_relocations_tuple,
                "unresolved_relocations": unresolved_relocations_tuple,
                "unsupported_relocations": unsupported_relocations_tuple,
                "raw": raw,
                "_pointer_size": pointer_size,
                "_byteorder": byteorder,
                "_address_names": address_names,
                "_uncertain_slot_widths": uncertain_slot_widths,
            }
        unowned_relocations = []
        for index, relocation in enumerate(all_relocations):
            section_name = elf.sections[relocation.target_section_index].name
            if index not in owned_relocation_indices:
                unowned_relocations.append(
                    (
                        section_name,
                        relocation.offset,
                        relocation.type,
                        relocation.symbol_name,
                        _unowned_relocation_target(
                            elf,
                            relocation,
                            path_maps,
                            section_data_cache,
                        ),
                    )
                )
        return records, covered, sorted(unowned_relocations, key=repr)

    left_records, left_covered, left_unowned_relocations = symbol_records(
        left_elf, left_sections, left_path_maps
    )
    right_records, right_covered, right_unowned_relocations = symbol_records(
        right_elf, right_sections, right_path_maps
    )
    for key in sorted(set(left_records) | set(right_records)):
        name = key[0] if key[3] == 0 else f"{key[0]}#{key[3] + 1}"
        left_record = left_records.get(key)
        right_record = right_records.get(key)
        if left_record is None or right_record is None:
            findings.append(
                Finding(
                    "FAIL",
                    "data-symbol",
                    name,
                    "<missing>" if left_record is None else "<present>",
                    "<missing>" if right_record is None else "<present>",
                )
            )
            continue
        comparable_left = {
            item: value
            for item, value in left_record.items()
            if item != "raw" and not item.startswith("_")
        }
        comparable_right = {
            item: value
            for item, value in right_record.items()
            if item != "raw" and not item.startswith("_")
        }
        unsupported_present = bool(
            left_record["unsupported_relocations"]
            or right_record["unsupported_relocations"]
        )
        unresolved_present = bool(
            left_record["unresolved_relocations"]
            or right_record["unresolved_relocations"]
        )
        uncertain_slot_widths: Dict[int, int] = {}
        for slot_widths in (
            left_record["_uncertain_slot_widths"],
            right_record["_uncertain_slot_widths"],
        ):
            for slot, width in slot_widths.items():
                uncertain_slot_widths[slot] = max(
                    uncertain_slot_widths.get(slot, 0), width
                )
        uncertain_slots = set(uncertain_slot_widths)
        comparable_left_resolved = tuple(
            item
            for item in left_record["resolved_relocations"]
            if item[0] not in uncertain_slots
        )
        comparable_right_resolved = tuple(
            item
            for item in right_record["resolved_relocations"]
            if item[0] not in uncertain_slots
        )
        if (
            comparable_left != comparable_right
            or unsupported_present
            or unresolved_present
        ):
            content_detail_parts = []
            left_raw = left_record["raw"]
            right_raw = right_record["raw"]
            left_comparison_raw = (
                _mask_data_slots(
                    left_raw,
                    uncertain_slot_widths,
                )
                if left_raw is not None
                else None
            )
            right_comparison_raw = (
                _mask_data_slots(
                    right_raw,
                    uncertain_slot_widths,
                )
                if right_raw is not None
                else None
            )
            if (
                left_comparison_raw is not None
                and right_comparison_raw is not None
            ):
                mismatch = next(
                    (
                        index
                        for index, pair in enumerate(
                            zip(left_comparison_raw, right_comparison_raw)
                        )
                        if pair[0] != pair[1]
                    ),
                    min(len(left_comparison_raw), len(right_comparison_raw))
                    if len(left_comparison_raw) != len(right_comparison_raw)
                    else None,
                )
                if mismatch is not None:
                    left_byte = (
                        left_comparison_raw[mismatch]
                        if mismatch < len(left_comparison_raw)
                        else "<end>"
                    )
                    right_byte = (
                        right_comparison_raw[mismatch]
                        if mismatch < len(right_comparison_raw)
                        else "<end>"
                    )
                    content_detail_parts.append(
                        "first differing byte at symbol offset "
                        f"0x{mismatch:x}: {left_byte!r} -> {right_byte!r}"
                    )
            resolved_differs = (
                comparable_left_resolved != comparable_right_resolved
            )
            unresolved_differs = (
                left_record["unresolved_relocations"]
                != right_record["unresolved_relocations"]
            )
            if resolved_differs:
                content_detail_parts.append(
                    data_symbol_relocation_detail(
                        comparable_left_resolved,
                        comparable_right_resolved,
                    )
                )
            left_content_digest = (
                _normalized_data_digest(
                    left_raw,
                    left_record["_pointer_size"],
                    left_record["_byteorder"],
                    left_record["_address_names"],
                    uncertain_slot_widths,
                )
                if left_raw is not None
                else left_record["content_sha256"]
            )
            right_content_digest = (
                _normalized_data_digest(
                    right_raw,
                    right_record["_pointer_size"],
                    right_record["_byteorder"],
                    right_record["_address_names"],
                    uncertain_slot_widths,
                )
                if right_raw is not None
                else right_record["content_sha256"]
            )
            content_keys = ("section", "section_flags", "size")
            content_differs = any(
                left_record[key] != right_record[key] for key in content_keys
            ) or left_content_digest != right_content_digest
            if content_differs or resolved_differs:
                finding_left = dict(comparable_left)
                finding_right = dict(comparable_right)
                finding_left["content_sha256"] = left_content_digest
                finding_right["content_sha256"] = right_content_digest
                findings.append(
                    Finding(
                        "FAIL",
                        "data-symbol",
                        name,
                        finding_left,
                        finding_right,
                        "\n".join(
                            part for part in content_detail_parts if part
                        )
                        or None,
                    )
                )
            if unresolved_present or unsupported_present:
                coverage_details = []
                if unresolved_present:
                    coverage_details.append(
                        "Unresolved relocation target(s): "
                        f"Make={len(left_record['unresolved_relocations'])}, "
                        f"Bazel={len(right_record['unresolved_relocations'])}."
                    )
                if unresolved_differs:
                    coverage_details.append(
                        data_symbol_relocation_detail(
                            left_record["unresolved_relocations"],
                            right_record["unresolved_relocations"],
                        )
                    )
                if unsupported_present:
                    left_types = sorted(
                        {
                            item[1]
                            for item in left_record[
                                "unsupported_relocations"
                            ]
                        }
                    )
                    right_types = sorted(
                        {
                            item[1]
                            for item in right_record[
                                "unsupported_relocations"
                            ]
                        }
                    )
                    coverage_details.append(
                        "Unsupported relocation type(s): "
                        f"Make={left_types or '<none>'}, "
                        f"Bazel={right_types or '<none>'}."
                    )
                findings.append(
                    Finding(
                        "ERROR",
                        "data-relocation-coverage",
                        name,
                        {
                            "section": left_record["section"],
                            "unresolved_relocations": left_record[
                                "unresolved_relocations"
                            ],
                            "unsupported_relocations": left_record[
                                "unsupported_relocations"
                            ],
                        },
                        {
                            "section": right_record["section"],
                            "unresolved_relocations": right_record[
                                "unresolved_relocations"
                            ],
                            "unsupported_relocations": right_record[
                                "unsupported_relocations"
                            ],
                        },
                        (
                            "At least one owned-data relocation cannot be "
                            "normalized safely.\n"
                            + "\n".join(
                                detail for detail in coverage_details if detail
                            )
                        ),
                    )
                )

    if left_unowned_relocations != right_unowned_relocations:
        findings.append(
            Finding(
                "ERROR",
                "unattributed-relocation",
                "allocated data relocation",
                left_unowned_relocations,
                right_unowned_relocations,
                unattributed_relocation_detail(
                    left_unowned_relocations, right_unowned_relocations
                ),
            )
        )

    # Bytes not owned by a data symbol cannot be safely classified. Ignore only
    # trailing zero padding; otherwise force an incomplete result with an offset.
    for name in sorted(set(left_sections) | set(right_sections)):
        left_section = left_sections.get(name)
        right_section = right_sections.get(name)
        if left_section is None or right_section is None:
            findings.append(Finding("ERROR", "unattributed-data", name, "<missing>" if left_section is None else "<present>", "<missing>" if right_section is None else "<present>"))
            continue
        if left_section.type == SHT_NOBITS and right_section.type == SHT_NOBITS:
            continue
        left_residual = bytearray(left_elf.section_data(left_section))
        right_residual = bytearray(right_elf.section_data(right_section))
        for start, end in left_covered.get(name, []):
            left_residual[start:end] = b"\0" * (end - start)
        for start, end in right_covered.get(name, []):
            right_residual[start:end] = b"\0" * (end - start)
        left_mapped = _normalize_paths(bytes(left_residual), left_path_maps)
        right_mapped = _normalize_paths(bytes(right_residual), right_path_maps)
        left_normalized = left_mapped.rstrip(b"\0")
        right_normalized = right_mapped.rstrip(b"\0")
        if left_normalized != right_normalized:
            left_summary = _unattributed_data_summary(left_mapped)
            right_summary = _unattributed_data_summary(right_mapped)
            strings_equal = (
                left_summary.printable_strings == right_summary.printable_strings
            )
            mismatch = next(
                (index for index, pair in enumerate(zip(left_normalized, right_normalized)) if pair[0] != pair[1]),
                min(len(left_normalized), len(right_normalized)),
            )
            findings.append(
                Finding(
                    "ERROR",
                    "unattributed-data",
                    name,
                    left_summary.as_dict(strings_equal),
                    right_summary.as_dict(strings_equal),
                    (
                        "normalized printable string multisets match after path mapping; "
                        "remaining opaque bytes or layout first differ at section offset "
                        f"0x{mismatch:x}; cannot safely classify as semantic equality"
                        if strings_equal
                        else "normalized printable string multisets differ; unowned data first "
                        f"differs at section offset 0x{mismatch:x}"
                    ),
                )
            )
    return findings


def explain_section_coverage(
    elf: Any, ignored_patterns: Sequence[str]
) -> List[Dict[str, Any]]:
    """Classify every named section by the build-mode evidence it receives."""

    result: List[Dict[str, Any]] = []
    direct_reasons = {
        ".dynamic": "supported dynamic tags and dependency order are compared",
        ".dynsym": "public imports and exports are compared by stable symbol attributes",
        ".gnu.version_r": "runtime version providers and maximum version floors are compared",
    }
    evidence_names = {
        ".dynstr",
        ".strtab",
        ".symtab",
        ".gnu.version",
        ".interp",
    }
    intentionally_ignored = {".shstrtab"}
    known_uncovered = {
        ".eh_frame",
        ".eh_frame_hdr",
        ".gcc_except_table",
        ".gnu.hash",
        ".hash",
        ".gnu.version_d",
        ".got",
        ".got.plt",
    }
    selected_target_indices = {
        section.index
        for section in _selected_data_sections(elf, ignored_patterns).values()
    }
    selected_target_indices.update(
        section.index
        for section in _initialization_array_sections(
            elf, ignored_patterns
        ).values()
    )
    consumed_relocation_sections = {
        relocation.source_section_index
        for relocation in elf.relocations()
        if relocation.target_section_index in selected_target_indices
    }
    for section in elf.sections:
        if section.index == 0 or not section.name:
            continue
        name = section.name
        if name == ".comment":
            classification = "evidence"
            reason = "compiler strings are compared only for a non-decisive JSON note"
        elif _matches_any(name, ignored_patterns) or name in intentionally_ignored:
            classification = "ignored"
            reason = "build/debug/layout metadata intentionally excluded by policy"
        elif section.type in {
            SHT_INIT_ARRAY,
            SHT_FINI_ARRAY,
            SHT_PREINIT_ARRAY,
        }:
            classification = "compared"
            reason = "callback count and order are compared; unresolved targets cause incomplete coverage"
        elif (
            section.flags & SHF_ALLOC
            and _matches_any(name, DATA_SECTION_PATTERNS)
        ):
            classification = "compared"
            reason = "selected allocated data is compared by symbol and relocation"
        elif name == ".note.gnu.property":
            if elf.machine in (EM_386, EM_X86_64, EM_AARCH64):
                classification = "compared"
                reason = "supported GNU property hardening bits are compared directionally"
            else:
                classification = "uncovered"
                reason = "GNU property semantics are not implemented for this architecture"
        elif name in direct_reasons:
            classification = "compared"
            reason = direct_reasons[name]
        elif name.startswith((".rela", ".rel")):
            if section.index in consumed_relocation_sections:
                classification = "evidence"
                reason = "at least one entry targets selected data or a callback array"
            else:
                classification = "uncovered"
                reason = "no entry is consumed by a current semantic comparison rule"
        elif name in evidence_names:
            classification = "evidence"
            reason = "used to interpret symbols, versions, or runtime metadata"
        elif _is_plt_section(name):
            classification = "evidence"
            reason = "excluded from function presence; loader table is not independently validated"
        elif section.flags & SHF_EXECINSTR:
            classification = "compared"
            reason = "function presence is compared; matched instructions are ignored"
        elif name in known_uncovered:
            classification = "uncovered"
            reason = "not currently normalized into the consistency decision"
        else:
            classification = "uncovered"
            reason = "no current semantic comparison rule"
        result.append(
            {
                "section": name,
                "index": section.index,
                "classification": classification,
                "reason": reason,
            }
        )
    return result


def render_coverage_explanation(report: Dict[str, Any]) -> str:
    lines = [f"Section coverage: {report['artifact']}"]
    for item in report["sections"]:
        lines.append(
            f"  [{item['classification']}] {item['section']} "
            f"[#{item['index']}]: {item['reason']}"
        )
    counts = report["summary"]
    lines.append(
        "Summary: "
        + ", ".join(
            f"{counts.get(name, 0)} {name}"
            for name in ("compared", "evidence", "ignored", "uncovered")
        )
    )
    return "\n".join(lines)


def _save_output(report_dir: Optional[str], result: CommandResult) -> Optional[str]:
    if not report_dir:
        return None
    os.makedirs(report_dir, exist_ok=True)
    path = os.path.join(report_dir, result.name.replace("/", "_") + ".txt")
    with open(path, "w", encoding="utf-8") as stream:
        stream.write("$ " + shlex.join(result.command) + "\n\n")
        stream.write(result.stdout)
        if result.stderr:
            stream.write("\n[stderr]\n" + result.stderr)
    return os.path.abspath(path)


def _run_readelf(
    runner: ToolRunner, command: Sequence[str], path: str, side: str
) -> CommandResult:
    return runner.run(
        f"readelf-{side}",
        list(command)
        + ["-h", "-l", "-d", "-n", "-s", "--version-info", "-W", path],
    )


def _tool_failure(result: CommandResult) -> Finding:
    detail = result.stderr.strip() or result.stdout.strip() or "tool returned no diagnostic"
    return Finding(
        "ERROR",
        "tool",
        result.name,
        "available",
        f"exit {result.returncode}",
        detail[:2000],
    )


def _abidiff_reports_only_export_surface_changes(output: str) -> bool:
    """Return true only when abidiff explicitly reports no changed interfaces.

    Added and removed functions or variables duplicate the dynamic export
    comparison. A non-zero ``Changed`` count represents the signature/type
    evidence for which abidiff is retained. Unknown output stays conservative
    and is not de-duplicated.
    """

    changed_counts: Dict[str, int] = {}
    pattern = re.compile(
        r"^(Functions|Variables) changes summary:.*?\b(\d+)\s+Changed\b",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        changed_counts[match.group(1)] = int(match.group(2))
    return (
        set(changed_counts) == {"Functions", "Variables"}
        and all(count == 0 for count in changed_counts.values())
    )


def _record_paired_results(
    results: Sequence[CommandResult],
    executions: List[Dict[str, Any]],
    findings: List[Finding],
    report_dir: Optional[str],
) -> bool:
    succeeded = True
    for result in results:
        executions.append(result.as_dict(_save_output(report_dir, result)))
        if result.returncode != 0:
            findings.append(_tool_failure(result))
            succeeded = False
    return succeeded


def compare_build(
    left_path: str,
    right_path: str,
    left_elf: Any,
    right_elf: Any,
    ignored_patterns: Sequence[str],
    args: Any,
    runner: Optional[ToolRunner] = None,
) -> Tuple[Dict[str, Any], int]:
    runner = runner or ToolRunner(args.timeout)
    tools = discover_tools(args)
    findings: List[Finding] = []
    executions: List[Dict[str, Any]] = []
    missing: List[str] = []
    if args.report_dir:
        os.makedirs(args.report_dir, exist_ok=True)

    both_dynamic = left_elf.type == 3 and right_elf.type == 3
    has_program_interpreter = any(
        program.type == PT_INTERP
        for elf in (left_elf, right_elf)
        for program in elf.program_headers
    )
    looks_like_shared_library = both_dynamic and not has_program_interpreter
    should_check_abi = (
        "abidiff" in args.require_tool
        or args.abi == "always"
        or (args.abi == "auto" and looks_like_shared_library)
    )
    skip_function_presence = bool(
        getattr(args, "skip_function_bodies", False)
    )
    required = ["readelf"]
    if args.level == "deep":
        required.extend(("elf_diff", "diffoscope"))
    if should_check_abi:
        required.append("abidiff")
    required.extend(args.require_tool)
    for name in dict.fromkeys(required):
        if tools.get(name) is None:
            missing.append(name)
            findings.append(
                Finding("ERROR", "coverage", name, "required", "missing", "Install it or pass its path explicitly.")
            )

    def has_section(elf: Any, name: str) -> bool:
        return any(section.name == name for section in elf.sections)

    strip_profile_mismatch = any(
        has_section(left_elf, name) != has_section(right_elf, name)
        for name in (".symtab", ".strtab")
    )
    if strip_profile_mismatch:
        findings.append(
            Finding(
                "ERROR",
                "coverage",
                "strip-profile",
                {
                    ".symtab": has_section(left_elf, ".symtab"),
                    ".strtab": has_section(left_elf, ".strtab"),
                },
                {
                    ".symtab": has_section(right_elf, ".symtab"),
                    ".strtab": has_section(right_elf, ".strtab"),
                },
                "The artifacts have different strip levels; function-presence coverage would be asymmetric. Compare equally stripped artifacts or retain symbols on both sides.",
            )
        )

    # These checks do not depend on external tools and always run. When strip
    # levels differ, use only .dynsym on both sides to keep symbol coverage
    # symmetric; the strip-profile finding records the lost local coverage.
    findings.extend(
        compare_data_sections(
            left_elf,
            right_elf,
            ignored_patterns,
            left_path_maps=args.left_path_map,
            right_path_maps=args.right_path_map,
            dynamic_symbols_only=strip_profile_mismatch,
        )
    )
    findings.extend(
        compare_initialization_arrays(
            left_elf,
            right_elf,
            ignored_patterns,
        )
    )

    readelf = tools.get("readelf")
    if readelf:
        left_readelf = _run_readelf(runner, readelf, left_path, "make")
        right_readelf = _run_readelf(runner, readelf, right_path, "bazel")
        if _record_paired_results(
            (left_readelf, right_readelf), executions, findings, args.report_dir
        ):
            left_dynamic_symbols = {
                section.name
                for section in left_elf.sections
                if section.type == SHT_DYNSYM
            } or {".dynsym"}
            right_dynamic_symbols = {
                section.name
                for section in right_elf.sections
                if section.type == SHT_DYNSYM
            } or {".dynsym"}
            left_contract = parse_readelf_contract(
                left_readelf.stdout, left_dynamic_symbols
            )
            right_contract = parse_readelf_contract(
                right_readelf.stdout, right_dynamic_symbols
            )
            required_contract_keys = ("elf.class", "elf.machine", "elf.type")
            for side, contract in (("make", left_contract), ("bazel", right_contract)):
                missing_keys = [key for key in required_contract_keys if key not in contract]
                if missing_keys:
                    findings.append(
                        Finding(
                            "ERROR",
                            "coverage",
                            f"readelf-{side}-parse",
                            "required fields",
                            missing_keys,
                            "readelf succeeded but its output was not understood",
                        )
                    )
            if all(key in left_contract and key in right_contract for key in required_contract_keys):
                findings.extend(
                    compare_contracts(
                        left_contract,
                        right_contract,
                        allow_extra_needed=args.allow_extra_needed,
                        allow_needed_reorder=args.allow_needed_reorder,
                    )
                )
            if not skip_function_presence and not strip_profile_mismatch:
                left_functions = parse_readelf_function_symbols(
                    left_readelf.stdout, left_elf
                )
                right_functions = parse_readelf_function_symbols(
                    right_readelf.stdout, right_elf
                )
                left_has_executable_content = any(
                    section.flags & SHF_EXECINSTR
                    and section.size
                    and not _is_plt_section(section.name)
                    for section in left_elf.sections
                )
                right_has_executable_content = any(
                    section.flags & SHF_EXECINSTR
                    and section.size
                    and not _is_plt_section(section.name)
                    for section in right_elf.sections
                )
                if (
                    left_has_executable_content and not left_functions
                ) or (
                    right_has_executable_content and not right_functions
                ):
                    findings.append(
                        Finding(
                            "ERROR",
                            "coverage",
                            "readelf-functions",
                            len(left_functions),
                            len(right_functions),
                            "executable sections exist but readelf did not provide a comparable function inventory",
                        )
                    )
                else:
                    findings.extend(
                        compare_functions(left_functions, right_functions)
                    )

    eu_elfcmp = tools.get("eu-elfcmp")
    if eu_elfcmp:
        result = runner.run(
            "eu-elfcmp",
            list(eu_elfcmp) + ["--ignore-build-id", "--gaps=ignore", "-l", left_path, right_path],
        )
        executions.append(result.as_dict(_save_output(args.report_dir, result)))
        if result.returncode == 1:
            findings.append(
                Finding(
                    "INFO",
                    "elf-layout",
                    "eu-elfcmp",
                    "make ELF",
                    "bazel ELF",
                    (result.stderr or result.stdout).strip()[:4000],
                )
            )
        elif result.returncode not in (0, 1):
            findings.append(_tool_failure(result))

    abidiff = tools.get("abidiff")
    if should_check_abi:
        if abidiff:
            result = runner.run("abidiff", list(abidiff) + [left_path, right_path])
            executions.append(result.as_dict(_save_output(args.report_dir, result)))
            if result.returncode & 3:
                findings.append(_tool_failure(result))
            elif result.returncode & 12:
                export_surface_changed = any(
                    finding.severity == "FAIL"
                    and finding.category.startswith("symbols-exported-")
                    for finding in findings
                )
                duplicate_export_evidence = (
                    export_surface_changed
                    and _abidiff_reports_only_export_surface_changes(
                        result.stdout
                    )
                )
                if not duplicate_export_evidence:
                    findings.append(
                        Finding(
                            "FAIL",
                            "abi",
                            "exported ABI",
                            "make ABI",
                            "bazel ABI",
                            result.stdout.strip()[:8000],
                        )
                    )
        else:
            # The required-tool pass above already records this as ERROR.
            pass

    run_elf_diff = args.level == "deep" or "elf_diff" in args.require_tool
    if run_elf_diff and tools.get("elf_diff"):
        if not args.report_dir:
            findings.append(Finding("ERROR", "coverage", "elf_diff", "report directory", "missing"))
        else:
            elf_diff_json = os.path.join(args.report_dir, "elf_diff.json")
            result = runner.run(
                "elf_diff",
                list(tools["elf_diff"] or []) + ["--json_file", elf_diff_json, left_path, right_path],
            )
            executions.append(result.as_dict(_save_output(args.report_dir, result)))
            if result.returncode != 0:
                findings.append(_tool_failure(result))

    run_diffoscope = args.level == "deep" or "diffoscope" in args.require_tool
    if run_diffoscope and tools.get("diffoscope"):
        if not args.report_dir:
            findings.append(Finding("ERROR", "coverage", "diffoscope", "report directory", "missing"))
        else:
            text_path = os.path.join(args.report_dir, "diffoscope.txt")
            html_path = os.path.join(args.report_dir, "diffoscope.html")
            result = runner.run(
                "diffoscope",
                list(tools["diffoscope"] or [])
                + ["--text", text_path, "--html", html_path, left_path, right_path],
            )
            executions.append(result.as_dict(_save_output(args.report_dir, result)))
            if result.returncode not in (0, 1):
                findings.append(_tool_failure(result))

    has_error = bool(missing) or any(item.severity == "ERROR" for item in findings)
    has_failure = any(item.severity == "FAIL" for item in findings)
    if has_failure:
        status = "DIFFERENT"
        exit_code = EXIT_DIFFERENT
        equal: Optional[bool] = False
    elif has_error:
        status = "INCOMPLETE"
        exit_code = EXIT_INCOMPLETE
        equal = None
    else:
        status = "CONSISTENT"
        exit_code = EXIT_CONSISTENT
        equal = True

    report = {
        "mode": "build",
        "level": args.level,
        "status": status,
        "equal": equal,
        "definition": (
            "Same runtime contract, supported security properties, selected "
            "allocated data, and ordered loader callback arrays; function "
            "presence comparison was explicitly skipped."
            if skip_function_presence
            else "Same runtime contract, supported security properties, "
            "function presence, selected allocated data, and ordered loader "
            "callback arrays. Matched function instructions are ignored."
        ),
        "left": {"role": "make", "path": os.path.abspath(left_path), "sha256": left_elf.sha256},
        "right": {"role": "bazel", "path": os.path.abspath(right_path), "sha256": right_elf.sha256},
        "coverage": {
            "required_tools": list(dict.fromkeys(required)),
            "missing_tools": missing,
            "available_tools": sorted(name for name, command in tools.items() if command),
            "skipped_checks": (
                ["function-presence"] if skip_function_presence else []
            ),
        },
        "summary": {
            "fail": sum(item.severity == "FAIL" for item in findings),
            "warn": sum(item.severity == "WARN" for item in findings),
            "info": sum(item.severity == "INFO" for item in findings),
            "error": sum(item.severity == "ERROR" for item in findings),
        },
        "groups": [group.as_dict() for group in group_findings(findings)],
        "findings": [item.as_dict() for item in findings],
        "tools": executions,
    }
    compiler_mismatch = compiler_comment_mismatch(left_elf, right_elf)
    if compiler_mismatch:
        report["compiler_version_mismatch"] = compiler_mismatch
    return report, exit_code


def group_findings(
    findings: Sequence[Finding], example_limit: int = 3
) -> List[FindingGroup]:
    """Group observable findings without inferring a shared root cause."""
    grouped: Dict[Tuple[str, str], List[str]] = {}
    for finding in findings:
        grouped.setdefault((finding.severity, finding.category), []).append(
            finding.path
        )
    severity_order = {"FAIL": 0, "ERROR": 1, "WARN": 2, "INFO": 3}
    ordered = sorted(
        grouped.items(),
        key=lambda item: (
            severity_order.get(item[0][0], 4),
            -len(item[1]),
            item[0][1],
        ),
    )
    return [
        FindingGroup(
            severity=severity,
            category=category,
            count=len(paths),
            examples=tuple(
                sorted(
                    {
                        summarize_finding_path(path, category)
                        for path in paths
                    }
                )[:example_limit]
            ),
        )
        for (severity, category), paths in ordered
    ]


def summarize_finding_path(path: str, category: Optional[str] = None) -> str:
    """Simplify known compiler-generated data symbols in summaries only."""

    if category != "data-symbol":
        return path
    match = re.fullmatch(
        r"(?P<base>_+PRETTY_FUNCTION_+|__func__|__FUNCTION__)"
        r"(?:\.\d+)?(?:#\d+)?",
        path,
    )
    return match.group("base") if match else path


def is_reportable_finding(finding: Dict[str, Any]) -> bool:
    """Return whether a finding belongs in user-facing reports."""

    category = finding.get("category")
    return (
        finding.get("severity") == "FAIL"
        and category not in OMITTED_REPORT_CATEGORIES
    )


def _finding_section(
    finding: Dict[str, Any], public_category: str
) -> Any:
    """Return the primary ELF location from which a finding was derived."""

    existing = finding.get("section")
    if existing is not None:
        return existing

    path = str(finding.get("path", finding.get("name", "")))
    if public_category == "startup-callback":
        match = re.match(r"(\.(?:preinit|init|fini)_array)", path)
        return match.group(1) if match else "<callback-array-sections>"
    if public_category == "security":
        if path == "security.bind_now":
            return ".dynamic"
        if path.startswith("security.gnu_property."):
            return "<gnu-property-notes>"
        return "<program-headers>"
    if public_category == "runtime-data":
        fallback = PUBLIC_CATEGORY_SECTIONS[public_category]
        left_value = finding.get("left")
        right_value = finding.get("right")
        left_section = (
            left_value.get("section", fallback)
            if isinstance(left_value, dict)
            else fallback
        )
        right_section = (
            right_value.get("section", fallback)
            if isinstance(right_value, dict)
            else fallback
        )
        return (
            left_section
            if left_section == right_section
            else {"make": left_section, "bazel": right_section}
        )
    return PUBLIC_CATEGORY_SECTIONS[public_category]


def finding_for_output(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return one confirmed semantic difference using the public vocabulary."""

    category = str(finding.get("category", "unknown"))
    if finding.get("severity") is None:
        if category not in PUBLIC_FINDING_CATEGORIES:
            return None
        public_category = category
    else:
        if not is_reportable_finding(finding):
            return None
        public_category = PUBLIC_CATEGORY_NAMES.get(category, category)
    if public_category not in PUBLIC_FINDING_CATEGORIES:
        return None
    public = {
        "category": public_category,
        "section": _finding_section(finding, public_category),
        "name": finding.get("name", finding.get("path", "")),
        "left": finding.get("left"),
        "right": finding.get("right"),
    }
    if finding.get("detail"):
        public["detail"] = finding["detail"]
    return public


def report_for_output(report: Dict[str, Any]) -> Dict[str, Any]:
    """Build the intentionally small JSON-facing comparison record."""

    left = report.get("make")
    if left is None:
        left = report.get("left", {}).get("path")
    right = report.get("bazel")
    if right is None:
        right = report.get("right", {}).get("path")
    public: Dict[str, Any] = {}
    if left is not None:
        public["make"] = left
    if right is not None:
        public["bazel"] = right
    if report.get("compiler_version_mismatch"):
        compiler_mismatch = dict(report["compiler_version_mismatch"])
        compiler_mismatch.setdefault("section", ".comment")
        public["compiler_version_mismatch"] = compiler_mismatch
    public_findings = []
    for item in report.get("findings", []):
        finding = finding_for_output(item)
        if finding is not None:
            public_findings.append(finding)
    public["findings"] = public_findings
    return public


def _human_finding_value(category: str, value: Any) -> str:
    if category == "data-relocation-coverage" and isinstance(value, dict):
        summarized = dict(value)
        for key, label in (
            ("relocations", "relocation(s)"),
            ("resolved_relocations", "resolved relocation(s)"),
            ("unresolved_relocations", "unresolved relocation(s)"),
            ("unsupported_relocations", "unsupported relocation(s)"),
        ):
            entries = summarized.get(key)
            if isinstance(entries, (list, tuple)):
                summarized[key] = f"{len(entries)} {label}"
        return str(summarized)
    return str(value)


def render_build_text(report: Dict[str, Any], max_differences: int) -> str:
    lines = [
        f"Result: {report['status']} (mode: build, level: {report['level']})",
        f"Make : {report['left']['path']}",
        f"Bazel: {report['right']['path']}",
    ]
    coverage = report["coverage"]
    lines.append("Tools: " + (", ".join(coverage["available_tools"]) or "none"))
    if coverage["missing_tools"]:
        lines.append("Missing required tools: " + ", ".join(coverage["missing_tools"]))
    if coverage.get("skipped_checks"):
        lines.append("Skipped checks: " + ", ".join(coverage["skipped_checks"]))

    count_label = "Semantic differences"
    group_label = "Semantic difference groups:"
    ordered = []
    for item in report["findings"]:
        finding = finding_for_output(item)
        if finding is not None:
            ordered.append(finding)
    if ordered:
        lines.append(f"{count_label}: {len(ordered)}")
        grouped_paths: Dict[str, List[str]] = {}
        for item in ordered:
            grouped_paths.setdefault(item["category"], []).append(item["path"])
        groups = [
            FindingGroup(
                severity="FAIL",
                category=category,
                count=len(paths),
                examples=tuple(sorted(set(paths))[:3]),
            )
            for category, paths in sorted(grouped_paths.items())
        ]
        if groups:
            lines.append(group_label)
            for group in groups:
                examples = group.displayed_examples()
                suffix = f"; examples: {examples}" if examples else ""
                lines.append(
                    f"  - [{group.category}] {group.count}{suffix}"
                )
        for item in ordered[:max_differences]:
            left_value = _human_finding_value(item["category"], item["left"])
            right_value = _human_finding_value(
                item["category"], item["right"]
            )
            lines.append(
                f"  - [{item['category']}] {item['path']}: "
                f"{left_value} -> {right_value}"
            )
            if item.get("detail"):
                detail_lines = str(item["detail"]).splitlines()
                lines.extend("      " + detail for detail in detail_lines[:12])
                if len(detail_lines) > 12:
                    lines.append(f"      ... {len(detail_lines) - 12} more line(s)")
        omitted = len(ordered) - max_differences
        if omitted > 0:
            lines.append(
                f"  ... {omitted} more item(s)"
            )
    else:
        lines.append(f"{count_label}: none")
    if report.get("report_dir"):
        lines.append("Reports: " + report["report_dir"])
    return "\n".join(lines)


def dump_json(report: Dict[str, Any]) -> str:
    return json.dumps(
        report_for_output(report), indent=2, ensure_ascii=False
    ) + "\n"
