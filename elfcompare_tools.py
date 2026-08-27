"""External-tool orchestration for Make-to-Bazel ELF comparisons."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, replace
from enum import Enum
from typing import (
    AbstractSet,
    Any,
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
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15
SHT_PREINIT_ARRAY = 16
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


class SymbolBinding(str, Enum):
    LOCAL = "LOCAL"
    GLOBAL = "GLOBAL"
    WEAK = "WEAK"
    UNIQUE = "UNIQUE"


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

@dataclass(frozen=True)
class FunctionSymbolMetadata:
    binding: SymbolBinding
    names: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "binding", SymbolBinding(self.binding))


@dataclass
class FunctionBlock:
    name: str
    binding: Optional[SymbolBinding]
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
    return {
        "readelf": resolve_command(args.readelf, "readelf"),
        "abidiff": resolve_command(args.abidiff, "abidiff"),
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
    return _is_gcc_derived_only_function(block)


def _is_plt_section(name: str) -> bool:
    return name in (".plt", ".iplt") or name.startswith(
        (".plt.", ".iplt.")
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
    for symbol in elf.symbols():
        if (
            symbol.type in (STT_FUNC, STT_GNU_IFUNC)
            and symbol.name
            and 0 < symbol.shndx < len(elf.sections)
        ):
            grouped.setdefault((symbol.shndx, symbol.value), []).append(symbol)

    result: Dict[FunctionLocation, FunctionSymbolMetadata] = {}
    ambiguous_keys = set()
    for (section_index, address), symbols in grouped.items():
        identity_symbols, binding = _preferred_function_aliases(symbols)
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
        result[result_key] = FunctionSymbolMetadata(binding, names)
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
        else:
            binding = next(
                candidate
                for candidate in binding_order
                if any(item[2] == candidate for item in symbols)
            )
            preferred = [item for item in symbols if item[2] == binding]
            aliases = tuple(sorted({item[0] for item in preferred}))

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
            binding=binding,
            aliases=aliases,
            section=section.name,
        )
    return functions


def _compare_one_sided_function(
    block: FunctionBlock, side: str
) -> Optional[Finding]:
    if side == "right" and block.binding == SymbolBinding.WEAK:
        return None
    return Finding(
        "FAIL",
        "function-removed" if side == "left" else "function-added",
        block.name,
        "<present>" if side == "left" else "<missing>",
        "<missing>" if side == "left" else "<present>",
        "A Make function is absent from Bazel."
        if side == "left"
        else "Bazel adds a non-WEAK function.",
        section=block.section,
    )


def _pair_function_blocks(
    left: Dict[FunctionIdentity, FunctionBlock],
    right: Dict[FunctionIdentity, FunctionBlock],
) -> Tuple[
    Dict[FunctionIdentity, FunctionBlock],
    Dict[FunctionIdentity, FunctionBlock],
]:
    left_remaining = dict(left)
    right_remaining = dict(right)
    for key in sorted(set(left_remaining) & set(right_remaining)):
        left_remaining.pop(key)
        right_remaining.pop(key)

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
            left_remaining.pop(left_key)
            right_remaining.pop(right_key)
    return left_remaining, right_remaining


def compare_functions(
    left: Dict[FunctionIdentity, FunctionBlock],
    right: Dict[FunctionIdentity, FunctionBlock],
) -> List[Finding]:
    findings: List[Finding] = []
    left_remaining, right_remaining = _pair_function_blocks(
        left, right
    )
    for key, left_block in sorted(left_remaining.items()):
        if _ignore_one_sided_gcc_derived_function(left_block):
            continue
        finding = _compare_one_sided_function(left_block, "left")
        if finding is not None:
            findings.append(finding)
    for key, right_block in sorted(right_remaining.items()):
        if _ignore_one_sided_gcc_derived_function(right_block):
            continue
        finding = _compare_one_sided_function(right_block, "right")
        if finding is not None:
            findings.append(finding)
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
    findings: List[Finding],
) -> bool:
    succeeded = True
    for result in results:
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
    missing: List[str] = []

    both_dynamic = left_elf.type == 3 and right_elf.type == 3
    has_program_interpreter = any(
        program.type == PT_INTERP
        for elf in (left_elf, right_elf)
        for program in elf.program_headers
    )
    looks_like_shared_library = both_dynamic and not has_program_interpreter
    should_check_abi = looks_like_shared_library
    required = ["readelf"]
    if should_check_abi:
        required.append("abidiff")
    for name in required:
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
            (left_readelf, right_readelf), findings
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
                        allow_extra_needed=(),
                        allow_needed_reorder=False,
                    )
                )
            if not strip_profile_mismatch:
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

    abidiff = tools.get("abidiff")
    if should_check_abi:
        if abidiff:
            result = runner.run("abidiff", list(abidiff) + [left_path, right_path])
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

    has_error = bool(missing) or any(item.severity == "ERROR" for item in findings)
    has_failure = any(item.severity == "FAIL" for item in findings)
    if has_failure:
        exit_code = EXIT_DIFFERENT
    elif has_error:
        exit_code = EXIT_INCOMPLETE
    else:
        exit_code = EXIT_CONSISTENT

    report = {
        "make": os.path.abspath(left_path),
        "bazel": os.path.abspath(right_path),
        "findings": [item.as_dict() for item in findings],
    }
    compiler_mismatch = compiler_comment_mismatch(left_elf, right_elf)
    if compiler_mismatch:
        report["compiler_version_mismatch"] = compiler_mismatch
    return report, exit_code


def is_reportable_finding(finding: Dict[str, Any]) -> bool:
    """Return whether a finding belongs in user-facing reports."""

    return finding.get("severity") == "FAIL"


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


def dump_json(report: Dict[str, Any]) -> str:
    return json.dumps(
        report_for_output(report), indent=2, ensure_ascii=False
    ) + "\n"
