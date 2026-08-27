#!/usr/bin/env python3
"""Compare two ELF artifacts byte-for-byte or by a normalized ELF view."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import struct
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple


VERSION = "3.0.0"
EXIT_EQUAL = 0
EXIT_DIFFERENT = 1
EXIT_ERROR = 2
EXIT_INCOMPLETE = 3

ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2
PN_XNUM = 0xFFFF
SHN_XINDEX = 0xFFFF
SHT_NOBITS = 8
SHT_SYMTAB = 2
SHT_DYNSYM = 11
SHT_RELA = 4
SHT_REL = 9
SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
STT_OBJECT = 1
STT_FUNC = 2
STT_TLS = 6

DEFAULT_IGNORED_SECTIONS = (
    ".comment",
    ".note.gnu.build-id",
    ".note.go.buildid",
    ".note.package",
    ".gnu_debuglink",
    ".gnu_debugaltlink",
    ".debug*",
    ".zdebug*",
    ".gdb_index",
)

ELF_TYPES = {
    0: "NONE",
    1: "REL",
    2: "EXEC",
    3: "DYN",
    4: "CORE",
}

MACHINES = {
    0: "NONE",
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}

SECTION_TYPES = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    16: "PREINIT_ARRAY",
    17: "GROUP",
    18: "SYMTAB_SHNDX",
}

PROGRAM_TYPES = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    5: "SHLIB",
    6: "PHDR",
    7: "TLS",
    0x6474E550: "GNU_EH_FRAME",
    0x6474E551: "GNU_STACK",
    0x6474E552: "GNU_RELRO",
    0x6474E553: "GNU_PROPERTY",
}


class ElfError(ValueError):
    pass


@dataclass(frozen=True)
class Section:
    index: int
    name_offset: int
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int


@dataclass(frozen=True)
class ProgramHeader:
    index: int
    type: int
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int


@dataclass(frozen=True)
class Symbol:
    table: str
    index: int
    name: str
    value: int
    size: int
    info: int
    other: int
    shndx: int

    @property
    def type(self) -> int:
        return self.info & 0xF

    @property
    def binding(self) -> int:
        return self.info >> 4


@dataclass(frozen=True)
class Relocation:
    section: str
    source_section_index: int
    target_section_index: int
    offset: int
    type: int
    symbol_name: str
    symbol_value: int
    symbol_section_index: int
    addend: Optional[int]


@dataclass(frozen=True)
class Difference:
    category: str
    path: str
    left: Any
    right: Any

    def as_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "path": self.path,
            "left": self.left,
            "right": self.right,
        }


class ElfFile:
    """A bounds-checked ELF header, program-header and section-table parser."""

    def __init__(self, path: str):
        self.path = path
        try:
            with open(path, "rb") as stream:
                self.data = stream.read()
        except OSError as exc:
            raise ElfError(f"cannot read {path!r}: {exc}") from exc

        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self._parse_header()
        self._parse_tables()

    def _parse_header(self) -> None:
        if len(self.data) < 16 or self.data[:4] != ELF_MAGIC:
            raise ElfError(f"{self.path!r} is not an ELF file")

        ident = self.data[:16]
        self.elf_class = ident[4]
        self.data_encoding = ident[5]
        self.ident_version = ident[6]
        self.osabi = ident[7]
        self.abi_version = ident[8]

        if self.elf_class not in (ELFCLASS32, ELFCLASS64):
            raise ElfError(f"unsupported ELF class {self.elf_class} in {self.path!r}")
        if self.data_encoding not in (ELFDATA2LSB, ELFDATA2MSB):
            raise ElfError(
                f"unsupported ELF data encoding {self.data_encoding} in {self.path!r}"
            )

        self.endian = "<" if self.data_encoding == ELFDATA2LSB else ">"
        if self.elf_class == ELFCLASS32:
            fmt = self.endian + "HHIIIIIHHHHHH"
        else:
            fmt = self.endian + "HHIQQQIHHHHHH"
        values = self._unpack_from(fmt, 16, "ELF header")
        (
            self.type,
            self.machine,
            self.version,
            self.entry,
            self.phoff,
            self.shoff,
            self.flags,
            self.ehsize,
            self.phentsize,
            self.phnum_raw,
            self.shentsize,
            self.shnum_raw,
            self.shstrndx_raw,
        ) = values

        expected_header_size = 52 if self.elf_class == ELFCLASS32 else 64
        if self.ehsize < expected_header_size:
            raise ElfError(
                f"invalid ELF header size {self.ehsize} in {self.path!r}; "
                f"expected at least {expected_header_size}"
            )

    def _unpack_from(self, fmt: str, offset: int, label: str) -> Tuple[Any, ...]:
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(self.data):
            raise ElfError(
                f"truncated {label} in {self.path!r} at file offset 0x{offset:x}"
            )
        return struct.unpack_from(fmt, self.data, offset)

    def _raw_section(self, index: int) -> Tuple[int, ...]:
        if self.elf_class == ELFCLASS32:
            fmt = self.endian + "IIIIIIIIII"
        else:
            fmt = self.endian + "IIQQQQIIQQ"
        native_size = struct.calcsize(fmt)
        if self.shentsize < native_size:
            raise ElfError(
                f"invalid section-header entry size {self.shentsize} in {self.path!r}"
            )
        return self._unpack_from(
            fmt, self.shoff + index * self.shentsize, f"section header {index}"
        )

    def _parse_tables(self) -> None:
        sh0: Optional[Tuple[int, ...]] = None
        needs_sh0 = (
            self.shnum_raw == 0
            or self.shstrndx_raw == SHN_XINDEX
            or self.phnum_raw == PN_XNUM
        )
        if needs_sh0 and self.shoff and self.shentsize:
            sh0 = self._raw_section(0)

        self.shnum = int(sh0[5]) if self.shnum_raw == 0 and sh0 else self.shnum_raw
        self.shstrndx = (
            int(sh0[6]) if self.shstrndx_raw == SHN_XINDEX and sh0 else self.shstrndx_raw
        )
        self.phnum = int(sh0[7]) if self.phnum_raw == PN_XNUM and sh0 else self.phnum_raw

        if self.shnum and (not self.shoff or not self.shentsize):
            raise ElfError(f"missing section table in {self.path!r}")
        if self.phnum and (not self.phoff or not self.phentsize):
            raise ElfError(f"missing program-header table in {self.path!r}")

        raw_sections = [self._raw_section(index) for index in range(self.shnum)]
        names = b""
        if self.shnum:
            if self.shstrndx >= self.shnum:
                raise ElfError(f"invalid section-name table index in {self.path!r}")
            name_header = raw_sections[self.shstrndx]
            names = self._slice(name_header[4], name_header[5], "section-name table")

        self.sections: List[Section] = []
        for index, fields in enumerate(raw_sections):
            name_offset = fields[0]
            self.sections.append(
                Section(
                    index=index,
                    name_offset=name_offset,
                    name=self._read_c_string(names, name_offset, index),
                    type=fields[1],
                    flags=fields[2],
                    addr=fields[3],
                    offset=fields[4],
                    size=fields[5],
                    link=fields[6],
                    info=fields[7],
                    addralign=fields[8],
                    entsize=fields[9],
                )
            )

        self.program_headers = [self._parse_program(index) for index in range(self.phnum)]

    def _parse_program(self, index: int) -> ProgramHeader:
        if self.elf_class == ELFCLASS32:
            fmt = self.endian + "IIIIIIII"
        else:
            fmt = self.endian + "IIQQQQQQ"
        native_size = struct.calcsize(fmt)
        if self.phentsize < native_size:
            raise ElfError(
                f"invalid program-header entry size {self.phentsize} in {self.path!r}"
            )
        fields = self._unpack_from(
            fmt, self.phoff + index * self.phentsize, f"program header {index}"
        )
        if self.elf_class == ELFCLASS32:
            p_type, offset, vaddr, paddr, filesz, memsz, flags, align = fields
        else:
            p_type, flags, offset, vaddr, paddr, filesz, memsz, align = fields
        return ProgramHeader(index, p_type, flags, offset, vaddr, paddr, filesz, memsz, align)

    def _slice(self, offset: int, size: int, label: str) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ElfError(
                f"{label} in {self.path!r} extends outside the file "
                f"(offset=0x{offset:x}, size=0x{size:x})"
            )
        return self.data[offset : offset + size]

    def _read_c_string(self, table: bytes, offset: int, index: int) -> str:
        if not table:
            return ""
        if offset >= len(table):
            raise ElfError(
                f"invalid name offset for section {index} in {self.path!r}"
            )
        end = table.find(b"\0", offset)
        if end < 0:
            raise ElfError(f"unterminated name for section {index} in {self.path!r}")
        return table[offset:end].decode("utf-8", errors="backslashreplace")

    def section_data(self, section: Section) -> bytes:
        if section.type == SHT_NOBITS:
            return b""
        return self._slice(section.offset, section.size, f"section {section.name!r}")

    def _symbols_from_table(self, table: Section) -> List[Symbol]:
        symbols: List[Symbol] = []
        if table.link >= len(self.sections):
            raise ElfError(f"invalid string-table link in symbol table {table.name!r}")
        strings = self.section_data(self.sections[table.link])
        if self.elf_class == ELFCLASS32:
            fmt = self.endian + "IIIBBH"
        else:
            fmt = self.endian + "IBBHQQ"
        native_size = struct.calcsize(fmt)
        entry_size = table.entsize or native_size
        if entry_size < native_size or table.size % entry_size:
            raise ElfError(f"invalid entry size in symbol table {table.name!r}")
        data = self.section_data(table)
        for index in range(table.size // entry_size):
            fields = struct.unpack_from(fmt, data, index * entry_size)
            if self.elf_class == ELFCLASS32:
                name_offset, value, size, info, other, shndx = fields
            else:
                name_offset, info, other, shndx, value, size = fields
            name = self._read_c_string(strings, name_offset, index)
            symbols.append(Symbol(table.name, index, name, value, size, info, other, shndx))
        return symbols

    def symbols(self) -> List[Symbol]:
        """Return the full symbol table when present, otherwise dynamic symbols."""
        symbol_tables = [section for section in self.sections if section.type == SHT_SYMTAB]
        if not symbol_tables:
            symbol_tables = [section for section in self.sections if section.type == SHT_DYNSYM]
        return [symbol for table in symbol_tables for symbol in self._symbols_from_table(table)]

    def dynamic_symbols(self) -> List[Symbol]:
        """Return only dynamic symbols, independent of the artifact's strip level."""
        symbol_tables = [section for section in self.sections if section.type == SHT_DYNSYM]
        return [symbol for table in symbol_tables for symbol in self._symbols_from_table(table)]

    def relocations(self) -> List[Relocation]:
        relocations: List[Relocation] = []
        for section in self.sections:
            if section.type not in (SHT_REL, SHT_RELA):
                continue
            if section.link >= len(self.sections) or section.info >= len(self.sections):
                raise ElfError(f"invalid link in relocation section {section.name!r}")
            symbol_table = self.sections[section.link]
            if symbol_table.type not in (SHT_SYMTAB, SHT_DYNSYM):
                raise ElfError(f"relocation section {section.name!r} does not link to symbols")
            symbols = self._symbols_from_table(symbol_table)
            if self.elf_class == ELFCLASS32:
                fmt = self.endian + ("IIi" if section.type == SHT_RELA else "II")
            else:
                fmt = self.endian + ("QQq" if section.type == SHT_RELA else "QQ")
            native_size = struct.calcsize(fmt)
            entry_size = section.entsize or native_size
            if entry_size < native_size or section.size % entry_size:
                raise ElfError(f"invalid entry size in relocation section {section.name!r}")
            data = self.section_data(section)
            for index in range(section.size // entry_size):
                fields = struct.unpack_from(fmt, data, index * entry_size)
                offset, info = fields[:2]
                addend = fields[2] if section.type == SHT_RELA else None
                if self.elf_class == ELFCLASS32:
                    symbol_index, relocation_type = info >> 8, info & 0xFF
                else:
                    symbol_index, relocation_type = info >> 32, info & 0xFFFFFFFF
                if symbol_index >= len(symbols):
                    raise ElfError(f"invalid symbol index in relocation section {section.name!r}")
                target_index = section.info
                if target_index == 0 and self.type != 1:
                    containing_sections = [
                        candidate
                        for candidate in self.sections
                        if candidate.index != 0
                        and candidate.flags & 0x2  # SHF_ALLOC
                        and candidate.addr <= offset < candidate.addr + candidate.size
                    ]
                    if containing_sections:
                        target_index = min(containing_sections, key=lambda item: item.size).index
                target = self.sections[target_index]
                relative_offset = offset if self.type == 1 else offset - target.addr
                relocations.append(
                    Relocation(
                        section.name,
                        section.index,
                        target_index,
                        relative_offset,
                        relocation_type,
                        symbols[symbol_index].name,
                        symbols[symbol_index].value,
                        symbols[symbol_index].shndx,
                        addend,
                    )
                )
        return relocations

    @property
    def display_class(self) -> str:
        return "ELF32" if self.elf_class == ELFCLASS32 else "ELF64"

    @property
    def display_endian(self) -> str:
        return "little" if self.data_encoding == ELFDATA2LSB else "big"


def _format_enum(value: int, names: Dict[int, str]) -> str:
    return f"{names.get(value, 'UNKNOWN')} (0x{value:x})"


def _is_ignored(name: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _numbered_sections(elf: ElfFile, patterns: Sequence[str]) -> Dict[Tuple[str, int], Section]:
    result: Dict[Tuple[str, int], Section] = {}
    occurrences: Dict[str, int] = {}
    for section in elf.sections:
        if section.index == 0 or _is_ignored(section.name, patterns):
            continue
        occurrence = occurrences.get(section.name, 0)
        occurrences[section.name] = occurrence + 1
        result[(section.name, occurrence)] = section
    return result


def _section_label(key: Tuple[str, int]) -> str:
    name, occurrence = key
    return name if occurrence == 0 else f"{name}#{occurrence + 1}"


def _link_name(elf: ElfFile, index: int) -> Any:
    if index == 0:
        return 0
    if index < len(elf.sections):
        return elf.sections[index].name
    return f"<invalid:{index}>"


def semantic_differences(
    left: ElfFile, right: ElfFile, ignored_patterns: Sequence[str]
) -> List[Difference]:
    differences: List[Difference] = []

    header_fields = (
        ("class", left.display_class, right.display_class),
        ("endianness", left.display_endian, right.display_endian),
        ("ident_version", left.ident_version, right.ident_version),
        ("osabi", left.osabi, right.osabi),
        ("abi_version", left.abi_version, right.abi_version),
        ("type", _format_enum(left.type, ELF_TYPES), _format_enum(right.type, ELF_TYPES)),
        (
            "machine",
            _format_enum(left.machine, MACHINES),
            _format_enum(right.machine, MACHINES),
        ),
        ("version", left.version, right.version),
        ("entry", f"0x{left.entry:x}", f"0x{right.entry:x}"),
        ("flags", f"0x{left.flags:x}", f"0x{right.flags:x}"),
    )
    for name, left_value, right_value in header_fields:
        if left_value != right_value:
            differences.append(Difference("header", name, left_value, right_value))

    left_programs = left.program_headers
    right_programs = right.program_headers
    if len(left_programs) != len(right_programs):
        differences.append(
            Difference("program_headers", "count", len(left_programs), len(right_programs))
        )
    for index, (left_ph, right_ph) in enumerate(zip(left_programs, right_programs)):
        fields = (
            ("type", _format_enum(left_ph.type, PROGRAM_TYPES), _format_enum(right_ph.type, PROGRAM_TYPES)),
            ("flags", f"0x{left_ph.flags:x}", f"0x{right_ph.flags:x}"),
            ("vaddr", f"0x{left_ph.vaddr:x}", f"0x{right_ph.vaddr:x}"),
            ("paddr", f"0x{left_ph.paddr:x}", f"0x{right_ph.paddr:x}"),
            ("filesz", left_ph.filesz, right_ph.filesz),
            ("memsz", left_ph.memsz, right_ph.memsz),
            ("align", left_ph.align, right_ph.align),
        )
        for name, left_value, right_value in fields:
            if left_value != right_value:
                differences.append(
                    Difference("program_header", f"[{index}].{name}", left_value, right_value)
                )

    left_sections = _numbered_sections(left, ignored_patterns)
    right_sections = _numbered_sections(right, ignored_patterns)
    all_keys = sorted(set(left_sections) | set(right_sections))
    for key in all_keys:
        label = _section_label(key)
        left_section = left_sections.get(key)
        right_section = right_sections.get(key)
        if left_section is None:
            differences.append(Difference("section", label, "<missing>", "<present>"))
            continue
        if right_section is None:
            differences.append(Difference("section", label, "<present>", "<missing>"))
            continue

        section_fields = (
            (
                "type",
                _format_enum(left_section.type, SECTION_TYPES),
                _format_enum(right_section.type, SECTION_TYPES),
            ),
            ("flags", f"0x{left_section.flags:x}", f"0x{right_section.flags:x}"),
            ("addr", f"0x{left_section.addr:x}", f"0x{right_section.addr:x}"),
            ("size", left_section.size, right_section.size),
            ("link", _link_name(left, left_section.link), _link_name(right, right_section.link)),
            ("addralign", left_section.addralign, right_section.addralign),
            ("entsize", left_section.entsize, right_section.entsize),
        )
        if left_section.type in (SHT_REL, SHT_RELA):
            section_fields += (("info", _link_name(left, left_section.info), _link_name(right, right_section.info)),)
        else:
            section_fields += (("info", left_section.info, right_section.info),)

        for name, left_value, right_value in section_fields:
            if left_value != right_value:
                differences.append(
                    Difference("section", f"{label}.{name}", left_value, right_value)
                )

        left_digest = hashlib.sha256(left.section_data(left_section)).hexdigest()
        right_digest = hashlib.sha256(right.section_data(right_section)).hexdigest()
        if left_digest != right_digest:
            differences.append(
                Difference(
                    "section_content",
                    f"{label}.sha256",
                    left_digest,
                    right_digest,
                )
            )

    return differences


def _first_mismatch(left: bytes, right: bytes) -> Optional[int]:
    for index, (left_byte, right_byte) in enumerate(zip(left, right)):
        if left_byte != right_byte:
            return index
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def compare(
    left_path: str,
    right_path: str,
    mode: str,
    ignored_patterns: Sequence[str],
) -> Dict[str, Any]:
    left = ElfFile(left_path)
    right = ElfFile(right_path)
    byte_equal = left.data == right.data
    differences = semantic_differences(left, right, ignored_patterns)
    semantic_equal = not differences
    selected_equal = byte_equal if mode == "exact" else semantic_equal
    mismatch = _first_mismatch(left.data, right.data)

    return {
        "tool": {"name": "elfcompare", "version": VERSION},
        "mode": mode,
        "equal": selected_equal,
        "byte_equal": byte_equal,
        "semantic_equal": semantic_equal,
        "left": {
            "path": os.path.abspath(left_path),
            "size": len(left.data),
            "sha256": left.sha256,
            "class": left.display_class,
            "endianness": left.display_endian,
            "type": _format_enum(left.type, ELF_TYPES),
            "machine": _format_enum(left.machine, MACHINES),
        },
        "right": {
            "path": os.path.abspath(right_path),
            "size": len(right.data),
            "sha256": right.sha256,
            "class": right.display_class,
            "endianness": right.display_endian,
            "type": _format_enum(right.type, ELF_TYPES),
            "machine": _format_enum(right.machine, MACHINES),
        },
        "first_byte_mismatch": mismatch,
        "ignored_section_patterns": list(ignored_patterns),
        "differences": [difference.as_dict() for difference in differences],
    }


def _short_hash(value: str) -> str:
    return value[:12]


def render_text(report: Dict[str, Any], max_differences: int) -> str:
    equal = report["equal"]
    mode = report["mode"]
    lines = [f"Result: {'CONSISTENT' if equal else 'DIFFERENT'} (mode: {mode})"]
    for side in ("left", "right"):
        item = report[side]
        lines.append(
            f"{side.capitalize():5}: {item['path']} "
            f"[{item['class']} {item['endianness']}, {item['machine']}, "
            f"{item['size']} bytes, sha256={_short_hash(item['sha256'])}...]"
        )

    lines.append(f"Bytes: {'identical' if report['byte_equal'] else 'different'}")
    lines.append(
        "Normalized ELF: "
        + ("equivalent" if report["semantic_equal"] else "different")
    )
    if report["first_byte_mismatch"] is not None:
        lines.append(f"First byte mismatch: 0x{report['first_byte_mismatch']:x}")

    differences = report["differences"]
    if differences:
        lines.append(f"Semantic differences ({len(differences)}):")
        for difference in differences[:max_differences]:
            lines.append(
                f"  - [{difference['category']}] {difference['path']}: "
                f"{difference['left']} -> {difference['right']}"
            )
        omitted = len(differences) - max_differences
        if omitted > 0:
            lines.append(f"  ... {omitted} more difference(s)")
    elif not report["byte_equal"]:
        lines.append(
            "Diagnosis: the normalized view found no difference. The changed "
            "bytes are in ignored sections, layout/padding, or data this view does not model."
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="elfcompare",
        description=(
            "Compare one Make-built ELF with one Bazel-built ELF and write a "
            "semantic-difference summary as JSON."
        ),
    )
    parser.add_argument("left", metavar="MAKE_ELF", help="Make-built ELF file")
    parser.add_argument("right", metavar="BAZEL_ELF", help="Bazel-built ELF file")
    return parser


@dataclass(frozen=True)
class ComparisonPolicy:
    """Versioned policy applied identically to every CLI invocation."""

    timeout: int = 300
    tool_prefix: str = ""
    readelf: Optional[str] = None
    eu_elfcmp: Optional[str] = None
    abidiff: Optional[str] = None
    elf_diff: Optional[str] = None
    diffoscope: Optional[str] = None
    abi: str = "auto"
    require_tool: Tuple[str, ...] = ()
    level: str = "standard"
    report_dir: Optional[str] = None
    skip_function_bodies: bool = False
    left_path_map: Tuple[Tuple[str, str], ...] = ()
    right_path_map: Tuple[Tuple[str, str], ...] = ()
    allow_extra_needed: Tuple[str, ...] = ()
    allow_needed_reorder: bool = False


def _compare_one_build(
    left_path: str,
    right_path: str,
    args: ComparisonPolicy,
    ignored_patterns: Sequence[str],
) -> Tuple[Dict[str, Any], int]:
    from elfcompare_tools import compare_build

    left_elf = ElfFile(left_path)
    right_elf = ElfFile(right_path)
    report, exit_code = compare_build(
        left_path,
        right_path,
        left_elf,
        right_elf,
        ignored_patterns=ignored_patterns,
        args=args,
    )
    return report, exit_code


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    policy = ComparisonPolicy()

    try:
        from elfcompare_tools import dump_json

        report, exit_code = _compare_one_build(
            args.left,
            args.right,
            policy,
            DEFAULT_IGNORED_SECTIONS,
        )
        sys.stdout.write(dump_json(report))
        return exit_code
    except ElfError as exc:
        print(f"elfcompare: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
