#!/usr/bin/env python3
"""Parse two ELF artifacts and emit their semantic-difference summary."""

from __future__ import annotations

import argparse
import os
import struct
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple


EXIT_ERROR = 2

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


class ElfFile:
    """A bounds-checked ELF header, program-header and section-table parser."""

    def __init__(self, path: str):
        self.path = path
        try:
            with open(path, "rb") as stream:
                self.data = stream.read()
        except OSError as exc:
            raise ElfError(f"cannot read {path!r}: {exc}") from exc

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
    readelf: Optional[str] = None
    abidiff: Optional[str] = None


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
