#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FoxPointerScanner 3.0 — read-only pointer scanner for Windows.

Возможности:
- поиск одноуровневых и многоуровневых pointer-chain;
- обязательная автоматическая проверка найденных цепочек;
- сохранение только цепочек, которые действительно разрешаются в TARGET;
- быстрый повторный контроль цепочек из JSON без полного сканирования;
- подробный debug-режим и журнал scanner.log;
- live-уведомления о найденных рабочих цепочках;
- пакетное чтение памяти процесса без записи в неё.

Формат цепочки:
    address = module_base + root_offset
    pointer = *(address)
    address = pointer + offset_1
    pointer = *(address)
    address = pointer + offset_2
    ...
    final_address = pointer + offset_N

Использовать только для собственных программ, тестовых стендов и процессов,
на анализ которых имеется разрешение.
"""

from __future__ import annotations

import bisect
import ctypes
import json
import math
import os
import re
import struct
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple
from ctypes import wintypes


if os.name != "nt":
    print("[!] Данная программа поддерживает только Windows.")
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# WinAPI constants
# ---------------------------------------------------------------------------

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000

PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

READABLE_PROTECTIONS = {
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
}

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_PATH = 260
STILL_ACTIVE = 259
MIN_VALID_POINTER = 0x10000

# 16 MiB — хороший компромисс между количеством системных вызовов и RAM.
DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024
DEFAULT_MAX_PATHS_PER_NODE = 4

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


# ---------------------------------------------------------------------------
# WinAPI structures
# ---------------------------------------------------------------------------

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_ubyte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


# ---------------------------------------------------------------------------
# WinAPI signatures
# ---------------------------------------------------------------------------

kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL

kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ModuleInfo:
    name: str
    path: str
    base: int
    size: int

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass(frozen=True)
class MemoryRegion:
    base: int
    size: int
    protect: int

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass(frozen=True)
class Edge:
    source_address: int
    pointer_value: int
    offset: int
    target_address: int


@dataclass(frozen=True)
class PointerChain:
    module: ModuleInfo
    root_offset: int
    edges: Tuple[Edge, ...]

    @property
    def offsets(self) -> Tuple[int, ...]:
        return tuple(edge.offset for edge in self.edges)

    @property
    def depth(self) -> int:
        return len(self.edges)

    @property
    def signature(self) -> str:
        offsets = ",".join(f"{value:X}" for value in self.offsets)
        return f"{self.module.name.lower()}|{self.root_offset:X}|{offsets}"

    def pretty(self) -> str:
        offsets = " -> ".join(f"+0x{value:X}" for value in self.offsets)
        return f"{self.module.name}+0x{self.root_offset:X} -> {offsets}"


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    resolved_address: Optional[int]
    failed_at_level: Optional[int]
    reason: str


@dataclass(frozen=True)
class LevelTrace:
    level: int
    read_address: int
    pointer_value: Optional[int]
    offset: int
    next_address: Optional[int]
    ok: bool
    reason: str


@dataclass(frozen=True)
class DetailedValidationResult:
    valid: bool
    resolved_address: Optional[int]
    failed_at_level: Optional[int]
    reason: str
    levels: Tuple[LevelTrace, ...]


@dataclass(frozen=True)
class ValueSpec:
    type_name: str
    expected: object
    tolerance: float = 0.0
    max_length: int = 256


@dataclass(frozen=True)
class ValueCheckResult:
    valid: bool
    actual: object
    reason: str


class DebugLogger:
    def __init__(self, enabled: bool, log_path: Optional[Path] = None) -> None:
        self.enabled = enabled
        self.log_path = log_path or (Path.cwd() / "scanner.log")
        self._stream = None
        if enabled:
            self._stream = self.log_path.open("a", encoding="utf-8", buffering=1)
            self.write("=" * 76, force_file=True)
            self.write(
                f"FoxPointerScanner session: {datetime.now().isoformat(timespec='seconds')}",
                force_file=True,
            )

    def write(self, message: str, *, console: bool = False, force_file: bool = False) -> None:
        if console:
            print(message)
        if self._stream is not None and (self.enabled or force_file):
            self._stream.write(message + "\n")

    def debug(self, message: str) -> None:
        if self.enabled:
            self.write(message, console=True)

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None


# ---------------------------------------------------------------------------
# Input and general helpers
# ---------------------------------------------------------------------------

def win_error(prefix: str) -> OSError:
    code = ctypes.get_last_error()
    return OSError(code, f"{prefix}: {ctypes.FormatError(code).strip()}")


def parse_int(text: str) -> int:
    cleaned = text.strip().replace("`", "").replace("_", "").replace(" ", "")
    if not cleaned:
        raise ValueError("Пустое значение")
    base = 0 if cleaned.lower().startswith(("0x", "0o", "0b")) else 16
    return int(cleaned, base)


def ask_int(prompt: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        raw = input(f"{prompt} [{default}]: ").strip()
        if not raw:
            return default
        try:
            value = int(raw, 10)
        except ValueError:
            print("[-] Требуется десятичное целое число.")
            continue
        if minimum <= value <= maximum:
            return value
        print(f"[-] Допустимый диапазон: {minimum}–{maximum}.")


def ask_hex(prompt: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        raw = input(f"{prompt} [0x{default:X}]: ").strip()
        if not raw:
            return default
        try:
            value = parse_int(raw)
        except ValueError:
            print("[-] Некорректное число. Пример: 0x1000.")
            continue
        if minimum <= value <= maximum:
            return value
        print(f"[-] Допустимый диапазон: 0x{minimum:X}–0x{maximum:X}.")


def ask_choice(prompt: str, choices: Dict[str, str], default: str) -> str:
    print(prompt)
    for key, description in choices.items():
        suffix = " (по умолчанию)" if key == default else ""
        print(f"  {key}. {description}{suffix}")
    while True:
        value = input("Выбор: ").strip() or default
        if value in choices:
            return value
        print(f"[-] Выберите один из вариантов: {', '.join(choices)}.")


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{prompt} [{suffix}]: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes", "д", "да"}:
            return True
        if raw in {"n", "no", "н", "нет"}:
            return False
        print("[-] Введите y или n.")


def safe_filename_component(value: str) -> str:
    basename = Path(value).name
    cleaned = re.sub(r"[^A-Za-zА-Яа-я0-9._-]+", "_", basename)
    return cleaned.strip("._") or "process"


# ---------------------------------------------------------------------------
# Process and module enumeration
# ---------------------------------------------------------------------------

def find_processes(name: str) -> List[Tuple[int, str]]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise win_error("CreateToolhelp32Snapshot(PROCESS)")

    matches: List[Tuple[int, str]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            executable = str(entry.szExeFile)
            if executable.lower() == name.lower() or name.lower() in executable.lower():
                matches.append((int(entry.th32ProcessID), executable))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return matches


def choose_process() -> Tuple[int, str]:
    raw = input("Имя процесса или PID: ").strip()
    if not raw:
        raise ValueError("Процесс не указан")
    if raw.isdigit():
        return int(raw), f"PID_{raw}"

    matches = find_processes(raw)
    if not matches:
        raise RuntimeError(f"Процесс «{raw}» не найден")
    if len(matches) == 1:
        return matches[0]

    print("[+] Найдено несколько процессов:")
    for index, (pid, executable) in enumerate(matches, 1):
        print(f"    {index}. {executable} (PID {pid})")
    while True:
        selected = input("Номер процесса: ").strip()
        if selected.isdigit() and 1 <= int(selected) <= len(matches):
            return matches[int(selected) - 1]
        print("[-] Указан неверный номер.")


def enumerate_modules(pid: int) -> List[ModuleInfo]:
    snapshot = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        pid,
    )
    if snapshot == INVALID_HANDLE_VALUE:
        raise win_error("CreateToolhelp32Snapshot(MODULE)")

    modules: List[ModuleInfo] = []
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel32.Module32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
            modules.append(
                ModuleInfo(
                    name=str(entry.szModule),
                    path=str(entry.szExePath),
                    base=int(base),
                    size=int(entry.modBaseSize),
                )
            )
            ok = kernel32.Module32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    modules.sort(key=lambda item: item.base)
    return modules


def module_for_address(
    modules: Sequence[ModuleInfo],
    module_bases: Sequence[int],
    address: int,
) -> Optional[ModuleInfo]:
    index = bisect.bisect_right(module_bases, address) - 1
    if index < 0:
        return None
    module = modules[index]
    return module if address < module.end else None


# ---------------------------------------------------------------------------
# Memory access
# ---------------------------------------------------------------------------

def process_is_alive(process_handle: int) -> bool:
    exit_code = wintypes.DWORD(0)
    if not kernel32.GetExitCodeProcess(process_handle, ctypes.byref(exit_code)):
        return False
    return exit_code.value == STILL_ACTIVE


def enumerate_regions(process_handle: int) -> List[MemoryRegion]:
    regions: List[MemoryRegion] = []
    address = 0
    max_address = 0x00007FFFFFFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFFFFFF
    mbi = MEMORY_BASIC_INFORMATION()

    while address < max_address:
        result = kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if result == 0:
            # VirtualQueryEx описывает MEM_FREE-регионы тоже. Ноль обычно означает
            # достижение конца адресного пространства или фатальную ошибку запроса.
            break

        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize or 0)
        protect = int(mbi.Protect)
        protection_base = protect & 0xFF

        readable = (
            int(mbi.State) == MEM_COMMIT
            and size > 0
            and not (protect & PAGE_GUARD)
            and not (protect & PAGE_NOACCESS)
            and protection_base in READABLE_PROTECTIONS
        )
        if readable:
            regions.append(MemoryRegion(base=base, size=size, protect=protect))

        next_address = base + max(size, 0x1000)
        if next_address <= address:
            break
        address = next_address

    return regions


def read_chunk(process_handle: int, address: int, size: int) -> bytes:
    if size <= 0:
        return b""
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )
    if not ok and bytes_read.value == 0:
        return b""
    return buffer.raw[: bytes_read.value]


def read_pointer(process_handle: int, address: int, pointer_size: int) -> Optional[int]:
    data = read_chunk(process_handle, address, pointer_size)
    if len(data) != pointer_size:
        return None
    return int.from_bytes(data, byteorder="little", signed=False)


def iter_region_chunks(
    process_handle: int,
    region: MemoryRegion,
    chunk_size: int,
    pointer_size: int,
) -> Iterator[Tuple[int, bytes, int]]:
    """Читает блоки с look-ahead, не теряя указатели на границе чанков.

    ``core_size`` задаёт число новых стартовых позиций в текущем блоке.
    Дополнительные ``pointer_size - 1`` байт используются только для чтения
    указателя, пересекающего границу, и повторно как стартовые позиции не
    сканируются.
    """
    cursor = region.base
    while cursor < region.end:
        core_size = min(chunk_size, region.end - cursor)
        request_size = min(core_size + pointer_size - 1, region.end - cursor)
        data = read_chunk(process_handle, cursor, request_size)
        if data:
            yield cursor, data, core_size
        cursor += core_size


# ---------------------------------------------------------------------------
# Search and validation
# ---------------------------------------------------------------------------

def validate_chain_detailed(
    process_handle: int,
    chain: PointerChain,
    target_address: int,
    pointer_size: int,
    debug_callback: Optional[Callable[[str], None]] = None,
    chain_label: str = "",
) -> DetailedValidationResult:
    """Разрешает цепочку и записывает результат каждого уровня.

    Функция только читает память и не участвует в построении BFS-графа.
    Благодаря этому подробная диагностика не меняет основной алгоритм поиска.
    """
    current_address = chain.module.base + chain.root_offset
    prefix = f"{chain_label} " if chain_label else ""
    traces: List[LevelTrace] = []

    if debug_callback:
        debug_callback(
            f"[*] {prefix}root: {chain.module.name}+0x{chain.root_offset:X} "
            f"= 0x{current_address:X}"
        )

    for level, offset in enumerate(chain.offsets, start=1):
        read_address = current_address
        pointer_value = read_pointer(process_handle, read_address, pointer_size)
        if pointer_value is None:
            reason = f"ReadProcessMemory failed at 0x{read_address:X}"
            traces.append(LevelTrace(level, read_address, None, offset, None, False, reason))
            if debug_callback:
                debug_callback(f"[-] {prefix}Level {level} ✗ | {reason}")
            return DetailedValidationResult(False, None, level, reason, tuple(traces))

        if pointer_value < MIN_VALID_POINTER:
            reason = f"invalid/null pointer 0x{pointer_value:X}"
            traces.append(LevelTrace(level, read_address, pointer_value, offset, None, False, reason))
            if debug_callback:
                debug_callback(
                    f"[-] {prefix}Level {level} ✗ | read 0x{pointer_value:X} "
                    f"from 0x{read_address:X} | {reason}"
                )
            return DetailedValidationResult(False, None, level, reason, tuple(traces))

        next_address = pointer_value + offset
        reason = "ok"
        traces.append(LevelTrace(level, read_address, pointer_value, offset, next_address, True, reason))
        if debug_callback:
            debug_callback(
                f"[+] {prefix}Level {level} ✓ | *(0x{read_address:X}) = "
                f"0x{pointer_value:X} | +0x{offset:X} => 0x{next_address:X}"
            )
        current_address = next_address

    if current_address != target_address:
        reason = f"final mismatch: got 0x{current_address:X}, expected 0x{target_address:X}"
        if debug_callback:
            debug_callback(f"[-] {prefix}{reason}")
        return DetailedValidationResult(False, current_address, len(chain.offsets), reason, tuple(traces))

    if debug_callback:
        debug_callback(f"[+] {prefix}confirmed: 0x{current_address:X}")
    return DetailedValidationResult(True, current_address, None, "ok", tuple(traces))


def validate_chain(
    process_handle: int,
    chain: PointerChain,
    target_address: int,
    pointer_size: int,
    debug_callback: Optional[Callable[[str], None]] = None,
    chain_label: str = "",
) -> ValidationResult:
    detailed = validate_chain_detailed(
        process_handle, chain, target_address, pointer_size, debug_callback, chain_label
    )
    return ValidationResult(
        detailed.valid, detailed.resolved_address, detailed.failed_at_level, detailed.reason
    )


def read_typed_value(
    process_handle: int, address: int, type_name: str, max_length: int = 256
) -> object:
    normalized = type_name.strip().lower()
    formats = {
        "int8": "<b", "uint8": "<B",
        "int16": "<h", "uint16": "<H",
        "int": "<i", "int32": "<i", "uint32": "<I",
        "int64": "<q", "uint64": "<Q",
        "float": "<f", "double": "<d",
    }
    if normalized in formats:
        st = struct.Struct(formats[normalized])
        data = read_chunk(process_handle, address, st.size)
        if len(data) != st.size:
            raise RuntimeError(f"Не удалось прочитать {st.size} байт по адресу 0x{address:X}")
        return st.unpack(data)[0]
    if normalized in {"string", "utf8", "utf-8"}:
        data = read_chunk(process_handle, address, max_length)
        return data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    if normalized in {"wstring", "utf16", "utf-16", "utf16le"}:
        data = read_chunk(process_handle, address, max_length * 2)
        end = len(data)
        for i in range(0, len(data) - 1, 2):
            if data[i:i+2] == b"\x00\x00":
                end = i
                break
        return data[:end].decode("utf-16-le", errors="replace")
    raise ValueError(f"Неподдерживаемый тип: {type_name}")


def check_memory_value(process_handle: int, address: int, spec: ValueSpec) -> ValueCheckResult:
    try:
        actual = read_typed_value(process_handle, address, spec.type_name, spec.max_length)
    except Exception as exc:
        return ValueCheckResult(False, None, str(exc))

    if isinstance(actual, float):
        expected = float(spec.expected)
        if not math.isfinite(actual):
            return ValueCheckResult(False, actual, "прочитано NaN/Infinity")
        ok = abs(actual - expected) <= spec.tolerance
        reason = "ok" if ok else f"value mismatch: got {actual!r}, expected {expected!r} ± {spec.tolerance}"
        return ValueCheckResult(ok, actual, reason)
    if isinstance(actual, int):
        expected = int(spec.expected)
        ok = abs(actual - expected) <= spec.tolerance
        reason = "ok" if ok else f"value mismatch: got {actual}, expected {expected} ± {spec.tolerance}"
        return ValueCheckResult(ok, actual, reason)
    expected = str(spec.expected)
    ok = actual == expected
    return ValueCheckResult(ok, actual, "ok" if ok else f"value mismatch: got {actual!r}, expected {expected!r}")


def find_parents_for_targets(
    process_handle: int,
    regions: Sequence[MemoryRegion],
    targets_to_paths: Dict[int, List[Tuple[Edge, ...]]],
    pointer_size: int,
    max_offset: int,
    scan_step: int,
    chunk_size: int,
    candidate_cap: int,
    max_paths_per_node: int,
) -> Tuple[Dict[int, List[Tuple[Edge, ...]]], int, int, bool]:
    """Выполняет один обратный уровень поиска.

    Для каждого указателя P ищется T из текущего frontier, для которого:
        0 <= T - P <= max_offset
    """
    sorted_targets = sorted(targets_to_paths)
    if not sorted_targets:
        return {}, 0, 0, False

    new_paths: Dict[int, List[Tuple[Edge, ...]]] = {}
    path_signatures: Dict[int, set[Tuple[Tuple[int, int, int, int], ...]]] = {}

    unpacker = struct.Struct("<Q" if pointer_size == 8 else "<I")
    scanned_bytes = 0
    raw_hits = 0
    cap_reached = False
    last_progress = time.monotonic()
    last_liveness_check = last_progress

    for region in regions:
        if cap_reached:
            break

        for chunk_address, data, core_size in iter_region_chunks(
            process_handle,
            region,
            chunk_size,
            pointer_size,
        ):
            scanned_bytes += core_size
            max_start = min(core_size - 1, len(data) - pointer_size)
            if max_start < 0:
                continue

            for local_offset in range(0, max_start + 1, scan_step):
                pointer_value = unpacker.unpack_from(data, local_offset)[0]
                if pointer_value < MIN_VALID_POINTER:
                    continue

                left = bisect.bisect_left(sorted_targets, pointer_value)
                right = bisect.bisect_right(
                    sorted_targets,
                    pointer_value + max_offset,
                    lo=left,
                )
                if left == right:
                    continue

                source_address = chunk_address + local_offset
                existing = new_paths.setdefault(source_address, [])
                signatures = path_signatures.setdefault(source_address, set())

                for target in sorted_targets[left:right]:
                    edge = Edge(
                        source_address=source_address,
                        pointer_value=pointer_value,
                        offset=target - pointer_value,
                        target_address=target,
                    )
                    for child_path in targets_to_paths[target]:
                        if len(existing) >= max_paths_per_node:
                            break
                        path = (edge,) + child_path
                        signature = tuple(
                            (item.source_address, item.pointer_value, item.offset, item.target_address)
                            for item in path
                        )
                        if signature in signatures:
                            continue
                        signatures.add(signature)
                        existing.append(path)
                        raw_hits += 1
                    if len(existing) >= max_paths_per_node:
                        break

                if len(new_paths) >= candidate_cap:
                    cap_reached = True
                    break

            now = time.monotonic()
            if now - last_progress >= 2.0:
                print(
                    f"    [*] Прочитано: {scanned_bytes / (1024**2):.1f} MiB | "
                    f"узлов: {len(new_paths)} | путей: {raw_hits}"
                )
                last_progress = now

            if now - last_liveness_check >= 1.0:
                if not process_is_alive(process_handle):
                    raise RuntimeError("Процесс завершился во время сканирования")
                last_liveness_check = now

            if cap_reached:
                break

    return new_paths, scanned_bytes, raw_hits, cap_reached


def deduplicate_chains(chains: Iterable[PointerChain]) -> List[PointerChain]:
    unique: Dict[str, PointerChain] = {}
    for chain in chains:
        unique.setdefault(chain.signature, chain)
    return sorted(
        unique.values(),
        key=lambda chain: (
            chain.depth,
            chain.module.name.lower(),
            chain.root_offset,
            chain.offsets,
        ),
    )


def validate_and_filter_chains(
    process_handle: int,
    chains: Iterable[PointerChain],
    target_address: int,
    pointer_size: int,
    logger: Optional[DebugLogger] = None,
    announce_valid: bool = False,
) -> Tuple[List[PointerChain], int]:
    valid: List[PointerChain] = []
    rejected = 0
    unique = deduplicate_chains(chains)
    for index, chain in enumerate(unique, 1):
        callback = logger.debug if logger and logger.enabled else None
        result = validate_chain(
            process_handle, chain, target_address, pointer_size, callback, f"chain #{index}"
        )
        if result.valid:
            valid.append(chain)
            if announce_valid:
                print(f"[+] WORKING POINTER FOUND: {chain.pretty()}")
                if logger:
                    logger.write(
                        f"[+] WORKING POINTER FOUND: {chain.pretty()}",
                        force_file=logger.enabled,
                    )
        else:
            rejected += 1
    return valid, rejected


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def load_json_payload(path: str) -> dict:
    source = Path(path).expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"JSON не найден: {source}")
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Корневой элемент JSON должен быть объектом")
    return data


def load_previous_signatures(path: str) -> set[str]:
    if not path:
        return set()
    data = load_json_payload(path)
    return {
        str(item["signature"])
        for item in data.get("results", [])
        if isinstance(item, dict) and "signature" in item
    }


def parse_json_chains(data: dict, modules: Sequence[ModuleInfo]) -> Tuple[List[PointerChain], List[str]]:
    module_map = {module.name.lower(): module for module in modules}
    chains: List[PointerChain] = []
    errors: List[str] = []

    for index, item in enumerate(data.get("results", []), 1):
        if not isinstance(item, dict):
            errors.append(f"chain #{index}: запись не является объектом")
            continue
        try:
            module_name = str(item["module"])
            module = module_map.get(module_name.lower())
            if module is None:
                raise ValueError(f"module not loaded: {module_name}")
            root_offset = parse_int(str(item["root_offset"]))
            offsets = tuple(parse_int(str(value)) for value in item.get("offsets", []))
            if not offsets:
                raise ValueError("offsets list is empty")

            # Для быстрой перепроверки абсолютные адреса edge из старого запуска не нужны.
            # Они восстанавливаются динамически текущими значениями указателей.
            placeholder_edges = tuple(
                Edge(0, 0, offset, 0) for offset in offsets
            )
            chains.append(PointerChain(module, root_offset, placeholder_edges))
        except Exception as exc:
            errors.append(f"chain #{index}: {exc}")

    return deduplicate_chains(chains), errors


def chain_to_json(chain: PointerChain, target: int, stable: bool = False) -> dict:
    return {
        "module": chain.module.name,
        "module_path": chain.module.path,
        "root_offset": f"0x{chain.root_offset:X}",
        "offsets": [f"0x{offset:X}" for offset in chain.offsets],
        "depth": chain.depth,
        "signature": chain.signature,
        "validated": True,
        "resolved_address": f"0x{target:X}",
        "stable_against_previous_scan": stable,
        "display": chain.pretty(),
    }


def save_results(
    process_name: str,
    pid: int,
    target: int,
    pointer_size: int,
    max_offset: int,
    max_depth: int,
    scan_step: int,
    elapsed_seconds: float,
    chains: Sequence[PointerChain],
    stable_signatures: set[str],
    rejected_during_validation: int,
    scan_complete: bool,
) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = safe_filename_component(process_name)
    output_path = Path.cwd() / f"pointer_scan_{safe_name}_{timestamp}.json"

    payload = {
        "scanner_version": "3.0",
        "mode": "full_scan",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "process": process_name,
        "pid": pid,
        "target_address": f"0x{target:X}",
        "pointer_size": pointer_size,
        "max_offset": f"0x{max_offset:X}",
        "max_depth": max_depth,
        "scan_step": scan_step,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "scan_complete": scan_complete,
        "validation": {
            "enabled": True,
            "saved_only_valid_chains": True,
            "rejected_chains": rejected_during_validation,
        },
        "results": [
            chain_to_json(chain, target, chain.signature in stable_signatures)
            for chain in chains
        ],
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return output_path


def save_recheck_results(
    process_name: str,
    pid: int,
    target: int,
    source_json: str,
    elapsed_seconds: float,
    valid_chains: Sequence[PointerChain],
    failures: Sequence[dict],
    parse_errors: Sequence[str],
) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = safe_filename_component(process_name)
    output_path = Path.cwd() / f"pointer_recheck_{safe_name}_{timestamp}.json"
    payload = {
        "scanner_version": "3.0",
        "mode": "fast_json_recheck",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "process": process_name,
        "pid": pid,
        "target_address": f"0x{target:X}",
        "source_json": str(Path(source_json).expanduser()),
        "elapsed_seconds": round(elapsed_seconds, 3),
        "summary": {
            "loaded": len(valid_chains) + len(failures),
            "working": len(valid_chains),
            "failed": len(failures),
            "parse_errors": len(parse_errors),
        },
        "results": [chain_to_json(chain, target, True) for chain in valid_chains],
        "failed_checks": list(failures),
        "parse_errors": list(parse_errors),
    }
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return output_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_fast_recheck(logger: DebugLogger) -> int:
    pid, process_name = choose_process()
    target = parse_int(input("Новый текущий адрес целевого значения: "))
    json_path = input("Путь к JSON предыдущего скана: ").strip().strip('"')
    payload = load_json_payload(json_path)

    process_handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not process_handle:
        raise win_error("Не удалось открыть процесс")

    try:
        modules = enumerate_modules(pid)
        chains, parse_errors = parse_json_chains(payload, modules)
        print(f"[+] Загружено цепочек для проверки: {len(chains)}")
        if parse_errors:
            print(f"[!] Пропущено некорректных записей: {len(parse_errors)}")
            for message in parse_errors:
                logger.debug(f"[-] JSON parse: {message}")

        started = time.monotonic()
        valid: List[PointerChain] = []
        failures: List[dict] = []

        for index, chain in enumerate(chains, 1):
            callback = logger.debug if logger.enabled else None
            result = validate_chain(
                process_handle, chain, target, 8, callback, f"chain #{index}"
            )
            if result.valid:
                valid.append(chain)
                message = f"[+] WORKING POINTER FOUND [{index}/{len(chains)}]: {chain.pretty()}"
                print(message)
                logger.write(message, force_file=logger.enabled)
            else:
                failure = {
                    "index": index,
                    "signature": chain.signature,
                    "display": chain.pretty(),
                    "failed_at_level": result.failed_at_level,
                    "resolved_address": (
                        f"0x{result.resolved_address:X}"
                        if result.resolved_address is not None else None
                    ),
                    "reason": result.reason,
                }
                failures.append(failure)
                if logger.enabled:
                    logger.debug(
                        f"[-] Chain #{index} rejected: {result.reason}"
                    )

        elapsed = time.monotonic() - started
        output = save_recheck_results(
            process_name, pid, target, json_path, elapsed, valid, failures, parse_errors
        )
        print("\n" + "=" * 76)
        print(" БЫСТРАЯ ПЕРЕПРОВЕРКА ЗАВЕРШЕНА")
        print("=" * 76)
        print(f"[+] Рабочих: {len(valid)}")
        print(f"[-] Нерабочих: {len(failures)}")
        print(f"[!] Ошибок формата JSON: {len(parse_errors)}")
        print(f"[+] Время: {elapsed:.3f} сек.")
        print(f"[+] Результат: {output.resolve()}")
        return 0
    finally:
        kernel32.CloseHandle(process_handle)


def format_trace(trace: LevelTrace) -> str:
    status = "✓" if trace.ok else "✗"
    pointer = "READ FAILED" if trace.pointer_value is None else f"0x{trace.pointer_value:X}"
    next_addr = "-" if trace.next_address is None else f"0x{trace.next_address:X}"
    return (
        f"    Level {trace.level:<2} {status} | read 0x{trace.read_address:X} | "
        f"ptr {pointer} | offset +0x{trace.offset:X} | next {next_addr}"
        + ("" if trace.reason == "ok" else f" | {trace.reason}")
    )


def open_process_for_read(pid: int) -> int:
    handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        raise win_error("Не удалось открыть процесс")
    if not process_is_alive(handle):
        kernel32.CloseHandle(handle)
        raise RuntimeError("Выбранный процесс уже завершён")
    return handle


def load_chains_for_current_process(pid: int, json_path: str) -> Tuple[List[PointerChain], List[str], dict]:
    payload = load_json_payload(json_path)
    modules = enumerate_modules(pid)
    chains, errors = parse_json_chains(payload, modules)
    return chains, errors, payload


def run_chain_analyzer(logger: DebugLogger) -> int:
    pid, process_name = choose_process()
    target = parse_int(input("Текущий адрес целевого значения: "))
    json_path = input("Путь к JSON с цепочками: ").strip().strip('"')
    limit = ask_int("Сколько цепочек подробно вывести", 50, 1, 100000)
    handle = open_process_for_read(pid)
    try:
        chains, parse_errors, _ = load_chains_for_current_process(pid, json_path)
        print(f"[+] Загружено цепочек: {len(chains)}")
        if parse_errors:
            print(f"[!] Ошибок JSON: {len(parse_errors)}")
        reports = []
        working = 0
        for index, chain in enumerate(chains, 1):
            result = validate_chain_detailed(handle, chain, target, 8)
            if result.valid:
                working += 1
            report = {
                "index": index, "signature": chain.signature, "display": chain.pretty(),
                "valid": result.valid,
                "resolved_address": f"0x{result.resolved_address:X}" if result.resolved_address is not None else None,
                "failed_at_level": result.failed_at_level, "reason": result.reason,
                "levels": [
                    {
                        "level": t.level, "ok": t.ok, "read_address": f"0x{t.read_address:X}",
                        "pointer_value": f"0x{t.pointer_value:X}" if t.pointer_value is not None else None,
                        "offset": f"0x{t.offset:X}",
                        "next_address": f"0x{t.next_address:X}" if t.next_address is not None else None,
                        "reason": t.reason,
                    } for t in result.levels
                ],
            }
            reports.append(report)
            if index <= limit:
                status = "WORKING" if result.valid else "FAILED"
                print(f"\n[{index}/{len(chains)}] {status}: {chain.pretty()}")
                for trace in result.levels:
                    print(format_trace(trace))
                print(f"    Final: {result.reason}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path.cwd() / f"pointer_analysis_{safe_filename_component(process_name)}_{timestamp}.json"
        out.write_text(json.dumps({
            "scanner_version": "3.0", "mode": "chain_analyzer",
            "process": process_name, "pid": pid, "target_address": f"0x{target:X}",
            "source_json": json_path, "summary": {"loaded": len(chains), "working": working, "failed": len(chains)-working},
            "parse_errors": parse_errors, "reports": reports
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n[+] Рабочих: {working} | нерабочих: {len(chains)-working}")
        print(f"[+] Полный отчёт: {out.resolve()}")
        return 0
    finally:
        kernel32.CloseHandle(handle)


def ask_value_spec() -> ValueSpec:
    choices = {
        "1": "int8", "2": "uint8", "3": "int16", "4": "uint16",
        "5": "int32", "6": "uint32", "7": "int64", "8": "uint64",
        "9": "float", "10": "double", "11": "string UTF-8", "12": "string UTF-16",
    }
    selected = ask_choice("Тип значения:", choices, "5")
    type_map = {**{str(i): n for i, n in enumerate(["int8","uint8","int16","uint16","int32","uint32","int64","uint64","float","double"],1)}, "11":"string", "12":"wstring"}
    type_name = type_map[selected]
    raw_expected = input("Ожидаемое значение: ")
    if type_name in {"float", "double"}:
        expected = float(raw_expected.replace(",", "."))
        tolerance = float((input("Допуск ± [0]: ").strip() or "0").replace(",", "."))
    elif type_name in {"string", "wstring"}:
        expected = raw_expected
        tolerance = 0.0
    else:
        expected = int(raw_expected.strip(), 0)
        tolerance = float(input("Допуск ± [0]: ").strip() or "0")
    max_length = ask_int("Максимальная длина строки", 256, 1, 65536) if type_name in {"string", "wstring"} else 256
    return ValueSpec(type_name, expected, tolerance, max_length)


def run_value_validation(logger: DebugLogger) -> int:
    pid, process_name = choose_process()
    target = parse_int(input("Текущий адрес целевого значения: "))
    json_path = input("Путь к JSON с цепочками: ").strip().strip('"')
    spec = ask_value_spec()
    handle = open_process_for_read(pid)
    try:
        chains, parse_errors, _ = load_chains_for_current_process(pid, json_path)
        passed = []
        failed = []
        for index, chain in enumerate(chains, 1):
            address_result = validate_chain_detailed(handle, chain, target, 8)
            if not address_result.valid:
                failed.append({"index": index, "signature": chain.signature, "stage": "address", "reason": address_result.reason})
                continue
            value_result = check_memory_value(handle, target, spec)
            if value_result.valid:
                passed.append(chain)
                print(f"[+] VALUE MATCH [{index}/{len(chains)}]: {chain.pretty()} | value={value_result.actual!r}")
            else:
                failed.append({"index": index, "signature": chain.signature, "stage": "value", "actual": value_result.actual, "reason": value_result.reason})
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path.cwd() / f"pointer_value_check_{safe_filename_component(process_name)}_{timestamp}.json"
        out.write_text(json.dumps({
            "scanner_version":"3.0", "mode":"value_validation", "process":process_name, "pid":pid,
            "target_address":f"0x{target:X}", "source_json":json_path,
            "value_spec":{"type":spec.type_name,"expected":spec.expected,"tolerance":spec.tolerance,"max_length":spec.max_length},
            "summary":{"loaded":len(chains),"passed":len(passed),"failed":len(failed),"parse_errors":len(parse_errors)},
            "results":[chain_to_json(c,target,True) for c in passed], "failed_checks":failed, "parse_errors":parse_errors
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n[+] Прошли адрес + значение: {len(passed)}")
        print(f"[-] Отклонено: {len(failed)}")
        print(f"[+] Результат: {out.resolve()}")
        return 0
    finally:
        kernel32.CloseHandle(handle)


def show_info() -> int:
    print("""
FoxPointerScanner 3.0 работает только на Windows x64 и только читает память.

Режимы:
  1 — полный обратный BFS-скан с обязательной финальной проверкой;
  2 — быстрая перепроверка ранее сохранённых цепочек;
  3 — подробная диагностика каждого уровня цепочки;
  4 — проверка цепочек одновременно по адресу и значению памяти.

Важно: анализ уровней реализован отдельным валидатором и не изменяет
алгоритм поиска, frontier, кандидатов или правила построения цепочек.
""")
    return 0


def run_full_scan(logger: DebugLogger) -> int:
    pid, process_name = choose_process()
    target = parse_int(input("Текущий адрес целевого значения: "))

    scan_mode = ask_choice(
        "\nРежим поиска:",
        {"1": "Один оффсет (глубина 1)", "2": "Многоуровневая pointer-chain"},
        default="2",
    )
    max_depth = 1 if scan_mode == "1" else ask_int(
        "Максимальная глубина цепочки", 4, 2, 8
    )
    max_offset = ask_hex("Максимальный оффсет", 0x1000, 0, 0x100000)
    scan_step = int(ask_choice(
        "\nТочность сканирования:",
        {
            "8": "Быстро — 8-байтовое выравнивание",
            "4": "Сбалансированно — шаг 4 байта",
            "2": "Точно — шаг 2 байта",
            "1": "Максимально точно — каждый байт",
        },
        default="4",
    ))
    candidate_cap = ask_int("Лимит узлов на один уровень", 100000, 1000, 2_000_000)
    previous_path = input(
        "JSON предыдущего скана для сравнения (Enter — пропустить): "
    ).strip().strip('"')
    previous_signatures = load_previous_signatures(previous_path) if previous_path else set()
    if previous_signatures:
        print(f"[+] Загружено сигнатур предыдущего скана: {len(previous_signatures)}")

    process_handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not process_handle:
        raise win_error("Не удалось открыть процесс")

    try:
        if not process_is_alive(process_handle):
            raise RuntimeError("Выбранный процесс уже завершён")
        modules = enumerate_modules(pid)
        regions = enumerate_regions(process_handle)
        if not modules or not regions:
            raise RuntimeError("Не удалось получить модули или читаемые регионы")

        module_bases = [m.base for m in modules]
        total_readable = sum(r.size for r in regions)
        print("\n" + "-" * 76)
        print(f"[+] Процесс: {process_name} (PID {pid})")
        print(f"[+] TARGET: 0x{target:X}")
        print(f"[+] Модулей: {len(modules)} | регионов: {len(regions)}")
        print(f"[+] Читаемая память: {total_readable / (1024**3):.2f} GiB")
        print(f"[+] Глубина: {max_depth} | max offset: 0x{max_offset:X} | шаг: {scan_step}")
        print("-" * 76)

        frontier: Dict[int, List[Tuple[Edge, ...]]] = {target: [tuple()]}
        found_candidates: List[PointerChain] = []
        seen_heap_nodes = {target}
        scan_complete = True
        total_rejected = 0
        started = time.monotonic()

        for depth in range(1, max_depth + 1):
            if not frontier:
                print(f"[*] Уровень {depth}: дальнейшие узлы отсутствуют.")
                break
            print(f"\n[*] Уровень {depth}/{max_depth}: целей {len(frontier)}")
            logger.debug(f"[*] Starting level {depth}; frontier={len(frontier)}")
            new_paths, scanned_bytes, raw_hits, cap_reached = find_parents_for_targets(
                process_handle, regions, frontier, 8, max_offset, scan_step,
                DEFAULT_CHUNK_SIZE, candidate_cap, DEFAULT_MAX_PATHS_PER_NODE
            )
            print(
                f"[+] Уровень {depth}: {scanned_bytes/(1024**2):.1f} MiB, "
                f"узлов {len(new_paths)}, путей {raw_hits}"
            )
            if cap_reached:
                scan_complete = False
                print("[!] Достигнут лимит узлов; уровень неполный.")

            next_frontier: Dict[int, List[Tuple[Edge, ...]]] = {}
            static_candidates: List[PointerChain] = []
            for source_address, paths in new_paths.items():
                module = module_for_address(modules, module_bases, source_address)
                if module is not None:
                    static_candidates.extend(
                        PointerChain(module, source_address - module.base, path)
                        for path in paths
                    )
                elif source_address not in seen_heap_nodes:
                    next_frontier[source_address] = paths
                    seen_heap_nodes.add(source_address)

            valid_now, rejected_now = validate_and_filter_chains(
                process_handle, static_candidates, target, 8, logger, announce_valid=True
            )
            found_candidates.extend(valid_now)
            total_rejected += rejected_now
            print(f"[+] Статических кандидатов: {len(static_candidates)}")
            print(f"[+] Автопроверку прошли: {len(valid_now)}")
            if rejected_now:
                print(f"[-] Отклонено: {rejected_now}")
            frontier = next_frontier

        elapsed = time.monotonic() - started
        validated_chains, rejected_final = validate_and_filter_chains(
            process_handle, found_candidates, target, 8, logger, announce_valid=False
        )
        total_rejected += rejected_final
        stable_signatures = {
            c.signature for c in validated_chains if c.signature in previous_signatures
        }
        display_chains = sorted(
            validated_chains,
            key=lambda c: (c.signature not in stable_signatures, c.depth, c.root_offset, c.offsets),
        )

        print("\n" + "=" * 76)
        print(" РЕЗУЛЬТАТ")
        print("=" * 76)
        print(f"[+] Время: {elapsed:.2f} сек.")
        print(f"[+] Рабочих уникальных цепочек: {len(display_chains)}")
        print(f"[-] Отклонено проверкой: {total_rejected}")
        print(f"[+] Полнота: {'полная' if scan_complete else 'неполная'}")
        if previous_signatures:
            print(f"[+] Совпало с предыдущим сканом: {len(stable_signatures)}")
        for index, chain in enumerate(display_chains[:50], 1):
            stable = " [STABLE]" if chain.signature in stable_signatures else ""
            print(f"    {index:>3}. {chain.pretty()}{stable}")

        output = save_results(
            process_name, pid, target, 8, max_offset, max_depth, scan_step, elapsed,
            display_chains, stable_signatures, total_rejected, scan_complete
        )
        print(f"\n[+] JSON сохранён: {output.resolve()}")
        return 0
    finally:
        kernel32.CloseHandle(process_handle)


def main() -> int:
    print("=" * 76)
    print(" FoxPointerScanner 3.0 — READ-ONLY POINTER SCANNER")
    print("=" * 76)
    print("[i] Программа только читает память процесса.\n")

    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[-] Требуется 64-битная версия Python/EXE.")
        return 1

    logger: Optional[DebugLogger] = None
    try:
        mode = ask_choice(
            "Режим работы:",
            {
                "1": "Новый полный скан",
                "2": "Быстрая перепроверка цепочек из JSON",
                "3": "Подробный анализ каждого уровня цепочки",
                "4": "Проверка цепочек по адресу и значению памяти",
                "5": "Информация",
                "6": "Выход",
            },
            default="1",
        )
        if mode == "6":
            return 0
        if mode == "5":
            show_info()
            input("\nНажмите Enter для выхода...")
            return 0
        debug_enabled = ask_yes_no("Включить подробный Debug Mode", default=False)
        logger = DebugLogger(debug_enabled)
        if debug_enabled:
            print(f"[+] Debug-журнал: {logger.log_path.resolve()}")

        runners = {
            "1": run_full_scan,
            "2": run_fast_recheck,
            "3": run_chain_analyzer,
            "4": run_value_validation,
        }
        result = runners[mode](logger)
        input("\nНажмите Enter для выхода...")
        return result
    except KeyboardInterrupt:
        print("\n[!] Операция остановлена пользователем.")
        return 130
    except Exception as exc:
        print(f"\n[-] Ошибка: {exc}")
        if logger:
            logger.write(f"[-] Fatal error: {exc}", force_file=logger.enabled)
        print("[i] Проверьте PID, TARGET, разрядность и права доступа.")
        input("\nНажмите Enter для выхода...")
        return 1
    finally:
        if logger:
            logger.close()


if __name__ == "__main__":
    raise SystemExit(main())
