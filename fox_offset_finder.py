#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FoxPointerScanner — read-only pointer scanner for Windows.

Возможности:
- поиск одноуровневых и многоуровневых pointer-chain;
- обязательная автоматическая проверка найденных цепочек;
- сохранение только цепочек, которые действительно разрешаются в TARGET;
- сравнение сигнатур с предыдущим JSON-сканом;
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
import os
import re
import struct
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple
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

def validate_chain(
    process_handle: int,
    chain: PointerChain,
    target_address: int,
    pointer_size: int,
) -> ValidationResult:
    current_address = chain.module.base + chain.root_offset

    for level, offset in enumerate(chain.offsets, start=1):
        pointer_value = read_pointer(process_handle, current_address, pointer_size)
        if pointer_value is None:
            return ValidationResult(
                valid=False,
                resolved_address=None,
                failed_at_level=level,
                reason=f"ReadProcessMemory failed at 0x{current_address:X}",
            )
        current_address = pointer_value + offset

    if current_address != target_address:
        return ValidationResult(
            valid=False,
            resolved_address=current_address,
            failed_at_level=None,
            reason=(
                f"resolved to 0x{current_address:X}, expected 0x{target_address:X}"
            ),
        )

    return ValidationResult(
        valid=True,
        resolved_address=current_address,
        failed_at_level=None,
        reason="ok",
    )


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
) -> Tuple[List[PointerChain], int]:
    valid: List[PointerChain] = []
    rejected = 0
    for chain in deduplicate_chains(chains):
        result = validate_chain(process_handle, chain, target_address, pointer_size)
        if result.valid:
            valid.append(chain)
        else:
            rejected += 1
    return valid, rejected


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def load_previous_signatures(path: str) -> set[str]:
    if not path:
        return set()
    data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    return {
        str(item["signature"])
        for item in data.get("results", [])
        if isinstance(item, dict) and "signature" in item
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
        "scanner_version": "2.0",
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
            {
                "module": chain.module.name,
                "module_path": chain.module.path,
                "root_offset": f"0x{chain.root_offset:X}",
                "offsets": [f"0x{offset:X}" for offset in chain.offsets],
                "depth": chain.depth,
                "signature": chain.signature,
                "validated": True,
                "resolved_address": f"0x{target:X}",
                "stable_against_previous_scan": chain.signature in stable_signatures,
                "display": chain.pretty(),
                "edges": [
                    {
                        "source_address": f"0x{edge.source_address:X}",
                        "pointer_value": f"0x{edge.pointer_value:X}",
                        "offset": f"0x{edge.offset:X}",
                        "target_address": f"0x{edge.target_address:X}",
                    }
                    for edge in chain.edges
                ],
            }
            for chain in chains
        ],
    }

    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return output_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 76)
    print(" FoxPointerScanner 2.0 — READ-ONLY POINTER SCANNER")
    print("=" * 76)
    print("[i] Программа не записывает данные в память выбранного процесса.")
    print("[i] Используйте её только для разрешённого анализа.\n")

    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[-] Запущена 32-битная версия Python/EXE.")
        print("[-] Для анализа 64-битного процесса требуется 64-битная сборка.")
        return 1

    try:
        pid, process_name = choose_process()
        target = parse_int(input("Текущий адрес целевого значения: "))

        scan_mode = ask_choice(
            "\nРежим поиска:",
            {
                "1": "Один оффсет (глубина 1)",
                "2": "Многоуровневая pointer-chain",
            },
            default="2",
        )
        max_depth = 1 if scan_mode == "1" else ask_int(
            "Максимальная глубина цепочки",
            default=4,
            minimum=2,
            maximum=8,
        )

        max_offset = ask_hex(
            "Максимальный оффсет",
            default=0x1000,
            minimum=0,
            maximum=0x100000,
        )
        scan_step = int(
            ask_choice(
                "\nТочность сканирования:",
                {
                    "8": "Быстро — только 8-байтовое выравнивание",
                    "4": "Сбалансированно — шаг 4 байта",
                    "2": "Точно — шаг 2 байта",
                    "1": "Максимально точно — каждый байт (значительно медленнее)",
                },
                default="4",
            )
        )
        candidate_cap = ask_int(
            "Лимит узлов на один уровень",
            default=100000,
            minimum=1000,
            maximum=2_000_000,
        )

        previous_path = input(
            "JSON предыдущего скана для сравнения (Enter — пропустить): "
        ).strip().strip('"')
        previous_signatures = load_previous_signatures(previous_path) if previous_path else set()
        if previous_signatures:
            print(f"[+] Загружено сигнатур предыдущего скана: {len(previous_signatures)}")

        process_handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False,
            pid,
        )
        if not process_handle:
            raise win_error("Не удалось открыть процесс")

        try:
            if not process_is_alive(process_handle):
                raise RuntimeError("Выбранный процесс уже завершён")

            modules = enumerate_modules(pid)
            regions = enumerate_regions(process_handle)
            if not modules:
                raise RuntimeError("Не удалось получить список модулей процесса")
            if not regions:
                raise RuntimeError("Не найдены читаемые регионы памяти")

            module_bases = [module.base for module in modules]
            total_readable = sum(region.size for region in regions)

            print("\n" + "-" * 76)
            print(f"[+] Процесс: {process_name} (PID {pid})")
            print(f"[+] Целевой адрес: 0x{target:X}")
            print(f"[+] Модулей: {len(modules)}")
            print(f"[+] Читаемых регионов: {len(regions)}")
            print(f"[+] Читаемая память: {total_readable / (1024**3):.2f} GiB")
            print(f"[+] Глубина: {max_depth}")
            print(f"[+] Максимальный оффсет: 0x{max_offset:X}")
            print(f"[+] Шаг: {scan_step} байт")
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

                print(
                    f"\n[*] Уровень {depth}/{max_depth}: "
                    f"поиск родителей для {len(frontier)} целей..."
                )
                new_paths, scanned_bytes, raw_hits, cap_reached = find_parents_for_targets(
                    process_handle=process_handle,
                    regions=regions,
                    targets_to_paths=frontier,
                    pointer_size=8,
                    max_offset=max_offset,
                    scan_step=scan_step,
                    chunk_size=DEFAULT_CHUNK_SIZE,
                    candidate_cap=candidate_cap,
                    max_paths_per_node=DEFAULT_MAX_PATHS_PER_NODE,
                )

                print(
                    f"[+] Уровень {depth} завершён: "
                    f"{scanned_bytes / (1024**2):.1f} MiB, "
                    f"узлов {len(new_paths)}, путей {raw_hits}."
                )
                if cap_reached:
                    scan_complete = False
                    print(
                        "[!] Достигнут лимит узлов. Результат текущего уровня неполный. "
                        "Уменьшите максимальный оффсет или увеличьте лимит."
                    )

                next_frontier: Dict[int, List[Tuple[Edge, ...]]] = {}
                static_candidates: List[PointerChain] = []

                for source_address, paths in new_paths.items():
                    module = module_for_address(modules, module_bases, source_address)
                    if module is not None:
                        static_candidates.extend(
                            PointerChain(
                                module=module,
                                root_offset=source_address - module.base,
                                edges=path,
                            )
                            for path in paths
                        )
                    elif source_address not in seen_heap_nodes:
                        next_frontier[source_address] = paths
                        seen_heap_nodes.add(source_address)

                valid_now, rejected_now = validate_and_filter_chains(
                    process_handle,
                    static_candidates,
                    target,
                    pointer_size=8,
                )
                found_candidates.extend(valid_now)
                total_rejected += rejected_now

                print(f"[+] Статических кандидатов: {len(static_candidates)}")
                print(f"[+] Автопроверку прошли: {len(valid_now)}")
                if rejected_now:
                    print(f"[-] Отклонено нерабочих цепочек: {rejected_now}")

                frontier = next_frontier

            elapsed = time.monotonic() - started

            # Повторная финальная проверка защищает от изменения памяти во время скана.
            validated_chains, rejected_final = validate_and_filter_chains(
                process_handle,
                found_candidates,
                target,
                pointer_size=8,
            )
            total_rejected += rejected_final

            stable_signatures = {
                chain.signature
                for chain in validated_chains
                if chain.signature in previous_signatures
            }

            display_chains = sorted(
                validated_chains,
                key=lambda chain: (
                    chain.signature not in stable_signatures,
                    chain.depth,
                    chain.root_offset,
                    chain.offsets,
                ),
            )

            print("\n" + "=" * 76)
            print(" РЕЗУЛЬТАТ")
            print("=" * 76)
            print(f"[+] Время сканирования: {elapsed:.2f} сек.")
            print(f"[+] Рабочих уникальных цепочек: {len(display_chains)}")
            print(f"[-] Всего отклонено автопроверкой: {total_rejected}")
            print(f"[+] Полнота сканирования: {'полная' if scan_complete else 'неполная'}")
            if previous_signatures:
                print(f"[+] Совпало с предыдущим сканом: {len(stable_signatures)}")

            if display_chains:
                print("\n[+] Лучшие подтверждённые цепочки:")
                for index, chain in enumerate(display_chains[:50], 1):
                    stable = " [STABLE]" if chain.signature in stable_signatures else ""
                    print(f"    {index:>3}. {chain.pretty()}{stable}")
                if len(display_chains) > 50:
                    print(f"    ...ещё {len(display_chains) - 50} цепочек сохранено в JSON.")
            else:
                print("\n[-] Подтверждённые статические цепочки не найдены.")
                print("[i] Возможные причины: недостаточная глубина, малый max_offset,")
                print("[i] динамическое вычисление адреса или изменение TARGET во время скана.")

            output_path = save_results(
                process_name=process_name,
                pid=pid,
                target=target,
                pointer_size=8,
                max_offset=max_offset,
                max_depth=max_depth,
                scan_step=scan_step,
                elapsed_seconds=elapsed,
                chains=display_chains,
                stable_signatures=stable_signatures,
                rejected_during_validation=total_rejected,
                scan_complete=scan_complete,
            )
            print(f"\n[+] JSON сохранён: {output_path.resolve()}")
            print("[i] В файл записаны только цепочки, прошедшие автоматическую проверку.")
            input("\nНажмите Enter для выхода...")
            return 0

        finally:
            kernel32.CloseHandle(process_handle)

    except KeyboardInterrupt:
        print("\n[!] Сканирование остановлено пользователем.")
        return 130
    except Exception as exc:
        print(f"\n[-] Ошибка: {exc}")
        print("[i] Проверьте PID, адрес, разрядность Python/EXE и права доступа.")
        input("\nНажмите Enter для выхода...")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
