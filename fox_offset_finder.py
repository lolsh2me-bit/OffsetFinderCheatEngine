#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Read-only multi-level pointer scanner for Windows.

Назначение:
- Ищет цепочки вида:
    [[module.exe + ROOT] + off1] + off2 ... = TARGET
- Ничего не записывает в память процесса.
- Подходит для анализа собственных программ и тестовых стендов.

Важно:
- Для 64-битного процесса запускай 64-битную сборку Python/EXE.
- Сканирование больших процессов может занимать долгое время.
- Даже хороший pointer scan не гарантирует стабильную цепочку:
  адрес может вычисляться динамически или не иметь статического корня.
"""

from __future__ import annotations

import bisect
import ctypes
import json
import os
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from ctypes import wintypes


if os.name != "nt":
    print("Этот скрипт работает только на Windows.")
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
PAGE_EXECUTE = 0x10
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

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


# ---------------------------------------------------------------------------
# Structures
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
# Function signatures
# ---------------------------------------------------------------------------

kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]
kernel32.Process32FirstW.restype = wintypes.BOOL

kernel32.Process32NextW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]
kernel32.Process32NextW.restype = wintypes.BOOL

kernel32.Module32FirstW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(MODULEENTRY32W),
]
kernel32.Module32FirstW.restype = wintypes.BOOL

kernel32.Module32NextW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(MODULEENTRY32W),
]
kernel32.Module32NextW.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
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

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.GetNativeSystemInfo.argtypes = [ctypes.c_void_p]
kernel32.GetNativeSystemInfo.restype = None


# ---------------------------------------------------------------------------
# Data classes
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
        parts = [f"{self.module.name}+0x{self.root_offset:X}"]
        parts.extend(f"+0x{offset:X}" for offset in self.offsets)
        return " -> ".join(parts)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def win_error(prefix: str) -> OSError:
    code = ctypes.get_last_error()
    return OSError(code, f"{prefix}: {ctypes.FormatError(code).strip()}")


def parse_int(text: str) -> int:
    cleaned = text.strip().replace("`", "").replace("_", "").replace(" ", "")
    if not cleaned:
        raise ValueError("Пустое число")
    return int(cleaned, 0 if cleaned.lower().startswith(("0x", "0o", "0b")) else 16)


def ask_int(prompt: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        raw = input(f"{prompt} [{default}]: ").strip()
        if not raw:
            return default
        try:
            value = int(raw, 10)
            if minimum <= value <= maximum:
                return value
            print(f"Нужно число от {minimum} до {maximum}.")
        except ValueError:
            print("Тут нужно обычное десятичное число.")


def ask_hex(prompt: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        raw = input(f"{prompt} [0x{default:X}]: ").strip()
        if not raw:
            return default
        try:
            value = parse_int(raw)
            if minimum <= value <= maximum:
                return value
            print(f"Нужно значение от 0x{minimum:X} до 0x{maximum:X}.")
        except ValueError:
            print("Не понял число. Пример: 0x1000")


def find_processes(name: str) -> List[Tuple[int, str]]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise win_error("CreateToolhelp32Snapshot(PROCESS)")

    result: List[Tuple[int, str]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)

        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            exe = entry.szExeFile
            if exe.lower() == name.lower() or name.lower() in exe.lower():
                result.append((int(entry.th32ProcessID), exe))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    return result


def choose_process() -> Tuple[int, str]:
    raw = input("Имя процесса или PID: ").strip()
    if not raw:
        raise ValueError("Процесс не указан")

    if raw.isdigit():
        return int(raw), f"PID {raw}"

    matches = find_processes(raw)
    if not matches:
        raise RuntimeError(f"Процесс «{raw}» не найден")

    if len(matches) == 1:
        return matches[0]

    print("\nНашёл несколько процессов:")
    for index, (pid, exe) in enumerate(matches, 1):
        print(f"  {index}. {exe} — PID {pid}")

    while True:
        choice = input("Выбери номер: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(matches):
            return matches[int(choice) - 1]
        print("Нужен номер из списка.")


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
                    name=entry.szModule,
                    path=entry.szExePath,
                    base=int(base),
                    size=int(entry.modBaseSize),
                )
            )
            ok = kernel32.Module32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    modules.sort(key=lambda module: module.base)
    return modules


def module_for_address(modules: Sequence[ModuleInfo], address: int) -> Optional[ModuleInfo]:
    # Модулей обычно немного, линейный проход здесь достаточно быстрый.
    for module in modules:
        if module.base <= address < module.end:
            return module
    return None


def enumerate_regions(process_handle: int) -> List[MemoryRegion]:
    regions: List[MemoryRegion] = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()

    # Практический верхний предел пользовательского адресного пространства x64.
    max_address = 0x00007FFFFFFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFFFFFF

    while address < max_address:
        result = kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if result == 0:
            break

        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize or 0)
        protect = int(mbi.Protect)

        readable = (
            mbi.State == MEM_COMMIT
            and not (protect & PAGE_GUARD)
            and not (protect & PAGE_NOACCESS)
            and (protect & 0xFF) in READABLE_PROTECTIONS
        )

        if readable and size > 0:
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


def iter_region_chunks(
    process_handle: int,
    region: MemoryRegion,
    chunk_size: int,
    overlap: int,
) -> Iterable[Tuple[int, bytes]]:
    cursor = region.base
    end = region.end

    while cursor < end:
        request_size = min(chunk_size, end - cursor)
        data = read_chunk(process_handle, cursor, request_size)

        if data:
            yield cursor, data

        advance = request_size
        if request_size > overlap:
            advance -= overlap

        if advance <= 0:
            break
        cursor += advance


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
    """
    Один обратный уровень.

    Для каждого значения P в памяти ищется цель T, для которой:
        P + offset == T
        0 <= offset <= max_offset
    """
    sorted_targets = sorted(targets_to_paths)
    new_paths: Dict[int, List[Tuple[Edge, ...]]] = {}

    unpack_format = "<Q" if pointer_size == 8 else "<I"
    scanned_bytes = 0
    raw_hits = 0
    cap_reached = False
    last_progress = time.monotonic()

    for region_index, region in enumerate(regions, 1):
        if cap_reached:
            break

        for chunk_address, data in iter_region_chunks(
            process_handle,
            region,
            chunk_size,
            pointer_size - 1,
        ):
            scanned_bytes += len(data)
            usable = len(data) - pointer_size + 1

            for local_offset in range(0, max(0, usable), scan_step):
                pointer_value = struct.unpack_from(unpack_format, data, local_offset)[0]

                # Нули и слишком маленькие значения почти всегда мусор.
                if pointer_value < 0x10000:
                    continue

                first = bisect.bisect_left(sorted_targets, pointer_value)
                index = first

                while index < len(sorted_targets):
                    target = sorted_targets[index]
                    offset = target - pointer_value

                    if offset < 0:
                        index += 1
                        continue
                    if offset > max_offset:
                        break

                    source_address = chunk_address + local_offset
                    edge = Edge(
                        source_address=source_address,
                        pointer_value=pointer_value,
                        offset=offset,
                        target_address=target,
                    )

                    existing = new_paths.setdefault(source_address, [])
                    for child_path in targets_to_paths[target]:
                        path = (edge,) + child_path
                        if path not in existing:
                            existing.append(path)
                            raw_hits += 1
                            if len(existing) >= max_paths_per_node:
                                break

                    if len(new_paths) >= candidate_cap:
                        cap_reached = True
                        break

                    index += 1

                if cap_reached:
                    break

            now = time.monotonic()
            if now - last_progress >= 2.5:
                print(
                    f"    ищу... прочитал {scanned_bytes / (1024**2):.1f} МБ, "
                    f"зацепок: {len(new_paths)}"
                )
                last_progress = now

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


def load_previous_signatures(path: str) -> set[str]:
    if not path:
        return set()

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        str(item["signature"])
        for item in data.get("results", [])
        if "signature" in item
    }


def save_results(
    process_name: str,
    pid: int,
    target: int,
    pointer_size: int,
    max_offset: int,
    max_depth: int,
    chains: Sequence[PointerChain],
    stable_signatures: set[str],
) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in process_name)
    output_path = Path(f"pointer_scan_{safe_name}_{timestamp}.json")

    payload = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "process": process_name,
        "pid": pid,
        "target_address": f"0x{target:X}",
        "pointer_size": pointer_size,
        "max_offset": f"0x{max_offset:X}",
        "max_depth": max_depth,
        "results": [
            {
                "module": chain.module.name,
                "module_path": chain.module.path,
                "root_offset": f"0x{chain.root_offset:X}",
                "offsets": [f"0x{offset:X}" for offset in chain.offsets],
                "depth": chain.depth,
                "signature": chain.signature,
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
# Main scanner
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 72)
    print(" POINTER SCANNER — read-only, без записи в память")
    print("=" * 72)
    print("Йоу. Сейчас попробуем вытащить нормальные pointer-chain'ы.")
    print("Работает только с процессами, которые тебе разрешено анализировать.\n")

    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("Бро, это 32-битная сборка.")
        print("Для 64-битной игры собери EXE через Python x64.")
        return 1

    try:
        pid, process_name = choose_process()
        target = parse_int(input("Текущий адрес значения, например 0x123ABC: "))

        max_offset = ask_hex(
            "Максимальный оффсет",
            default=0x1000,
            minimum=0,
            maximum=0x100000,
        )
        max_depth = ask_int(
            "Максимальная глубина цепочки",
            default=4,
            minimum=1,
            maximum=8,
        )
        scan_step = ask_int(
            "Шаг чтения указателей (4 точнее, 8 быстрее)",
            default=4,
            minimum=1,
            maximum=8,
        )
        candidate_cap = ask_int(
            "Лимит кандидатов на один уровень",
            default=25000,
            minimum=100,
            maximum=500000,
        )

        previous_path = input(
            "JSON прошлого скана для проверки стабильности "
            "(Enter — пропустить): "
        ).strip()

        previous_signatures: set[str] = set()
        if previous_path:
            previous_signatures = load_previous_signatures(previous_path)
            print(f"Загрузил прошлый скан: {len(previous_signatures)} сигнатур.")

        process_handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False,
            pid,
        )
        if not process_handle:
            raise win_error(
                "Не удалось открыть процесс. Попробуй запустить от администратора"
            )

        try:
            modules = enumerate_modules(pid)
            regions = enumerate_regions(process_handle)

            if not modules:
                raise RuntimeError("Не удалось получить список модулей процесса")
            if not regions:
                raise RuntimeError("Не найдено доступных для чтения областей памяти")

            total_readable = sum(region.size for region in regions)
            print(f"\nПроцесс: {process_name} (PID {pid})")
            print(f"Цель: 0x{target:X}")
            print(f"Модулей: {len(modules)}")
            print(f"Читаемых регионов: {len(regions)}")
            print(f"Объём читаемой памяти: {total_readable / (1024**3):.2f} ГБ")
            print(
                f"Параметры: depth={max_depth}, "
                f"max_offset=0x{max_offset:X}, step={scan_step}\n"
            )

            # Адрес текущего узла -> варианты пути от него до конечной цели.
            frontier: Dict[int, List[Tuple[Edge, ...]]] = {target: [tuple()]}
            found_chains: List[PointerChain] = []
            global_seen_nodes = {target}

            started = time.monotonic()

            for depth in range(1, max_depth + 1):
                if not frontier:
                    print(f"[{depth}/{max_depth}] Больше некуда копать.")
                    break

                print(
                    f"[{depth}/{max_depth}] Сканирую уровень. "
                    f"Целей на входе: {len(frontier)}"
                )

                new_paths, scanned_bytes, raw_hits, cap_reached = find_parents_for_targets(
                    process_handle=process_handle,
                    regions=regions,
                    targets_to_paths=frontier,
                    pointer_size=8,
                    max_offset=max_offset,
                    scan_step=scan_step,
                    chunk_size=4 * 1024 * 1024,
                    candidate_cap=candidate_cap,
                    max_paths_per_node=4,
                )

                print(
                    f"    уровень готов: {scanned_bytes / (1024**2):.1f} МБ, "
                    f"узлов {len(new_paths)}, путей {raw_hits}"
                )

                if cap_reached:
                    print(
                        "    ух, кандидатов слишком много — упёрлись в лимит. "
                        "Уменьши max offset или увеличь лимит."
                    )

                next_frontier: Dict[int, List[Tuple[Edge, ...]]] = {}
                roots_this_level = 0

                for source_address, paths in new_paths.items():
                    module = module_for_address(modules, source_address)

                    if module is not None:
                        for path in paths:
                            found_chains.append(
                                PointerChain(
                                    module=module,
                                    root_offset=source_address - module.base,
                                    edges=path,
                                )
                            )
                            roots_this_level += 1
                    elif source_address not in global_seen_nodes:
                        next_frontier[source_address] = paths
                        global_seen_nodes.add(source_address)

                if roots_this_level:
                    print(
                        f"    йоу бро, кайф — статических цепочек на этом "
                        f"уровне: {roots_this_level}"
                    )
                elif new_paths:
                    print(
                        "    что-то нашёл, но пока это heap-адреса. "
                        "Копаю глубже..."
                    )
                else:
                    print(
                        "    эх, тут пусто. Либо цепочки нет, либо параметры "
                        "слишком жёсткие."
                    )

                frontier = next_frontier

            elapsed = time.monotonic() - started
            chains = deduplicate_chains(found_chains)

            stable_signatures = {
                chain.signature
                for chain in chains
                if chain.signature in previous_signatures
            }

            print("\n" + "=" * 72)
            print(f"Готово за {elapsed:.1f} сек.")
            print(f"Уникальных статических цепочек: {len(chains)}")

            if previous_signatures:
                print(f"Совпало с прошлым сканом: {len(stable_signatures)}")

            if chains:
                print("\nЛучшие результаты:")
                display_chains = sorted(
                    chains,
                    key=lambda chain: (
                        chain.signature not in stable_signatures,
                        chain.depth,
                        chain.root_offset,
                    ),
                )

                for index, chain in enumerate(display_chains[:50], 1):
                    stable_mark = (
                        " [СТАБИЛЬНАЯ, совпала с прошлым сканом]"
                        if chain.signature in stable_signatures
                        else ""
                    )
                    print(f"{index:>3}. {chain.pretty()}{stable_mark}")

                if len(chains) > 50:
                    print(f"...ещё {len(chains) - 50} результатов будут в JSON.")
            else:
                print(
                    "\nНичего статического не нашлось. Не обязательно баг:"
                    "\n- значение может не иметь обычной pointer-chain;"
                    "\n- max offset может быть мал;"
                    "\n- глубины может не хватать;"
                    "\n- адрес мог измениться во время поиска;"
                    "\n- часть памяти может быть недоступна."
                )

            output_path = save_results(
                process_name=process_name,
                pid=pid,
                target=target,
                pointer_size=8,
                max_offset=max_offset,
                max_depth=max_depth,
                chains=chains,
                stable_signatures=stable_signatures,
            )

            print(f"\nРезультаты сохранены: {output_path.resolve()}")
            print(
                "Для более точного результата: перезапусти программу, "
                "найди новый адрес значения и укажи этот JSON как прошлый скан."
            )
            print("Так случайный мусор отсеется, а стабильные цепочки останутся.")
            input("\nEnter — закрыть...")
            return 0

        finally:
            kernel32.CloseHandle(process_handle)

    except KeyboardInterrupt:
        print("\nОкей, остановили поиск.")
        return 130
    except Exception as exc:
        print(f"\nБро, что-то пошло не так: {exc}")
        print(
            "Проверь имя/PID, адрес, разрядность EXE и права доступа к процессу."
        )
        input("\nEnter — закрыть...")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
