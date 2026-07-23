import ctypes
import struct
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass


# ============================================================
# Direct Pointer Candidate Scanner (read-only, Windows x64)
#
# Ищет только прямую зависимость:
#     pointer_value + offset == target_address
#
# Это НЕ полноценный многоуровневый pointer scan.
# Используйте только для собственных программ или там,
# где у вас есть явное разрешение на тестирование.
# ============================================================


# -------------------- WinAPI constants --------------------

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

MEM_COMMIT = 0x1000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

ERROR_NO_MORE_FILES = 18
ERROR_INVALID_PARAMETER = 87
ERROR_PARTIAL_COPY = 299

READABLE_BASE_PROTECTIONS = {
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
}

CHUNK_SIZE = 4 * 1024 * 1024
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_X64 = 0x00007FFFFFFFFFFF
MAX_RESULTS_DEFAULT = 100_000

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


# -------------------- Structures --------------------

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
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """
    MEMORY_BASIC_INFORMATION для 64-битной Windows.

    PartitionId присутствует в современной x64-структуре и сохраняет
    правильное выравнивание RegionSize и последующих полей.
    """

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


@dataclass(frozen=True)
class Candidate:
    offset: int
    pointer_location: int
    pointer_value: int


# -------------------- WinAPI signatures --------------------

kernel32.CreateToolhelp32Snapshot.argtypes = [
    wintypes.DWORD,
    wintypes.DWORD,
]
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

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


# -------------------- Helpers --------------------

def format_win_error(error_code: int | None = None) -> str:
    if error_code is None:
        error_code = ctypes.get_last_error()

    try:
        return ctypes.FormatError(error_code).strip()
    except Exception:
        return f"WinAPI error {error_code}"


def get_pid_by_name(process_name: str) -> int | None:
    snapshot = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0,
    )

    if snapshot == INVALID_HANDLE_VALUE:
        error_code = ctypes.get_last_error()
        raise OSError(
            error_code,
            f"CreateToolhelp32Snapshot: {format_win_error(error_code)}",
        )

    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)

        if not kernel32.Process32FirstW(
            snapshot,
            ctypes.byref(entry),
        ):
            error_code = ctypes.get_last_error()

            if error_code == ERROR_NO_MORE_FILES:
                return None

            raise OSError(
                error_code,
                f"Process32FirstW: {format_win_error(error_code)}",
            )

        requested_name = process_name.casefold()

        while True:
            if entry.szExeFile.casefold() == requested_name:
                return int(entry.th32ProcessID)

            if not kernel32.Process32NextW(
                snapshot,
                ctypes.byref(entry),
            ):
                break

        return None

    finally:
        kernel32.CloseHandle(snapshot)


def is_readable_region(
    mbi: MEMORY_BASIC_INFORMATION,
) -> bool:
    if mbi.State != MEM_COMMIT:
        return False

    if mbi.Protect == 0:
        return False

    if mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS):
        return False

    base_protection = mbi.Protect & 0xFF
    return base_protection in READABLE_BASE_PROTECTIONS


def read_process_chunk(
    process_handle: wintypes.HANDLE,
    address: int,
    size: int,
) -> bytes:
    """
    Возвращает реально прочитанные байты.

    Даже если ReadProcessMemory возвращает False из-за частичного чтения,
    bytes_read иногда всё равно содержит полезную часть данных.
    """

    if size <= 0:
        return b""

    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)

    ctypes.set_last_error(0)

    kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )

    if bytes_read.value == 0:
        return b""

    return buffer.raw[:bytes_read.value]


def scan_memory_for_direct_candidates(
    process_handle: wintypes.HANDLE,
    target_address: int,
    max_offset: int,
    pointer_size: int = 8,
    alignment: int = 4,
    max_results: int = MAX_RESULTS_DEFAULT,
) -> tuple[list[Candidate], int, int]:
    """
    Ищет прямых кандидатов:

        pointer_value + offset == target_address

    Возвращает:
        candidates,
        bytes_scanned,
        regions_scanned
    """

    if pointer_size not in (4, 8):
        raise ValueError(
            "Размер указателя должен быть 4 или 8 байт."
        )

    if alignment not in (1, 2, 4, 8):
        raise ValueError(
            "Шаг проверки должен быть 1, 2, 4 или 8."
        )

    if alignment > pointer_size:
        raise ValueError(
            "Шаг проверки не должен превышать размер указателя."
        )

    if target_address <= 0:
        raise ValueError(
            "Целевой адрес должен быть больше нуля."
        )

    if max_offset < 0:
        raise ValueError(
            "Максимальный оффсет не может быть отрицательным."
        )

    if max_results <= 0:
        raise ValueError(
            "Лимит результатов должен быть больше нуля."
        )

    unpack_format = "<I" if pointer_size == 4 else "<Q"

    maximum_pointer_value = (
        0xFFFFFFFF
        if pointer_size == 4
        else 0xFFFFFFFFFFFFFFFF
    )

    lower_bound = max(
        0,
        target_address - max_offset,
    )

    upper_bound = min(
        target_address,
        maximum_pointer_value,
    )

    results: list[Candidate] = []
    seen: set[tuple[int, int]] = set()

    mbi = MEMORY_BASIC_INFORMATION()

    current_address = MIN_USER_ADDRESS
    maximum_address = (
        0x7FFFFFFF
        if pointer_size == 4
        else MAX_USER_ADDRESS_X64
    )

    bytes_scanned = 0
    regions_scanned = 0

    # Нужен, чтобы не пропускать указатель, который начался
    # в конце одного блока, а закончился в начале следующего.
    overlap_size = pointer_size - 1

    while current_address < maximum_address:
        ctypes.set_last_error(0)

        query_result = kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(current_address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )

        if query_result == 0:
            error_code = ctypes.get_last_error()

            # В конце пользовательского адресного пространства Windows
            # обычно возвращает ERROR_INVALID_PARAMETER.
            if error_code in (0, ERROR_INVALID_PARAMETER):
                break

            # Не обрываем весь поиск из-за одного проблемного адреса.
            current_address += 0x1000
            continue

        region_base = int(
            mbi.BaseAddress
            if mbi.BaseAddress is not None
            else current_address
        )

        region_size = int(mbi.RegionSize)

        if region_size <= 0:
            current_address += 0x1000
            continue

        region_end = region_base + region_size

        if is_readable_region(mbi):
            regions_scanned += 1

            chunk_address = region_base
            previous_tail = b""

            while chunk_address < region_end:
                amount_to_read = min(
                    CHUNK_SIZE,
                    region_end - chunk_address,
                )

                data = read_process_chunk(
                    process_handle,
                    chunk_address,
                    amount_to_read,
                )

                if not data:
                    previous_tail = b""
                    chunk_address += amount_to_read
                    continue

                bytes_scanned += len(data)

                combined = previous_tail + data
                combined_base = (
                    chunk_address - len(previous_tail)
                )

                last_start = len(combined) - pointer_size

                if last_start >= 0:
                    # Начинаем с позиции, адрес которой правильно
                    # выровнен относительно всего адресного пространства,
                    # а не только относительно локального bytes-буфера.
                    first_position = (
                        -combined_base
                    ) % alignment

                    for position in range(
                        first_position,
                        last_start + 1,
                        alignment,
                    ):
                        pointer_location = (
                            combined_base + position
                        )

                        pointer_value = struct.unpack_from(
                            unpack_format,
                            combined,
                            position,
                        )[0]

                        if not (
                            lower_bound
                            <= pointer_value
                            <= upper_bound
                        ):
                            continue

                        offset = (
                            target_address - pointer_value
                        )

                        key = (
                            pointer_location,
                            offset,
                        )

                        if key in seen:
                            continue

                        seen.add(key)

                        results.append(
                            Candidate(
                                offset=offset,
                                pointer_location=pointer_location,
                                pointer_value=pointer_value,
                            )
                        )

                        if len(results) >= max_results:
                            return (
                                results,
                                bytes_scanned,
                                regions_scanned,
                            )

                previous_tail = (
                    combined[-overlap_size:]
                    if overlap_size > 0
                    else b""
                )

                chunk_address += amount_to_read

        next_address = region_end

        if next_address <= current_address:
            current_address += 0x1000
        else:
            current_address = next_address

    return (
        results,
        bytes_scanned,
        regions_scanned,
    )


def read_hex(
    prompt: str,
    default: int | None = None,
) -> int:
    value = input(prompt).strip()

    if not value:
        if default is None:
            raise ValueError("Значение не введено.")

        return default

    if value.lower().startswith("0x"):
        value = value[2:]

    return int(value, 16)


def read_int(
    prompt: str,
    default: int,
) -> int:
    value = input(prompt).strip()

    if not value:
        return default

    return int(value)


# -------------------- Main --------------------

def main() -> None:
    if sys.platform != "win32":
        print("[-] Эта программа работает только в Windows.")
        return

    # Для корректного сканирования 64-битного процесса нужен
    # 64-битный интерпретатор Python или 64-битный EXE.
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print(
            "[-] Запусти программу через 64-битный Python/EXE."
        )
        print(
            "[-] 32-битный Python не подходит для полного "
            "сканирования адресного пространства x64."
        )
        return

    print("=" * 66)
    print(" Direct Pointer Candidate Scanner — read-only")
    print("=" * 66)
    print(
        "[!] Ищет только прямых кандидатов, "
        "а не полные цепочки указателей."
    )
    print(
        "[!] Используй только для собственных программ "
        "или с разрешением.\n"
    )

    process_name = input(
        "[?] Название процесса, например TestApp.exe: "
    ).strip()

    if not process_name:
        print("[-] Название процесса не введено.")
        return

    if not process_name.lower().endswith(".exe"):
        process_name += ".exe"

    try:
        pid = get_pid_by_name(process_name)
    except OSError as error:
        print(
            f"[-] Ошибка перечисления процессов: {error}"
        )
        return

    if pid is None:
        print(
            f"[-] Процесс {process_name!r} не найден."
        )
        return

    print(f"[+] Процесс найден. PID: {pid}")

    process_handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        False,
        pid,
    )

    if not process_handle:
        error_code = ctypes.get_last_error()

        print(
            f"[-] OpenProcess: {error_code} — "
            f"{format_win_error(error_code)}"
        )
        return

    try:
        try:
            target_address = read_hex(
                "\n[?] Целевой адрес из отладчика (HEX): "
            )

            max_offset = read_hex(
                "[?] Максимальный оффсет [1000]: ",
                default=0x1000,
            )

            pointer_size = read_int(
                "[?] Размер указателя, 4 или 8 [8]: ",
                default=8,
            )

            alignment = read_int(
                "[?] Шаг проверки, 1/2/4/8 [4]: ",
                default=4,
            )

        except ValueError as error:
            print(f"[-] Некорректный ввод: {error}")
            return

        print(
            f"\n[*] Цель: 0x{target_address:X}"
        )
        print(
            f"[*] Оффсет: 0x0..0x{max_offset:X}"
        )
        print(
            f"[*] Размер указателя: {pointer_size} байт"
        )
        print(
            f"[*] Шаг проверки: {alignment}"
        )
        print("\n[*] Начинаю сканирование...")

        started_at = time.perf_counter()

        try:
            (
                candidates,
                bytes_scanned,
                regions_scanned,
            ) = scan_memory_for_direct_candidates(
                process_handle=process_handle,
                target_address=target_address,
                max_offset=max_offset,
                pointer_size=pointer_size,
                alignment=alignment,
            )

        except ValueError as error:
            print(f"[-] Ошибка параметров: {error}")
            return

        elapsed = (
            time.perf_counter() - started_at
        )

        candidates.sort(
            key=lambda item: (
                item.offset,
                item.pointer_location,
            )
        )

        print(
            f"\n[*] Проверено регионов: "
            f"{regions_scanned}"
        )

        print(
            f"[*] Прочитано: "
            f"{bytes_scanned / (1024 ** 2):.2f} МБ"
        )

        print(f"[*] Время: {elapsed:.2f} сек.")

        if not candidates:
            print(
                "\n[-] Прямые кандидаты не найдены."
            )

            print(
                "[*] Это не доказывает отсутствие "
                "многоуровневой цепочки."
            )

            print(
                "[*] Для x64 обычно используй: "
                "размер 8, шаг 4; при необходимости шаг 1."
            )
            return

        print(
            f"\n[+] Найдено кандидатов: "
            f"{len(candidates)}"
        )

        for candidate in candidates[:100]:
            print("-" * 66)

            print(
                f"Оффсет:          "
                f"0x{candidate.offset:X}"
            )

            print(
                f"Значение:        "
                f"0x{candidate.pointer_value:X}"
            )

            print(
                f"Адрес указателя: "
                f"0x{candidate.pointer_location:X}"
            )

        if len(candidates) > 100:
            print(
                f"\n[*] Показаны первые 100 из "
                f"{len(candidates)} результатов."
            )

        print(
            "\n[!] Результаты — математические кандидаты, "
            "а не подтверждённые стабильные указатели."
        )

    finally:
        kernel32.CloseHandle(process_handle)


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print(
            "\n[*] Операция остановлена пользователем."
        )

    except Exception as error:
        print(
            f"\n[-] Необработанная ошибка: {error}"
        )

    input("\nНажми Enter для выхода...")
    
