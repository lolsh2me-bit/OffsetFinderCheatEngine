import ctypes
import struct
from ctypes import wintypes

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
READABLE_PROTECTIONS = {
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
}
CHUNK_SIZE = 4 * 1024 * 1024

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


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
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
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


def get_pid_by_name(process_name: str) -> int | None:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return None

    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return None

        requested_name = process_name.casefold()
        while True:
            if entry.szExeFile.casefold() == requested_name:
                return int(entry.th32ProcessID)
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
        return None
    finally:
        kernel32.CloseHandle(snapshot)


def is_readable_region(mbi: MEMORY_BASIC_INFORMATION) -> bool:
    if mbi.State != MEM_COMMIT:
        return False
    if mbi.Protect & PAGE_GUARD:
        return False
    if mbi.Protect & PAGE_NOACCESS:
        return False
    return (mbi.Protect & 0xFF) in READABLE_PROTECTIONS


def scan_memory_for_candidates(process_handle, target_address: int, max_offset: int):
    results = []
    mbi = MEMORY_BASIC_INFORMATION()
    current_address = 0x10000
    maximum_address = 0x7FFFFFFFFFFF

    while current_address < maximum_address:
        query_result = kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(current_address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if query_result == 0:
            break

        region_base = int(mbi.BaseAddress or current_address)
        region_size = int(mbi.RegionSize)
        if region_size <= 0:
            break

        if is_readable_region(mbi):
            region_end = region_base + region_size
            chunk_address = region_base

            while chunk_address < region_end:
                amount_to_read = min(CHUNK_SIZE, region_end - chunk_address)
                buffer = ctypes.create_string_buffer(amount_to_read)
                bytes_read = ctypes.c_size_t()

                success = kernel32.ReadProcessMemory(
                    process_handle,
                    ctypes.c_void_p(chunk_address),
                    buffer,
                    amount_to_read,
                    ctypes.byref(bytes_read),
                )

                if success and bytes_read.value >= 8:
                    data = buffer.raw[:bytes_read.value]
                    for position in range(0, len(data) - 7, 8):
                        pointer_value = struct.unpack_from("<Q", data, position)[0]
                        offset = target_address - pointer_value
                        if 0x8 <= offset <= max_offset and offset % 8 == 0:
                            results.append((offset, chunk_address + position, pointer_value))

                chunk_address += amount_to_read

        next_address = region_base + region_size
        if next_address <= current_address:
            break
        current_address = next_address

    return results


def read_hex(prompt: str, default: int | None = None) -> int:
    value = input(prompt).strip()
    if not value and default is not None:
        return default
    if value.lower().startswith("0x"):
        value = value[2:]
    return int(value, 16)


def main() -> None:
    print("=" * 55)
    print(" Fox Offset Auto-Finder")
    print("=" * 55)

    process_name = input("[?] Название процесса, например Game.exe: ").strip()
    if not process_name:
        print("[-] Название процесса не введено.")
        return
    if not process_name.lower().endswith(".exe"):
        process_name += ".exe"

    pid = get_pid_by_name(process_name)
    if pid is None:
        print(f"[-] Процесс {process_name!r} не найден.")
        return
    print(f"[+] Процесс найден. PID: {pid}")

    process_handle = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        False,
        pid,
    )
    if not process_handle:
        print(f"[-] OpenProcess завершился ошибкой: {ctypes.get_last_error()}")
        return

    try:
        try:
            target_address = read_hex("\n[?] Адрес из Cheat Engine: ")
            max_offset = read_hex("[?] Максимальный оффсет [500]: ", default=0x500)
        except ValueError:
            print("[-] Введено неверное HEX-число.")
            return

        if target_address <= 0 or max_offset < 8:
            print("[-] Адрес или максимальный оффсет некорректны.")
            return

        print(f"\n[*] Поиск кандидатов до 0x{max_offset:X}...")
        candidates = scan_memory_for_candidates(process_handle, target_address, max_offset)

        if not candidates:
            print("\n[-] Подходящие указатели не найдены.")
            return

        candidates.sort(key=lambda item: (item[0], item[1]))
        print(f"\n[+] Найдено кандидатов: {len(candidates)}")

        for offset, pointer_location, base_address in candidates[:100]:
            print("-" * 55)
            print(f"Оффсет:              0x{offset:X}")
            print(f"Предполагаемая база: 0x{base_address:X}")
            print(f"Адрес указателя:     0x{pointer_location:X}")

        if len(candidates) > 100:
            print(f"\n[*] Показаны первые 100 из {len(candidates)} результатов.")

        print("\n[!] Совпадение — кандидат, а не подтвержденная pointer chain.")
    finally:
        kernel32.CloseHandle(process_handle)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Операция остановлена пользователем.")
    except Exception as error:
        print(f"\n[-] Необработанная ошибка: {error}")
    input("\nНажми Enter для выхода...")
