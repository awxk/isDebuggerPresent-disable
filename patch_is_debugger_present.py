"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Copyright (c) 2025, Nic D. (https://github.com/awxk)
All rights reserved.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree.
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import ctypes
import os
from ctypes import wintypes
import time

# Define the MEMORY_BASIC_INFORMATION structure
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", wintypes.DWORD),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

# VirtualQuery and VirtualProtectEx prototypes
VirtualQuery = ctypes.windll.kernel32.VirtualQuery
VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION)]
VirtualQuery.restype = ctypes.c_size_t

OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
VirtualProtectEx.restype = wintypes.BOOL

# Constants for memory protection
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_NOACCESS = 0x01

def check_memory_protection(address, process_handle):
    print(f"Checking memory protection for address {hex(address)}...")

    mbi = MEMORY_BASIC_INFORMATION()
    result = VirtualQuery(ctypes.c_void_p(address), ctypes.byref(mbi))

    if result == 0:
        print("Failed to query memory.")
        return False
    else:
        print(f"BaseAddress: {hex(mbi.BaseAddress)}")
        print(f"Protect: {hex(mbi.Protect)}")
        return mbi.Protect in [PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_NOACCESS, PAGE_READONLY]

def try_patch(address, patch_code, process_handle):
    print(f"Attempting to patch at address {hex(address)}...")

    old_protect = wintypes.DWORD()
    success = VirtualProtectEx(
        process_handle,
        ctypes.c_void_p(address),
        ctypes.c_size_t(len(patch_code)),  # Size of the patch
        PAGE_EXECUTE_READWRITE,  # Change memory protection
        ctypes.byref(old_protect)
    )

    if not success:
        print(f"Failed to change memory protection to PAGE_EXECUTE_READWRITE at address {hex(address)}.")
        return False

    print(f"Memory protection changed successfully. Writing patch code...")

    ctypes.memmove(address, patch_code, len(patch_code))

    # Restore original memory protection
    VirtualProtectEx(
        process_handle,
        ctypes.c_void_p(address),
        ctypes.c_size_t(len(patch_code)),
        old_protect.value,
        ctypes.byref(old_protect)
    )

    print("Patch applied successfully!")
    return True

def get_is_debugger_present_address():
    kernel32_handle = ctypes.windll.kernel32.GetModuleHandleW("kernel32.dll")
    if not kernel32_handle:
        raise ctypes.WinError(ctypes.get_last_error(), "Failed to get handle to kernel32.dll")

    print(f"kernel32.dll handle: {hex(kernel32_handle)}")

    is_debugger_present_address = ctypes.windll.kernel32.GetProcAddress(kernel32_handle, b'IsDebuggerPresent')
    if not is_debugger_present_address:
        raise ctypes.WinError(ctypes.get_last_error(), "Failed to find IsDebuggerPresent address")

    print(f"IsDebuggerPresent address: {hex(is_debugger_present_address)}")
    return is_debugger_present_address

def patch_is_debugger_present():
    try:
        print("Starting patch process...")

        # Get the address of IsDebuggerPresent dynamically
        is_debugger_present_address = get_is_debugger_present_address()

        # Open the process handle to apply changes
        process_handle = OpenProcess(0x1F0FFF, False, os.getpid())
        if not process_handle:
            raise ctypes.WinError(ctypes.get_last_error(), "Failed to open process handle")

        print(f"Opened process handle: {hex(process_handle)}")

        # Check memory protection before attempting to patch
        if not check_memory_protection(is_debugger_present_address, process_handle):
            print(f"Memory protection for IsDebuggerPresent is not suitable for patching. Trying different methods...")

            # Try applying different protections and patching again
            protections = [PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_NOACCESS, PAGE_READONLY]
            patch_code = b'\x33\xC0\xC3'  # xor eax, eax; ret (the patch)

            for protection in protections:
                print(f"Trying protection: {hex(protection)}")
                success = try_patch(is_debugger_present_address, patch_code, process_handle)
                if success:
                    print("Patched successfully with different protection.")
                    return
                time.sleep(1)

            print(f"Failed to apply patch with any memory protection.")
            return

        # Default patching attempt
        patch_code = b'\x33\xC0\xC3'  # xor eax, eax; ret
        if try_patch(is_debugger_present_address, patch_code, process_handle):
            print("Patched IsDebuggerPresent to always return False.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    patch_is_debugger_present()
  
