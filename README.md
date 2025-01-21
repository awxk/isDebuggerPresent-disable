# IsDebuggerPresent Patcher

A Python script to dynamically patch the `IsDebuggerPresent` function in `kernel32.dll`, ensuring that it always returns `False`. This can be useful for testing or debugging purposes when bypassing debugger detection in certain applications.

## Features
- Dynamically locates the `IsDebuggerPresent` function address.
- Changes memory protection to enable patching.
- Applies a patch (`xor eax, eax; ret`) to make `IsDebuggerPresent` always return `False`.
- Restores original memory protection after patching.

## Requirements
- Windows operating system.
- Python 3.8 or later.
- Administrative privileges (required for memory patching).

## How to Use

### 1. Clone or Download the Repository
```bash
git clone https://github.com/awxk/isDebuggerPresent-disable.git
cd isDebuggerPresent-disable
```

### 2. Run the Script
Make sure to run the script in an environment with administrative privileges:
```bash
python patch_is_debugger_present.py
```

### 3. What to Expect
The script will:
1. Locate `IsDebuggerPresent` in `kernel32.dll`.
2. Open the process with the necessary permissions.
3. Attempt to change memory protection and apply the patch.
4. Output debugging information, including memory addresses and patching progress.

Example output:
```
Starting patch process...
kernel32.dll handle: 0x75fa0000
IsDebuggerPresent address: 0x75fa1000
Opened process handle: 0x12345678
Checking memory protection for address 0x75fa1000...
BaseAddress: 0x75fa0000
Protect: 0x4
Memory protection is suitable. Attempting patch...
Memory protection changed successfully. Writing patch code...
Patch applied successfully!
```

## Troubleshooting
- **Access Denied Errors**: Ensure the script is run with administrative privileges.
- **Unsupported Environment**: This script is specifically designed for Windows systems.
- **Failure to Patch**: The script attempts multiple memory protection methods. If all fail, ensure no other application is interfering with memory management.

## Code Overview

### Main Functions
- **`get_is_debugger_present_address()`**: Locates the address of `IsDebuggerPresent` in `kernel32.dll`.
- **`check_memory_protection()`**: Checks the memory protection status of the target address.
- **`try_patch()`**: Attempts to apply the patch by modifying memory protection and writing the patch code.
- **`patch_is_debugger_present()`**: Orchestrates the patching process and handles exceptions.

## Disclaimer
This script is intended for educational purposes and lawful testing only. Misuse of this script in violation of any applicable laws or terms of service is strictly prohibited. Use at your own risk.

## License
This source code is licensed under the BSD-style license found in the [LICENSE](https://github.com/awxk/isDebuggerPresent-disable/blob/main/LICENSE) file in the root directory of this source tree.

## Author
[Nic D.](https://github.com/awxk)
