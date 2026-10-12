# 🛡️ System Call Analysis Report: `sample_binary`

> **Automated Headless Binary Decompilation via Ghidra**  
> **Analysis Date:** 2026-10-12 22:23:25 UTC  
> **Analysis Mode:** Ghidra Headless (No GUI) | PyGhidra in-process

## 📦 Target Binary Information

| Attribute | Value |
| :--- | :--- |
| **File Name** | `sample_binary` |
| **Absolute Path** | `freida/samples/sample_binary` |
| **File Format** | `macOS Mach-O Binary` |
| **Architecture** | `AARCH64:LE:64:AppleSilicon` |
| **File Size** | 33.52 KB (34,320 bytes) |
| **SHA-256** | `c0ff6f7518d5219d72f69c6e92f8e0ed240b44ac4dd0aa45f6efe6e1797b2e45` |
| **MD-5** | `e0cbdec65ec18790e069f12205c82e93` |
| **Ghidra Program Name** | `sample_binary` |

## 📊 Analysis Dashboard

| Metric | Count | Details |
| :--- | :---: | :--- |
| **Total Functions Decompiled** | **6** | Analyzed via Ghidra Decompiler |
| **Total Syscall Invocations** | **13** | Detected across all functions & imports |
| **Unique System Calls** | **12** | Distinct system call primitives |
| **Critical Severity Calls** | **0** | High-impact actions (Injection, Exec, Arbitrary Memory) |
| **High Severity Calls** | **4** | Process spawns, Memory protection changes, Elevated privileges |
| **Medium Severity Calls** | **4** | Network sockets, File creation/deletion, IPC |
| **Low / Info Severity Calls** | **5** | File reads, Clocks, System telemetry |

## 📂 System Call Categories

| Category | Count | Distribution |
| :--- | :---: | :--- |
| **File I/O** | `4` | `████████████████████` 4 call(s) |
| **Process & Execution** | `3` | `███████████████░░░░░` 3 call(s) |
| **Memory Management** | `3` | `███████████████░░░░░` 3 call(s) |
| **Networking & Sockets** | `2` | `██████████░░░░░░░░░░` 2 call(s) |
| **Direct Syscall** | `1` | `█████░░░░░░░░░░░░░░░` 1 call(s) |

## 🔍 Security & Behavioral Observations

- ⚠️ **Direct Kernel Entry:** Raw syscall instructions that bypass libc wrappers in: `_perform_direct_syscall`.
- ⚠️ **Process Execution Capabilities:** Detected routines capable of spawning or altering processes: `execve, exit, fork`.
- ⚠️ **Dynamic Memory & Page Protection:** Target manages memory allocations and page permissions: `mmap, mprotect, munmap`.
- 🌐 **Network Communication:** Target initializes network sockets or connections: `connect, socket`.
- 📁 **Filesystem Operations:** Target accesses, modifies, or inspects files: `close, open, write`.

## 📋 System Calls Inventory

| Syscall / API | Category | Severity | Function / Address | Line | Type | Arguments / Context |
| :--- | :--- | :---: | :--- | :---: | :--- | :--- |
| **`direct_syscall`** | Direct Syscall | 🟠 HIGH | `_perform_direct_syscall`<br>`1000004b0` | 5 | Direct Syscall | — |
| **`open`** | File I/O | 🟡 MEDIUM | `_file_io_operations`<br>call @ `100000540` | 7 | Libc Wrapper | `"/tmp/output.dat",0x201` |
| **`write`** | File I/O | 🟢 LOW | `_file_io_operations`<br>call @ `100000564` | 9 | Libc Wrapper | `iVar1,"Data payload",0xc` |
| **`close`** | File I/O | ⚪ INFO | `_file_io_operations`<br>call @ `10000056c` | 10 | Libc Wrapper | `iVar1` |
| **`socket`** | Networking & Sockets | 🟡 MEDIUM | `_network_operations`<br>call @ `1000005a8` | 10 | Libc Wrapper | `2,1,0` |
| **`connect`** | Networking & Sockets | 🟠 HIGH | `_network_operations`<br>call @ `1000005d0` | 18 | Libc Wrapper | `iVar1,&sStack_28,0x10` |
| **`close`** | File I/O | ⚪ INFO | `_network_operations`<br>call @ `1000005d8` | 19 | Libc Wrapper | `iVar1` |
| **`fork`** | Process & Execution | 🟡 MEDIUM | `_process_execution`<br>call @ `100000624` | 12 | Libc Wrapper | — |
| **`execve`** | Process & Execution | 🟠 HIGH | `_process_execution`<br>call @ `100000660` | 17 | Libc Wrapper | `"/bin/ls",&local_30,(char **)0x0` |
| **`exit`** | Process & Execution | ⚪ INFO | `_process_execution`<br>call @ `100000668` | 19 | Libc Wrapper | `0` |
| **`mmap`** | Memory Management | 🟡 MEDIUM | `_memory_manipulation`<br>call @ `1000006c0` | 7 | Libc Wrapper | `0,0x1000,3,0x1002,0xffffffff,0` |
| **`mprotect`** | Memory Management | 🟠 HIGH | `_memory_manipulation`<br>call @ `1000006d4` | 8 | Libc Wrapper | `uVar1,0x1000,7` |
| **`munmap`** | Memory Management | 🟢 LOW | `_memory_manipulation`<br>call @ `1000006e0` | 9 | Libc Wrapper | `uVar1,0x1000` |

## 🔬 Decompiled Evidence & Callsite Context

### Function: `_perform_direct_syscall`

**Detected System Calls:** `direct_syscall`


- **Line 5** (`direct_syscall` - Direct Syscall):
  ```c
  CallSupervisor(0);
  ```

<details>
<summary><b>View Full Decompiled Function:</b> <code>_perform_direct_syscall</code></summary>

```c

void _perform_direct_syscall(void)

{
  CallSupervisor(0);
  if (*(long *)PTR____stack_chk_guard_100004000 - *(long *)PTR____stack_chk_guard_100004000 != 0) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail(*(long *)PTR____stack_chk_guard_100004000 -
                      *(long *)PTR____stack_chk_guard_100004000);
  }
  return;
}

```
</details>


### Function: `_file_io_operations`

**Detected System Calls:** `open`, `write`, `close`


- **Line 7** (`open` - File I/O):
  ```c
  iVar1 = _open("/tmp/output.dat",0x201);
  ```
- **Line 9** (`write` - File I/O):
  ```c
  _write(iVar1,"Data payload",0xc);
  ```
- **Line 10** (`close` - File I/O):
  ```c
  iVar1 = _close(iVar1);
  ```

<details>
<summary><b>View Full Decompiled Function:</b> <code>_file_io_operations</code></summary>

```c

int _file_io_operations(void)

{
  int iVar1;
  
  iVar1 = _open("/tmp/output.dat",0x201);
  if (-1 < iVar1) {
    _write(iVar1,"Data payload",0xc);
    iVar1 = _close(iVar1);
  }
  return iVar1;
}

```
</details>


### Function: `_network_operations`

**Detected System Calls:** `socket`, `connect`, `close`


- **Line 10** (`socket` - Networking & Sockets):
  ```c
  iVar1 = _socket(2,1,0);
  ```
- **Line 18** (`connect` - Networking & Sockets):
  ```c
  _connect(iVar1,&sStack_28,0x10);
  ```
- **Line 19** (`close` - File I/O):
  ```c
  iVar1 = _close(iVar1);
  ```

<details>
<summary><b>View Full Decompiled Function:</b> <code>_network_operations</code></summary>

```c

void _network_operations(void)

{
  int iVar1;
  sockaddr sStack_28;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  iVar1 = _socket(2,1,0);
  sStack_28.sa_family = '\x02';
  sStack_28.sa_data[0] = '\x1f';
  sStack_28.sa_data[1] = -0x70;
  sStack_28.sa_data[2] = '\0';
  sStack_28.sa_data[3] = '\0';
  sStack_28.sa_data[4] = '\0';
  sStack_28.sa_data[5] = '\0';
  _connect(iVar1,&sStack_28,0x10);
  iVar1 = _close(iVar1);
  if (*(long *)PTR____stack_chk_guard_100004000 - local_18 != 0) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail(*(long *)PTR____stack_chk_guard_100004000 - local_18,iVar1);
  }
  return;
}

```
</details>


### Function: `_process_execution`

**Detected System Calls:** `fork`, `execve`, `exit`


- **Line 12** (`fork` - Process & Execution):
  ```c
  pVar1 = _fork();
  ```
- **Line 17** (`execve` - Process & Execution):
  ```c
  _execve("/bin/ls",&local_30,(char **)0x0);
  ```
- **Line 19** (`exit` - Process & Execution):
  ```c
  _exit(0);
  ```

<details>
<summary><b>View Full Decompiled Function:</b> <code>_process_execution</code></summary>

```c

void _process_execution(void)

{
  pid_t pVar1;
  char *local_30;
  undefined *puStack_28;
  undefined8 local_20;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  pVar1 = _fork();
  if (pVar1 == 0) {
    puStack_28 = PTR_s__la_100004070;
    local_30 = PTR_s__bin_ls_100004068;
    local_20 = DAT_100004078;
    _execve("/bin/ls",&local_30,(char **)0x0);
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  if (*(long *)PTR____stack_chk_guard_100004000 - local_18 != 0) {
                    /* WARNING: Subroutine does not return */
    ___stack_chk_fail(*(long *)PTR____stack_chk_guard_100004000 - local_18);
  }
  return;
}

```
</details>


### Function: `_memory_manipulation`

**Detected System Calls:** `mmap`, `mprotect`, `munmap`


- **Line 7** (`mmap` - Memory Management):
  ```c
  uVar1 = _mmap(0,0x1000,3,0x1002,0xffffffff,0);
  ```
- **Line 8** (`mprotect` - Memory Management):
  ```c
  _mprotect(uVar1,0x1000,7);
  ```
- **Line 9** (`munmap` - Memory Management):
  ```c
  _munmap(uVar1,0x1000);
  ```

<details>
<summary><b>View Full Decompiled Function:</b> <code>_memory_manipulation</code></summary>

```c

void _memory_manipulation(void)

{
  undefined8 uVar1;
  
  uVar1 = _mmap(0,0x1000,3,0x1002,0xffffffff,0);
  _mprotect(uVar1,0x1000,7);
  _munmap(uVar1,0x1000);
  return;
}

```
</details>


## ⚙️ Methodology & Tooling

This report was generated using **Freida** operating in full **Headless Mode**:
- **Decompilation Engine:** Ghidra Decompiler (`DecompInterface`) driven in-process via PyGhidra.
- **Headless Execution:** Fully automated headless analysis without requiring the Ghidra graphical user interface (GUI).
- **Detection Scope:** Covers direct assembly syscall instructions (`syscall`, `sysenter`, `int 0x80`, `svc #0`), POSIX / libc system call wrappers, Windows Native NT and Win32 system APIs, and macOS Mach traps in native executables (ELF, PE, Mach-O).