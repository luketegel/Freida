# 🛡️ System Call Analysis Report: `sample_binary`

> **Automated Headless Binary & Applet Decompilation via Ghidra MCP**  
> **Analysis Date:** 2026-10-12 10:00:00 UTC  
> **Analysis Mode:** Ghidra Headless (No GUI) | Model Context Protocol

## 📦 Target Binary Information

| Attribute | Value |
| :--- | :--- |
| **File Name** | `sample_binary` |
| **Absolute Path** | `/Users/luketegel/FreidaPrototype/ghidra_syscall_analyzer/samples/sample_binary` |
| **File Format** | `ELF 64-bit / Linux Executable` |
| **Architecture** | `x86:LE:64:default` |
| **File Size** | 64.00 KB (65,536 bytes) |
| **SHA-256** | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| **MD-5** | `d41d8cd98f00b204e9800998ecf8427e` |
| **Ghidra Program Name** | `sample_binary` |

## 📊 Analysis Dashboard

| Metric | Count | Details |
| :--- | :---: | :--- |
| **Total Functions Decompiled** | **4** | Analyzed via Ghidra Decompiler |
| **Total Syscall Invocations** | **14** | Detected across all functions & imports |
| **Unique System Calls** | **13** | Distinct system call primitives |
| **Critical Severity Calls** | **0** | High-impact actions (Injection, Exec, Arbitrary Memory) |
| **High Severity Calls** | **4** | Process spawns, Memory protection changes, Elevated privileges |
| **Medium Severity Calls** | **5** | Network sockets, File creation/deletion, IPC |
| **Low / Info Severity Calls** | **5** | File reads, Clocks, System telemetry |

## 📂 System Call Categories

| Category | Count | Distribution |
| :--- | :---: | :--- |
| **Process & Execution** | `5` | `████████████████████` 5 call(s) |
| **File I/O** | `3` | `████████████░░░░░░░░` 3 call(s) |
| **Networking & Sockets** | `3` | `████████████░░░░░░░░` 3 call(s) |
| **Memory Management** | `2` | `████████░░░░░░░░░░░░` 2 call(s) |
| **Direct Syscall** | `1` | `████░░░░░░░░░░░░░░░░` 1 call(s) |

## 🔍 Security & Behavioral Observations

- ⚠️ **Process Execution Capabilities:** Detected routines capable of spawning or altering processes: `execve, exit, fork, wait4`.
- ⚠️ **Dynamic Memory & Page Protection:** Target manages memory allocations and page permissions: `mmap, mprotect`.
- 🌐 **Network Communication:** Target initializes network sockets or connections: `connect, sendto, socket`.
- 📁 **Filesystem Operations:** Target accesses, modifies, or inspects files: `close, open, read`.

## 📋 System Calls Inventory

| Syscall / API | Category | Severity | Function / Address | Line | Type | Arguments / Context |
| :--- | :--- | :---: | :--- | :---: | :--- | :--- |
| **`open`** | File I/O | 🟡 MEDIUM | `main`<br>`0x401000` | 2 | Libc Wrapper | `"/etc/target_config", 0` |
| **`exit`** | Process & Execution | ⚪ INFO | `main`<br>`0x401000` | 4 | Libc Wrapper | `1` |
| **`read`** | File I/O | 🟢 LOW | `main`<br>`0x401000` | 7 | Libc Wrapper | `fd, buf, 256` |
| **`close`** | File I/O | ⚪ INFO | `main`<br>`0x401000` | 8 | Libc Wrapper | `fd` |
| **`socket`** | Networking & Sockets | 🟡 MEDIUM | `main`<br>`0x401000` | 9 | Libc Wrapper | `2, 1, 0` |
| **`connect`** | Networking & Sockets | 🟠 HIGH | `main`<br>`0x401000` | 10 | Libc Wrapper | `sock, (struct sockaddr *)&srv, sizeof(sr...` |
| **`sendto`** | Networking & Sockets | 🟡 MEDIUM | `main`<br>`0x401000` | 11 | Libc Wrapper | `sock, buf, 256, 0, (struct sockaddr *)&s...` |
| **`fork`** | Process & Execution | 🟡 MEDIUM | `spawn_worker`<br>`0x401000` | 2 | Libc Wrapper | — |
| **`execve`** | Process & Execution | 🟠 HIGH | `spawn_worker`<br>`0x401000` | 5 | Libc Wrapper | `"/bin/sh", args, NULL` |
| **`wait4`** | Process & Execution | ⚪ INFO | `spawn_worker`<br>`0x401000` | 7 | Libc Wrapper | `pid, NULL, 0, NULL` |
| **`mmap`** | Memory Management | 🟡 MEDIUM | `allocate_protected`<br>`0x401000` | 2 | Libc Wrapper | `NULL, len, 3, 0x22, -1, 0` |
| **`mprotect`** | Memory Management | 🟠 HIGH | `allocate_protected`<br>`0x401000` | 3 | Libc Wrapper | `ptr, len, 7` |
| **`exit`** | Process & Execution | ⚪ INFO | `allocate_protected`<br>`0x401000` | 4 | Direct Syscall | `sys_nr=0x3c, 0` |
| **`direct_syscall`** | Direct Syscall | 🟠 HIGH | `raw_assembly_stub`<br>`0x401000` | 2 | Direct Syscall | — |

## 🔬 Decompiled Evidence & Callsite Context

### Function: `main`

**Detected System Calls:** `open`, `exit`, `read`, `close`, `socket`, `connect`, `sendto`


- **Line 2** (`open` - File I/O):
  ```c
  int fd = open("/etc/target_config", 0);
  ```
- **Line 4** (`exit` - Process & Execution):
  ```c
  exit(1);
  ```
- **Line 7** (`read` - File I/O):
  ```c
  read(fd, buf, 256);
  ```
- **Line 8** (`close` - File I/O):
  ```c
  close(fd);
  ```
- **Line 9** (`socket` - Networking & Sockets):
  ```c
  int sock = socket(2, 1, 0);
  ```
- **Line 10** (`connect` - Networking & Sockets):
  ```c
  connect(sock, (struct sockaddr *)&srv, sizeof(srv));
  ```
- **Line 11** (`sendto` - Networking & Sockets):
  ```c
  sendto(sock, buf, 256, 0, (struct sockaddr *)&srv, sizeof(srv));
  ```

<details>
<summary><b>View Full Decompiled Function:</b> <code>main</code></summary>

```c
int main(int argc, char **argv) {
    int fd = open("/etc/target_config", 0);
    if (fd < 0) {
        exit(1);
    }
    char buf[256];
    read(fd, buf, 256);
    close(fd);
    int sock = socket(2, 1, 0);
    connect(sock, (struct sockaddr *)&srv, sizeof(srv));
    sendto(sock, buf, 256, 0, (struct sockaddr *)&srv, sizeof(srv));
    return 0;
}
```
</details>


### Function: `spawn_worker`

**Detected System Calls:** `fork`, `execve`, `wait4`


- **Line 2** (`fork` - Process & Execution):
  ```c
  pid_t pid = fork();
  ```
- **Line 5** (`execve` - Process & Execution):
  ```c
  execve("/bin/sh", args, NULL);
  ```
- **Line 7** (`wait4` - Process & Execution):
  ```c
  wait4(pid, NULL, 0, NULL);
  ```

<details>
<summary><b>View Full Decompiled Function:</b> <code>spawn_worker</code></summary>

```c
void spawn_worker(char *path) {
    pid_t pid = fork();
    if (pid == 0) {
        char *args[] = {"/bin/sh", "-c", path, NULL};
        execve("/bin/sh", args, NULL);
    } else {
        wait4(pid, NULL, 0, NULL);
    }
}
```
</details>


### Function: `allocate_protected`

**Detected System Calls:** `mmap`, `mprotect`, `exit`


- **Line 2** (`mmap` - Memory Management):
  ```c
  void *ptr = mmap(NULL, len, 3, 0x22, -1, 0);
  ```
- **Line 3** (`mprotect` - Memory Management):
  ```c
  mprotect(ptr, len, 7); // RWX permissions
  ```
- **Line 4** (`exit` - Process & Execution):
  ```c
  syscall(0x3c, 0); // direct exit syscall (0x3c = 60 = exit)
  ```

<details>
<summary><b>View Full Decompiled Function:</b> <code>allocate_protected</code></summary>

```c
void *allocate_protected(size_t len) {
    void *ptr = mmap(NULL, len, 3, 0x22, -1, 0);
    mprotect(ptr, len, 7); // RWX permissions
    syscall(0x3c, 0); // direct exit syscall (0x3c = 60 = exit)
    return ptr;
}
```
</details>


### Function: `raw_assembly_stub`

**Detected System Calls:** `direct_syscall`


- **Line 2** (`direct_syscall` - Direct Syscall):
  ```c
  __asm__ volatile ("syscall");
  ```

<details>
<summary><b>View Full Decompiled Function:</b> <code>raw_assembly_stub</code></summary>

```c
void raw_assembly_stub() {
    __asm__ volatile ("syscall");
}
```
</details>


## ⚙️ Methodology & Tooling

This report was generated using **Ghidra Syscall Analyzer** operating in full **Headless Mode** via the **Model Context Protocol (MCP)**:
- **Decompilation Engine:** Ghidra Decompiler (`DecompInterface`) via PyGhidra / GhidraMCP.
- **Protocol:** Model Context Protocol (MCP) JSON-RPC 2.0 stdio / HTTP bridge.
- **Headless Execution:** Fully automated headless analysis without requiring the Ghidra graphical user interface (GUI).
- **Detection Scope:** Covers direct assembly syscall instructions (`syscall`, `sysenter`, `int 0x80`, `svc #0`), POSIX / libc system call wrappers, Windows Native NT and Win32 system APIs, macOS Mach traps, and Java JVM / Applet system invocations.