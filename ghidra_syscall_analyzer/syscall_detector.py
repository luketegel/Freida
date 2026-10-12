"""Syscall Detection Engine.

Analyzes decompiled C pseudocode, imports, disassembly, and Java applet
decompilations to identify direct system calls, libc wrappers, Windows NT
APIs, and Java JVM system invocations.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class SyscallFinding:
    """Represents a detected system call finding."""
    name: str
    category: str
    description: str
    severity: str  # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    detection_type: str  # "DIRECT_SYSCALL", "LIBC_WRAPPER", "WINDOWS_NATIVE", "WIN32_API", "MACOS_MACH", "JAVA_SYSTEM"
    function_name: str
    address: Optional[str]
    line_number: int
    code_snippet: str
    arguments: str
    syscall_number: Optional[int] = None
    target_arch: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Linux x86_64 syscall number mapping for direct syscall(number, ...) resolution
LINUX_X86_64_SYSCALLS: Dict[int, str] = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    30: "shmat",
    31: "shmctl",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    64: "semget",
    65: "semop",
    66: "semctl",
    67: "shmdt",
    68: "msgget",
    69: "msgsnd",
    70: "msgrcv",
    71: "msgctl",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    95: "umask",
    96: "gettimeofday",
    97: "getrlimit",
    98: "getrusage",
    99: "sysinfo",
    100: "times",
    101: "ptrace",
    102: "getuid",
    103: "syslog",
    104: "getgid",
    105: "setuid",
    106: "setgid",
    107: "geteuid",
    108: "getegid",
    109: "setpgid",
    110: "getppid",
    111: "getpgrp",
    112: "setsid",
    113: "setreuid",
    114: "setregid",
    115: "getgroups",
    116: "setgroups",
    117: "setresuid",
    118: "getresuid",
    119: "setresgid",
    120: "getresgid",
    121: "getpgid",
    122: "setfsuid",
    123: "setfsgid",
    124: "getsid",
    125: "capget",
    126: "capset",
    127: "rt_sigpending",
    128: "rt_sigtimedwait",
    129: "rt_sigqueueinfo",
    130: "rt_sigsuspend",
    131: "sigaltstack",
    132: "utime",
    133: "mknod",
    134: "uselib",
    135: "personality",
    136: "ustat",
    137: "statfs",
    138: "fstatfs",
    139: "sysfs",
    140: "getpriority",
    141: "setpriority",
    142: "sched_setparam",
    143: "sched_getparam",
    144: "sched_setscheduler",
    145: "sched_getscheduler",
    146: "sched_get_priority_max",
    147: "sched_get_priority_min",
    148: "sched_rr_get_interval",
    149: "mlock",
    150: "munlock",
    151: "mlockall",
    152: "munlockall",
    153: "vhangup",
    154: "modify_ldt",
    155: "pivot_root",
    156: "_sysctl",
    157: "prctl",
    158: "arch_prctl",
    159: "adjtimex",
    160: "setrlimit",
    161: "chroot",
    162: "sync",
    163: "acct",
    164: "settimeofday",
    165: "mount",
    166: "umount2",
    167: "swapon",
    168: "swapoff",
    169: "reboot",
    170: "sethostname",
    171: "setdomainname",
    172: "iopl",
    173: "ioperm",
    174: "create_module",
    175: "init_module",
    176: "delete_module",
    177: "get_kernel_syms",
    178: "query_module",
    179: "quotactl",
    180: "nfsservctl",
    181: "getpmsg",
    182: "putpmsg",
    183: "afs_syscall",
    184: "tuxcall",
    185: "security",
    186: "gettid",
    187: "readahead",
    188: "setxattr",
    189: "lsetxattr",
    190: "fsetxattr",
    191: "getxattr",
    192: "lgetxattr",
    193: "fgetxattr",
    194: "listxattr",
    195: "llistxattr",
    196: "flistxattr",
    197: "removexattr",
    198: "lremovexattr",
    199: "fremovexattr",
    200: "tkill",
    201: "time",
    202: "futex",
    203: "sched_setaffinity",
    204: "sched_getaffinity",
    205: "set_thread_area",
    206: "io_setup",
    207: "io_destroy",
    208: "io_getevents",
    209: "io_submit",
    210: "io_cancel",
    211: "get_thread_area",
    212: "lookup_dcookie",
    213: "epoll_create",
    214: "epoll_ctl_old",
    215: "epoll_wait_old",
    216: "remap_file_pages",
    217: "getdents64",
    218: "set_tid_address",
    219: "restart_syscall",
    220: "semtimedop",
    221: "fadvise64",
    222: "timer_create",
    223: "timer_settime",
    224: "timer_gettime",
    225: "timer_getoverrun",
    226: "timer_delete",
    227: "clock_settime",
    228: "clock_gettime",
    229: "clock_getres",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    234: "tgkill",
    235: "utimes",
    236: "vserver",
    237: "mbind",
    238: "set_mempolicy",
    239: "get_mempolicy",
    240: "mq_open",
    241: "mq_unlink",
    242: "mq_timedsend",
    243: "mq_timedreceive",
    244: "mq_notify",
    245: "mq_getsetattr",
    246: "kexec_load",
    247: "waitid",
    248: "add_key",
    249: "request_key",
    250: "keyctl",
    251: "ioprio_set",
    252: "ioprio_get",
    253: "inotify_init",
    254: "inotify_add_watch",
    255: "inotify_rm_watch",
    256: "migrate_pages",
    257: "openat",
    258: "mkdirat",
    259: "mknodat",
    260: "fchownat",
    261: "futimesat",
    262: "newfstatat",
    263: "unlinkat",
    264: "renameat",
    265: "linkat",
    266: "symlinkat",
    267: "readlinkat",
    268: "fchmodat",
    269: "faccessat",
    270: "pselect6",
    271: "ppoll",
    272: "unshare",
    273: "set_robust_list",
    274: "get_robust_list",
    275: "splice",
    276: "tee",
    277: "sync_file_range",
    278: "vmsplice",
    279: "move_pages",
    280: "utimensat",
    281: "epoll_pwait",
    282: "signalfd",
    283: "timerfd_create",
    284: "eventfd",
    285: "fallocate",
    286: "timerfd_settime",
    287: "timerfd_gettime",
    288: "accept4",
    289: "signalfd4",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    294: "inotify_init1",
    295: "preadv",
    296: "pwritev",
    297: "rt_tgsigqueueinfo",
    298: "perf_event_open",
    299: "recvmmsg",
    300: "fanotify_init",
    301: "fanotify_mark",
    302: "prlimit64",
    303: "name_to_handle_at",
    304: "open_by_handle_at",
    305: "clock_adjtime",
    306: "syncfs",
    307: "sendmmsg",
    308: "setns",
    309: "getcpu",
    310: "process_vm_readv",
    311: "process_vm_writev",
    312: "kcmp",
    313: "finit_module",
    314: "sched_setattr",
    315: "sched_getattr",
    316: "renameat2",
    317: "seccomp",
    318: "getrandom",
    319: "memfd_create",
    320: "kexec_file_load",
    321: "bpf",
    322: "execveat",
    323: "userfaultfd",
    324: "membarrier",
    325: "mlock2",
    326: "copy_file_range",
    327: "preadv2",
    328: "pwritev2",
    329: "pkey_mprotect",
    330: "pkey_alloc",
    331: "pkey_free",
    332: "statx",
    439: "faccessat2",
    440: "process_madvise",
    441: "epoll_pwait2",
    442: "mount_setattr",
    443: "quotactl_fd",
    444: "landlock_create_ruleset",
    445: "landlock_add_rule",
    446: "landlock_restrict_self",
    448: "process_mrelease",
}

# Syscall metadata dictionary: name -> (category, description, severity)
SYSCALL_CATALOG: Dict[str, Tuple[str, str, str]] = {
    # File I/O
    "read": ("File I/O", "Read from file descriptor", "LOW"),
    "write": ("File I/O", "Write to file descriptor", "LOW"),
    "open": ("File I/O", "Open file", "MEDIUM"),
    "openat": ("File I/O", "Open file relative to directory fd", "MEDIUM"),
    "close": ("File I/O", "Close file descriptor", "INFO"),
    "stat": ("File I/O", "Get file status", "INFO"),
    "fstat": ("File I/O", "Get file status from fd", "INFO"),
    "lstat": ("File I/O", "Get symbolic link status", "INFO"),
    "lseek": ("File I/O", "Reposition file offset", "INFO"),
    "ioctl": ("File I/O", "Device control / I/O control", "MEDIUM"),
    "access": ("File I/O", "Check user file permissions", "INFO"),
    "faccessat": ("File I/O", "Check file access permissions relative to fd", "INFO"),
    "creat": ("File I/O", "Create and open file", "MEDIUM"),
    "unlink": ("File I/O", "Delete file", "MEDIUM"),
    "unlinkat": ("File I/O", "Delete file relative to directory fd", "MEDIUM"),
    "rename": ("File I/O", "Rename file", "LOW"),
    "renameat": ("File I/O", "Rename file relative to directory fd", "LOW"),
    "mkdir": ("File I/O", "Create directory", "LOW"),
    "mkdirat": ("File I/O", "Create directory relative to directory fd", "LOW"),
    "rmdir": ("File I/O", "Remove directory", "LOW"),
    "chmod": ("File I/O", "Change file permissions", "MEDIUM"),
    "fchmod": ("File I/O", "Change file permissions via fd", "MEDIUM"),
    "chown": ("File I/O", "Change file ownership", "MEDIUM"),
    "fchown": ("File I/O", "Change file ownership via fd", "MEDIUM"),
    "statx": ("File I/O", "Extended file status", "INFO"),
    "getdents": ("File I/O", "Read directory entries", "INFO"),
    "getdents64": ("File I/O", "Read directory entries (64-bit)", "INFO"),

    # Process & Thread Management
    "execve": ("Process & Execution", "Execute binary program", "HIGH"),
    "execveat": ("Process & Execution", "Execute program relative to directory fd", "HIGH"),
    "fork": ("Process & Execution", "Create child process", "MEDIUM"),
    "vfork": ("Process & Execution", "Create child process (borrow parent vm)", "MEDIUM"),
    "clone": ("Process & Execution", "Create lightweight process/thread", "MEDIUM"),
    "exit": ("Process & Execution", "Terminate calling process", "INFO"),
    "exit_group": ("Process & Execution", "Exit all threads in process", "INFO"),
    "kill": ("Process & Execution", "Send signal to process", "MEDIUM"),
    "tkill": ("Process & Execution", "Send signal to specific thread", "MEDIUM"),
    "tgkill": ("Process & Execution", "Send signal to thread group", "MEDIUM"),
    "wait4": ("Process & Execution", "Wait for process state change", "INFO"),
    "waitid": ("Process & Execution", "Wait for child process state change", "INFO"),
    "ptrace": ("Process & Execution", "Trace/control process execution (anti-debug / inject)", "HIGH"),
    "prctl": ("Process & Execution", "Operations on a process (e.g. name, seccomp)", "MEDIUM"),
    "arch_prctl": ("Process & Execution", "Architecture-specific process state", "MEDIUM"),

    # Memory Management
    "mmap": ("Memory Management", "Map memory page", "MEDIUM"),
    "mprotect": ("Memory Management", "Set memory protection flags (RWX)", "HIGH"),
    "munmap": ("Memory Management", "Unmap memory page", "LOW"),
    "brk": ("Memory Management", "Change data segment size (heap)", "INFO"),
    "mremap": ("Memory Management", "Remap virtual memory address", "LOW"),
    "madvise": ("Memory Management", "Advise kernel about memory usage", "INFO"),
    "mlock": ("Memory Management", "Lock memory range in RAM", "MEDIUM"),
    "mlock2": ("Memory Management", "Lock memory with flags", "MEDIUM"),
    "pkey_mprotect": ("Memory Management", "Protection key memory protection", "HIGH"),
    "memfd_create": ("Memory Management", "Create anonymous file memory descriptor", "HIGH"),

    # Networking & Sockets
    "socket": ("Networking & Sockets", "Create communication endpoint", "MEDIUM"),
    "connect": ("Networking & Sockets", "Initiate connection on socket", "HIGH"),
    "bind": ("Networking & Sockets", "Bind name/port to socket", "MEDIUM"),
    "listen": ("Networking & Sockets", "Listen for incoming socket connections", "MEDIUM"),
    "accept": ("Networking & Sockets", "Accept incoming connection", "MEDIUM"),
    "accept4": ("Networking & Sockets", "Accept connection with flags", "MEDIUM"),
    "sendto": ("Networking & Sockets", "Send message on socket to address", "MEDIUM"),
    "recvfrom": ("Networking & Sockets", "Receive message from socket", "MEDIUM"),
    "sendmsg": ("Networking & Sockets", "Send complex message on socket", "MEDIUM"),
    "recvmsg": ("Networking & Sockets", "Receive complex message on socket", "MEDIUM"),
    "shutdown": ("Networking & Sockets", "Shut down part of full-duplex socket", "INFO"),
    "setsockopt": ("Networking & Sockets", "Set socket options", "LOW"),
    "getsockopt": ("Networking & Sockets", "Get socket options", "INFO"),
    "socketpair": ("Networking & Sockets", "Create pair of connected sockets", "LOW"),

    # IPC & Signals
    "pipe": ("IPC & Signals", "Create unidirectional data channel", "LOW"),
    "pipe2": ("IPC & Signals", "Create pipe with flags", "LOW"),
    "rt_sigaction": ("IPC & Signals", "Examine and change signal action", "LOW"),
    "rt_sigprocmask": ("IPC & Signals", "Examine and change blocked signals", "LOW"),
    "nanosleep": ("IPC & Signals", "High-resolution sleep", "INFO"),
    "pause": ("IPC & Signals", "Wait for signal", "INFO"),
    "shmget": ("IPC & Signals", "Allocates shared memory segment", "MEDIUM"),
    "shmat": ("IPC & Signals", "Attaches shared memory segment", "MEDIUM"),
    "semget": ("IPC & Signals", "Get semaphore set identifier", "LOW"),
    "msgget": ("IPC & Signals", "Get message queue identifier", "LOW"),

    # Security, Privileges & Capabilities
    "setuid": ("Security & Privileges", "Set real/effective user ID", "HIGH"),
    "setgid": ("Security & Privileges", "Set real/effective group ID", "HIGH"),
    "seteuid": ("Security & Privileges", "Set effective user ID", "HIGH"),
    "setegid": ("Security & Privileges", "Set effective group ID", "HIGH"),
    "setreuid": ("Security & Privileges", "Set real and effective user ID", "HIGH"),
    "setregid": ("Security & Privileges", "Set real and effective group ID", "HIGH"),
    "chroot": ("Security & Privileges", "Change root directory", "HIGH"),
    "capset": ("Security & Privileges", "Set thread capabilities", "HIGH"),
    "capget": ("Security & Privileges", "Get thread capabilities", "MEDIUM"),
    "seccomp": ("Security & Privileges", "Operate on seccomp sandbox state", "HIGH"),
    "bpf": ("Security & Privileges", "Execute Berkeley Packet Filter commands", "HIGH"),
    "landlock_restrict_self": ("Security & Privileges", "Enforce Landlock sandbox", "HIGH"),

    # System Info & Hardware
    "uname": ("System Info & Hardware", "Get system architecture/kernel name", "INFO"),
    "getpid": ("System Info & Hardware", "Get process ID", "INFO"),
    "getppid": ("System Info & Hardware", "Get parent process ID", "INFO"),
    "getuid": ("System Info & Hardware", "Get user ID", "INFO"),
    "geteuid": ("System Info & Hardware", "Get effective user ID", "INFO"),
    "getgid": ("System Info & Hardware", "Get group ID", "INFO"),
    "getegid": ("System Info & Hardware", "Get effective group ID", "INFO"),
    "sysinfo": ("System Info & Hardware", "Return system information statistics", "INFO"),
    "getrandom": ("System Info & Hardware", "Obtain series of random bytes", "LOW"),
    "clock_gettime": ("System Info & Hardware", "Get clock time", "INFO"),
    "gettimeofday": ("System Info & Hardware", "Get time of day", "INFO"),
}

# Windows Native (NT) Syscalls and Win32 Core APIs
WINDOWS_SYSCALL_CATALOG: Dict[str, Tuple[str, str, str, str]] = {
    # Name: (category, description, severity, detection_type)
    # Native NT Syscalls
    "NtCreateFile": ("File I/O", "Native NT file creation/open", "MEDIUM", "WINDOWS_NATIVE"),
    "ZwCreateFile": ("File I/O", "Native NT file creation/open", "MEDIUM", "WINDOWS_NATIVE"),
    "NtOpenFile": ("File I/O", "Native NT file open", "MEDIUM", "WINDOWS_NATIVE"),
    "ZwOpenFile": ("File I/O", "Native NT file open", "MEDIUM", "WINDOWS_NATIVE"),
    "NtReadFile": ("File I/O", "Native NT read file", "LOW", "WINDOWS_NATIVE"),
    "ZwReadFile": ("File I/O", "Native NT read file", "LOW", "WINDOWS_NATIVE"),
    "NtWriteFile": ("File I/O", "Native NT write file", "LOW", "WINDOWS_NATIVE"),
    "ZwWriteFile": ("File I/O", "Native NT write file", "LOW", "WINDOWS_NATIVE"),
    "NtDeleteFile": ("File I/O", "Native NT delete file", "MEDIUM", "WINDOWS_NATIVE"),
    "ZwDeleteFile": ("File I/O", "Native NT delete file", "MEDIUM", "WINDOWS_NATIVE"),
    "NtAllocateVirtualMemory": ("Memory Management", "Native NT virtual memory allocation", "HIGH", "WINDOWS_NATIVE"),
    "ZwAllocateVirtualMemory": ("Memory Management", "Native NT virtual memory allocation", "HIGH", "WINDOWS_NATIVE"),
    "NtProtectVirtualMemory": ("Memory Management", "Native NT memory protection modification", "HIGH", "WINDOWS_NATIVE"),
    "ZwProtectVirtualMemory": ("Memory Management", "Native NT memory protection modification", "HIGH", "WINDOWS_NATIVE"),
    "NtFreeVirtualMemory": ("Memory Management", "Native NT virtual memory release", "LOW", "WINDOWS_NATIVE"),
    "NtCreateThread": ("Process & Execution", "Native NT thread creation", "HIGH", "WINDOWS_NATIVE"),
    "NtCreateThreadEx": ("Process & Execution", "Native NT extended thread creation (injection vector)", "CRITICAL", "WINDOWS_NATIVE"),
    "ZwCreateThreadEx": ("Process & Execution", "Native NT extended thread creation", "CRITICAL", "WINDOWS_NATIVE"),
    "NtCreateProcess": ("Process & Execution", "Native NT process creation", "HIGH", "WINDOWS_NATIVE"),
    "NtCreateProcessEx": ("Process & Execution", "Native NT process creation with inheritance", "HIGH", "WINDOWS_NATIVE"),
    "NtOpenProcess": ("Process & Execution", "Native NT open target process handle", "HIGH", "WINDOWS_NATIVE"),
    "ZwOpenProcess": ("Process & Execution", "Native NT open target process handle", "HIGH", "WINDOWS_NATIVE"),
    "NtTerminateProcess": ("Process & Execution", "Native NT terminate process", "MEDIUM", "WINDOWS_NATIVE"),
    "NtSuspendProcess": ("Process & Execution", "Native NT suspend target process", "HIGH", "WINDOWS_NATIVE"),
    "NtResumeProcess": ("Process & Execution", "Native NT resume target process", "HIGH", "WINDOWS_NATIVE"),
    "NtQueueApcThread": ("Process & Execution", "Native NT APC queuing (APC injection vector)", "CRITICAL", "WINDOWS_NATIVE"),
    "NtWriteVirtualMemory": ("Memory Management", "Native NT write to remote process memory", "CRITICAL", "WINDOWS_NATIVE"),
    "NtReadVirtualMemory": ("Memory Management", "Native NT read from remote process memory", "HIGH", "WINDOWS_NATIVE"),

    # Win32 Wrappers
    "CreateProcessA": ("Process & Execution", "Win32 process creation", "HIGH", "WIN32_API"),
    "CreateProcessW": ("Process & Execution", "Win32 process creation (wide)", "HIGH", "WIN32_API"),
    "CreateRemoteThread": ("Process & Execution", "Win32 remote thread injection", "CRITICAL", "WIN32_API"),
    "VirtualAlloc": ("Memory Management", "Win32 memory allocation", "HIGH", "WIN32_API"),
    "VirtualAllocEx": ("Memory Management", "Win32 remote process memory allocation", "CRITICAL", "WIN32_API"),
    "VirtualProtect": ("Memory Management", "Win32 memory protection change", "HIGH", "WIN32_API"),
    "VirtualProtectEx": ("Memory Management", "Win32 remote process protection change", "CRITICAL", "WIN32_API"),
    "WriteProcessMemory": ("Memory Management", "Win32 write to target process memory", "CRITICAL", "WIN32_API"),
    "ReadProcessMemory": ("Memory Management", "Win32 read target process memory", "HIGH", "WIN32_API"),
    "CreateFileA": ("File I/O", "Win32 open/create file", "MEDIUM", "WIN32_API"),
    "CreateFileW": ("File I/O", "Win32 open/create file (wide)", "MEDIUM", "WIN32_API"),
    "DeleteFileA": ("File I/O", "Win32 delete file", "MEDIUM", "WIN32_API"),
    "DeleteFileW": ("File I/O", "Win32 delete file (wide)", "MEDIUM", "WIN32_API"),
    "WSAStartup": ("Networking & Sockets", "Initialize Winsock DLL", "MEDIUM", "WIN32_API"),
    "connect": ("Networking & Sockets", "Winsock connect", "HIGH", "WIN32_API"),
    "send": ("Networking & Sockets", "Winsock send data", "MEDIUM", "WIN32_API"),
    "recv": ("Networking & Sockets", "Winsock receive data", "MEDIUM", "WIN32_API"),
}

# Java Applet / JVM System Invocations Catalog
JAVA_SYSTEM_CATALOG: Dict[str, Tuple[str, str, str]] = {
    # (Category, Description, Severity)
    "Runtime.getRuntime().exec": ("Process & Execution", "Execute host operating system command/process", "CRITICAL"),
    "ProcessBuilder": ("Process & Execution", "Build and launch host OS process", "CRITICAL"),
    "ProcessBuilder.start": ("Process & Execution", "Start native host process", "CRITICAL"),
    "System.exit": ("Process & Execution", "Terminate JVM instance", "MEDIUM"),
    "System.loadLibrary": ("System & Native", "Load native dynamic library (JNI bridge)", "HIGH"),
    "System.load": ("System & Native", "Load native file path (JNI bridge)", "HIGH"),
    "System.getProperty": ("System Info & Hardware", "Query host environment properties", "LOW"),
    "System.getenv": ("System Info & Hardware", "Read host environment variables", "MEDIUM"),
    "AccessController.doPrivileged": ("Security & Privileges", "Bypass Java Sandbox / Execute with elevated privileges", "CRITICAL"),
    "Socket": ("Networking & Sockets", "Open TCP socket connection", "HIGH"),
    "ServerSocket": ("Networking & Sockets", "Bind and listen on TCP port", "HIGH"),
    "URL.openConnection": ("Networking & Sockets", "Open HTTP/network connection", "MEDIUM"),
    "HttpURLConnection": ("Networking & Sockets", "HTTP network communication", "MEDIUM"),
    "DatagramSocket": ("Networking & Sockets", "Open UDP datagram socket", "HIGH"),
    "File": ("File I/O", "File handle manipulation", "LOW"),
    "FileInputStream": ("File I/O", "Read raw file stream from host disk", "MEDIUM"),
    "FileOutputStream": ("File I/O", "Write raw file stream to host disk", "HIGH"),
    "RandomAccessFile": ("File I/O", "Arbitrary file read/write access", "HIGH"),
    "Files.readAllBytes": ("File I/O", "Read entire file from disk", "MEDIUM"),
    "Files.write": ("File I/O", "Write data to disk file", "HIGH"),
    "Files.delete": ("File I/O", "Delete file on host system", "HIGH"),
    "Unsafe.allocateMemory": ("Memory Management", "Off-heap unmanaged memory allocation", "HIGH"),
    "Unsafe.putAddress": ("Memory Management", "Direct raw pointer manipulation", "CRITICAL"),
}

# macOS / Mach Traps
MACOS_MACH_CATALOG: Dict[str, Tuple[str, str, str]] = {
    "mach_msg": ("IPC & Signals", "Mach kernel IPC message exchange", "MEDIUM"),
    "mach_msg_trap": ("IPC & Signals", "Direct Mach trap for kernel communication", "HIGH"),
    "mach_reply_port": ("IPC & Signals", "Allocate Mach port for reply", "LOW"),
    "mach_task_self": ("Process & Execution", "Get handle to current Mach task", "MEDIUM"),
    "task_for_pid": ("Process & Execution", "Obtain Mach task port of arbitrary process (code injection)", "CRITICAL"),
    "thread_create": ("Process & Execution", "Create Mach thread in task", "HIGH"),
    "vm_allocate": ("Memory Management", "Mach virtual memory allocation", "MEDIUM"),
    "vm_protect": ("Memory Management", "Mach virtual memory protection change", "HIGH"),
    "vm_write": ("Memory Management", "Write memory in Mach task", "CRITICAL"),
    "vm_read": ("Memory Management", "Read memory in Mach task", "HIGH"),
}


class SyscallDetector:
    """Detects system calls across decompiled C code, imports, and Java sources."""

    def __init__(self) -> None:
        # Regex patterns for direct syscall instructions
        # Matches: syscall, sysenter, int 0x80, int 0x2e, svc #0, __asm__("syscall")
        self.direct_asm_pattern = re.compile(
            r"""(?ix)
            \b(
                (?:__asm__\s*(?:volatile)?\s*\(\s*["'].*?(?:syscall|sysenter|int\s*0x80|svc\s*\#?0).*?["']\s*\))|
                (?:\b(?:syscall|sysenter)\s*;) |
                (?:\bint\s+0x80\b) |
                (?:\bsvc\s+\#?0\b) |
                (?:\b__syscall\b)
            )
            """,
            re.VERBOSE,
        )

        # Pattern for libc syscall(NUMBER, ...) invocations
        self.syscall_fn_pattern = re.compile(
            r"""(?ix)
            \b(?:syscall|__syscall)\s*\(\s*
            (?P<nr>0x[0-9a-fA-F]+|\d+|SYS_[a-zA-Z0-9_]+)
            (?P<args>[^)]*)
            \)
            """,
            re.VERBOSE,
        )

        # Pattern for C function calls: func_name(arg1, arg2...)
        self.c_call_pattern = re.compile(
            r"""(?ix)
            \b(?P<func>[a-zA-Z_][a-zA-Z0-9_]*)\s*\((?P<args>[^;{}]*)\)
            """,
            re.VERBOSE,
        )

        # Pattern for Java Applet / Object invocations: Class.method(args) or obj.method(args)
        self.java_method_pattern = re.compile(
            r"""(?ix)
            \b(?P<target>[a-zA-Z0-9_.]+)\s*\((?P<args>[^;{}]*)\)
            """,
            re.VERBOSE,
        )

    def analyze_decompiled_function(
        self,
        function_name: str,
        code: str,
        entry_address: Optional[str] = None,
        target_arch: Optional[str] = None,
    ) -> List[SyscallFinding]:
        """Scans decompiled C or Java code for system calls and returns findings."""
        findings: List[SyscallFinding] = []
        lines = code.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # 1. Check for Direct Syscall Instructions (inline asm, assembly tokens)
            direct_matches = list(self.direct_asm_pattern.finditer(stripped))
            for dm in direct_matches:
                matched_token = dm.group(0)
                findings.append(
                    SyscallFinding(
                        name="direct_syscall",
                        category="Direct Syscall",
                        description=f"Raw hardware/kernel system call instruction: {matched_token}",
                        severity="HIGH",
                        detection_type="DIRECT_SYSCALL",
                        function_name=function_name,
                        address=entry_address,
                        line_number=idx,
                        code_snippet=stripped,
                        arguments="",
                        target_arch=target_arch,
                    )
                )

            # 2. Check for syscall(NR, ...) calls
            syscall_calls = list(self.syscall_fn_pattern.finditer(stripped))
            for sc in syscall_calls:
                raw_nr = sc.group("nr")
                args_str = sc.group("args").strip()
                syscall_name = "syscall"
                syscall_nr = None

                # Resolve numeric syscall number
                try:
                    if raw_nr.lower().startswith("0x"):
                        syscall_nr = int(raw_nr, 16)
                    elif raw_nr.isdigit():
                        syscall_nr = int(raw_nr, 10)
                    elif raw_nr.startswith("SYS_"):
                        candidate = raw_nr[4:].lower()
                        syscall_name = candidate
                except ValueError:
                    pass

                if syscall_nr is not None and syscall_nr in LINUX_X86_64_SYSCALLS:
                    syscall_name = LINUX_X86_64_SYSCALLS[syscall_nr]

                cat, desc, sev = SYSCALL_CATALOG.get(
                    syscall_name,
                    ("System Call", f"Dynamic kernel syscall {raw_nr}", "HIGH"),
                )

                findings.append(
                    SyscallFinding(
                        name=syscall_name,
                        category=cat,
                        description=desc,
                        severity=sev,
                        detection_type="DIRECT_SYSCALL",
                        function_name=function_name,
                        address=entry_address,
                        line_number=idx,
                        code_snippet=stripped,
                        arguments=f"sys_nr={raw_nr}{args_str}",
                        syscall_number=syscall_nr,
                        target_arch=target_arch,
                    )
                )

            # 3. Check for standard POSIX / Libc System Call Wrappers
            for call_match in self.c_call_pattern.finditer(stripped):
                fn = call_match.group("func")
                args = call_match.group("args").strip()

                # Match against standard syscall catalog
                if fn in SYSCALL_CATALOG:
                    cat, desc, sev = SYSCALL_CATALOG[fn]
                    findings.append(
                        SyscallFinding(
                            name=fn,
                            category=cat,
                            description=desc,
                            severity=sev,
                            detection_type="LIBC_WRAPPER",
                            function_name=function_name,
                            address=entry_address,
                            line_number=idx,
                            code_snippet=stripped,
                            arguments=args,
                            target_arch=target_arch,
                        )
                    )

                # Match against Windows Native / Win32
                elif fn in WINDOWS_SYSCALL_CATALOG:
                    cat, desc, sev, det_type = WINDOWS_SYSCALL_CATALOG[fn]
                    findings.append(
                        SyscallFinding(
                            name=fn,
                            category=cat,
                            description=desc,
                            severity=sev,
                            detection_type=det_type,
                            function_name=function_name,
                            address=entry_address,
                            line_number=idx,
                            code_snippet=stripped,
                            arguments=args,
                            target_arch=target_arch,
                        )
                    )

                # Match against macOS Mach traps
                elif fn in MACOS_MACH_CATALOG:
                    cat, desc, sev = MACOS_MACH_CATALOG[fn]
                    findings.append(
                        SyscallFinding(
                            name=fn,
                            category=cat,
                            description=desc,
                            severity=sev,
                            detection_type="MACOS_MACH",
                            function_name=function_name,
                            address=entry_address,
                            line_number=idx,
                            code_snippet=stripped,
                            arguments=args,
                            target_arch=target_arch,
                        )
                    )

            # 4. Check for Java Applet / JVM System Invocations
            for java_key, (j_cat, j_desc, j_sev) in JAVA_SYSTEM_CATALOG.items():
                if java_key in stripped:
                    # Extract arguments if present
                    arg_match = re.search(re.escape(java_key) + r"\s*\((.*?)\)", stripped)
                    args = arg_match.group(1).strip() if arg_match else ""
                    findings.append(
                        SyscallFinding(
                            name=java_key,
                            category=j_cat,
                            description=j_desc,
                            severity=j_sev,
                            detection_type="JAVA_SYSTEM",
                            function_name=function_name,
                            address=entry_address,
                            line_number=idx,
                            code_snippet=stripped,
                            arguments=args,
                            target_arch=target_arch or "Java/JVM",
                        )
                    )

        # Deduplicate findings on the same line for the same syscall
        unique_findings: List[SyscallFinding] = []
        seen = set()
        for f in findings:
            key = (f.name, f.line_number, f.code_snippet)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def analyze_imports(
        self,
        imports: List[Dict[str, Any]],
        target_arch: Optional[str] = None,
    ) -> List[SyscallFinding]:
        """Analyzes imported symbols / functions from the binary header."""
        findings: List[SyscallFinding] = []

        for imp in imports:
            name = imp.get("name") or imp.get("symbol") or ""
            # Strip DLL decoration if present (e.g., KERNEL32.DLL!CreateProcessW)
            base_name = name.split("!")[-1].split("@")[0].strip()
            address = imp.get("address") or imp.get("entry")

            if base_name in SYSCALL_CATALOG:
                cat, desc, sev = SYSCALL_CATALOG[base_name]
                findings.append(
                    SyscallFinding(
                        name=base_name,
                        category=cat,
                        description=f"Imported system call wrapper: {desc}",
                        severity=sev,
                        detection_type="LIBC_WRAPPER",
                        function_name="[IMPORT_TABLE]",
                        address=str(address) if address else None,
                        line_number=0,
                        code_snippet=f"Import: {name}",
                        arguments="",
                        target_arch=target_arch,
                    )
                )
            elif base_name in WINDOWS_SYSCALL_CATALOG:
                cat, desc, sev, det_type = WINDOWS_SYSCALL_CATALOG[base_name]
                findings.append(
                    SyscallFinding(
                        name=base_name,
                        category=cat,
                        description=f"Imported Windows system API: {desc}",
                        severity=sev,
                        detection_type=det_type,
                        function_name="[IMPORT_TABLE]",
                        address=str(address) if address else None,
                        line_number=0,
                        code_snippet=f"Import: {name}",
                        arguments="",
                        target_arch=target_arch,
                    )
                )
            elif base_name in MACOS_MACH_CATALOG:
                cat, desc, sev = MACOS_MACH_CATALOG[base_name]
                findings.append(
                    SyscallFinding(
                        name=base_name,
                        category=cat,
                        description=f"Imported Mach kernel trap: {desc}",
                        severity=sev,
                        detection_type="MACOS_MACH",
                        function_name="[IMPORT_TABLE]",
                        address=str(address) if address else None,
                        line_number=0,
                        code_snippet=f"Import: {name}",
                        arguments="",
                        target_arch=target_arch,
                    )
                )

        return findings
