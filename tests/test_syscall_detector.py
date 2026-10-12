"""Tests for SyscallDetector engine."""

import unittest
from ghidra_syscall_analyzer.syscall_detector import SyscallDetector


class TestSyscallDetector(unittest.TestCase):

    def setUp(self) -> None:
        self.detector = SyscallDetector()

    def test_direct_assembly_syscall(self) -> None:
        code = """void test_func() {
            __asm__ volatile ("syscall");
        }"""
        findings = self.detector.analyze_decompiled_function("test_func", code, "0x401000")
        self.assertGreaterEqual(len(findings), 1)
        direct_finds = [f for f in findings if f.detection_type == "DIRECT_SYSCALL"]
        self.assertTrue(len(direct_finds) > 0)
        self.assertEqual(direct_finds[0].severity, "HIGH")

    def test_libc_syscall_number_resolution(self) -> None:
        # syscall(1, ...) -> Linux x86_64 write
        code = """void test_write() {
            syscall(1, 1, "hello", 5);
        }"""
        findings = self.detector.analyze_decompiled_function("test_write", code, "0x401050")
        names = [f.name for f in findings]
        self.assertIn("write", names)
        write_finding = next(f for f in findings if f.name == "write")
        self.assertEqual(write_finding.category, "File I/O")
        self.assertEqual(write_finding.syscall_number, 1)

    def test_posix_wrappers(self) -> None:
        code = """int do_work() {
            int fd = open("/etc/passwd", 0);
            read(fd, buf, 100);
            close(fd);
            pid_t p = fork();
            if (p == 0) {
                execve("/bin/sh", NULL, NULL);
            }
            return 0;
        }"""
        findings = self.detector.analyze_decompiled_function("do_work", code)
        names = [f.name for f in findings]
        self.assertIn("open", names)
        self.assertIn("read", names)
        self.assertIn("close", names)
        self.assertIn("fork", names)
        self.assertIn("execve", names)

        execve_find = next(f for f in findings if f.name == "execve")
        self.assertEqual(execve_find.severity, "HIGH")
        self.assertEqual(execve_find.category, "Process & Execution")

    def test_windows_native_and_win32(self) -> None:
        code = """void inject() {
            HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            LPVOID mem = VirtualAllocEx(h, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            WriteProcessMemory(h, mem, buf, 4096, NULL);
            NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, h, mem, NULL, FALSE, 0, 0, 0, NULL);
        }"""
        findings = self.detector.analyze_decompiled_function("inject", code)
        names = [f.name for f in findings]
        self.assertIn("VirtualAllocEx", names)
        self.assertIn("WriteProcessMemory", names)
        self.assertIn("NtCreateThreadEx", names)

        nt_find = next(f for f in findings if f.name == "NtCreateThreadEx")
        self.assertEqual(nt_find.detection_type, "WINDOWS_NATIVE")
        self.assertEqual(nt_find.severity, "CRITICAL")

    def test_java_applet_system_calls(self) -> None:
        code = """public void init() {
            Runtime.getRuntime().exec("calc.exe");
            AccessController.doPrivileged(new PrivilegedAction() { ... });
            Socket s = new Socket("example.com", 80);
            FileOutputStream fos = new FileOutputStream("/tmp/test");
        }"""
        findings = self.detector.analyze_decompiled_function("init", code)
        names = [f.name for f in findings]
        self.assertIn("Runtime.getRuntime().exec", names)
        self.assertIn("AccessController.doPrivileged", names)
        self.assertIn("Socket", names)
        self.assertIn("FileOutputStream", names)

        runtime_find = next(f for f in findings if f.name == "Runtime.getRuntime().exec")
        self.assertEqual(runtime_find.severity, "CRITICAL")
        self.assertEqual(runtime_find.category, "Process & Execution")
        self.assertEqual(runtime_find.detection_type, "JAVA_SYSTEM")

    def test_imports_analysis(self) -> None:
        imports = [
            {"name": "mprotect", "address": "0x400010"},
            {"name": "KERNEL32.DLL!CreateProcessW", "address": "0x400020"},
            {"name": "mach_msg", "address": "0x400030"},
        ]
        findings = self.detector.analyze_imports(imports)
        names = [f.name for f in findings]
        self.assertIn("mprotect", names)
        self.assertIn("CreateProcessW", names)
        self.assertIn("mach_msg", names)


if __name__ == "__main__":
    unittest.main()
