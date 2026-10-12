"""Tests for SyscallDetector engine."""

import unittest

from freida.syscall_detector import SyscallDetector


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

    def test_macho_underscore_symbols_resolve(self) -> None:
        code = """int _file_io_operations(void) {
  iVar1 = _open("/tmp/output.dat",0x201);
  ___stack_chk_fail();
  __exit(0);
}"""
        findings = self.detector.analyze_decompiled_function("_file_io_operations", code)
        self.assertEqual([f.name for f in findings], ["open", "exit"])
        self.assertEqual(findings[0].arguments, '"/tmp/output.dat",0x201')

        imports = [{"name": "_mprotect", "library": "/usr/lib/libSystem.B.dylib"}, {"name": "___stack_chk_guard"}]
        self.assertEqual([f.name for f in self.detector.analyze_imports(imports)], ["mprotect"])

    def test_resolve_api_strips_decoration(self) -> None:
        self.assertEqual(self.detector.resolve_api("KERNEL32.DLL::CreateProcessW")[0], "CreateProcessW")
        self.assertEqual(self.detector.resolve_api("send@16")[4], "WIN32_API")
        self.assertIsNone(self.detector.resolve_api("_file_io_operations"))

    def test_ghidra_pcodeop_direct_syscalls(self) -> None:
        # CallSupervisor is verified against Ghidra 12.1.4 AArch64 output; syscall()/swi() follow Ghidra's x86 pcode ops.
        for stmt in ("CallSupervisor(0);", "syscall();", "swi(0x80);"):
            findings = self.detector.analyze_decompiled_function("f", "void f(void) {\n  " + stmt + "\n}")
            self.assertEqual([f.name for f in findings], ["direct_syscall"], stmt)

    def test_syscall_numbers_not_resolved_with_x86_table_on_other_arch(self) -> None:
        code = "void f(void) {\n  syscall(172);\n}"
        arm = self.detector.analyze_decompiled_function("f", code, target_arch="AARCH64:LE:64:AppleSilicon")
        self.assertEqual(arm[0].name, "syscall")
        x86 = self.detector.analyze_decompiled_function("f", code, target_arch="x86:LE:64:default")
        self.assertEqual(x86[0].name, "iopl")

    def test_callsites_pair_with_decompiled_lines(self) -> None:
        code = """void _process_execution(void) {
  pVar1 = _fork();
  _execve("/bin/ls",&local_30,(char **)0x0);
  _exit(0);
}"""
        decompiled = self.detector.analyze_decompiled_function("_process_execution", code, "100000608")
        callsites = [
            {"to": "_execve", "at": "100000660"},
            {"to": "_fork", "at": "100000624"},
            {"to": "_exit", "at": "100000668"},
            {"to": "___stack_chk_fail", "at": "100000688"},
        ]
        merged = self.detector.analyze_callsites("_process_execution", callsites, decompiled, "100000608")

        self.assertEqual([(f.name, f.callsite_address) for f in merged],
                         [("fork", "100000624"), ("execve", "100000660"), ("exit", "100000668")])
        self.assertEqual(merged[1].arguments, '"/bin/ls",&local_30,(char **)0x0')

    def test_callsites_without_matching_lines_are_reported_alone(self) -> None:
        code = "void f(void) {\n  _open(path,0);\n  CallSupervisor(0);\n}"
        decompiled = self.detector.analyze_decompiled_function("f", code)
        callsites = [{"to": "_open", "at": "1000"}, {"to": "_open", "at": "1010"}]
        merged = self.detector.analyze_callsites("f", callsites, decompiled)

        opens = [f for f in merged if f.name == "open"]
        self.assertEqual([(f.callsite_address, f.line_number) for f in opens], [("1000", 0), ("1010", 0)])
        self.assertIn("direct_syscall", [f.name for f in merged])


if __name__ == "__main__":
    unittest.main()
