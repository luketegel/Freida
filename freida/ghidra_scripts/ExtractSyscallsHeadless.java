// Companion Ghidra Headless Script: ExtractSyscallsHeadless.java
// Analyzes binary or applet in Ghidra headless mode without GUI and exports system calls.
//@category HeadlessAnalysis
//@author Ghidra Syscall Analyzer

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class ExtractSyscallsHeadless extends GhidraScript {

    private static final Set<String> KNOWN_SYSCALLS = new HashSet<>(Arrays.asList(
        "read", "write", "open", "openat", "close", "stat", "fstat", "lstat", "poll", "lseek",
        "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "ioctl",
        "access", "pipe", "select", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill",
        "socket", "connect", "accept", "sendto", "recvfrom", "shutdown", "bind", "listen",
        "ptrace", "prctl", "setuid", "setgid", "chroot", "seccomp", "bpf",
        // Windows
        "NtCreateFile", "ZwCreateFile", "NtReadFile", "NtWriteFile", "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory", "NtCreateThreadEx", "CreateProcessA", "CreateProcessW",
        "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
        // Java
        "Runtime.exec", "ProcessBuilder", "System.exit", "System.loadLibrary"
    ));

    @Override
    public void run() throws Exception {
        Program prog = currentProgram;
        if (prog == null) {
            println("No program loaded in Ghidra.");
            return;
        }

        println("Running ExtractSyscallsHeadless on: " + prog.getName());
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(prog);

        File outputFile = new File(prog.getName() + "_headless_syscalls.txt");
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            writer.println("Syscall Analysis for: " + prog.getName());
            writer.println("Architecture: " + prog.getLanguage().getLanguageID());
            writer.println("==================================================");

            FunctionIterator iter = prog.getFunctionManager().getFunctions(true);
            int funcCount = 0;
            int syscallCount = 0;

            while (iter.hasNext() && !monitor.isCancelled()) {
                Function func = iter.next();
                funcCount++;
                DecompileResults results = decomp.decompileFunction(func, 30, monitor);

                if (results != null && results.decompileCompleted()) {
                    String cCode = results.getDecompiledFunction().getC();
                    for (String line : cCode.split("\\r?\\n")) {
                        for (String sc : KNOWN_SYSCALLS) {
                            if (line.contains(sc + "(") || line.contains(sc + " (")) {
                                syscallCount++;
                                writer.println(String.format("[%s @ %s] Found: %s -> %s",
                                    func.getName(), func.getEntryPoint(), sc, line.trim()));
                            }
                        }
                    }
                }
            }
            writer.println("==================================================");
            writer.println("Decompiled " + funcCount + " functions. Identified " + syscallCount + " system calls.");
        }

        println("Saved headless syscall output to: " + outputFile.getAbsolutePath());
    }
}
