/*
 * Sample Target Binary Source
 * Demonstrates direct assembly syscalls, libc wrappers, and memory management.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>

void perform_direct_syscall() {
    // Direct Linux/POSIX syscall wrapper
    const char msg[] = "Direct syscall test\n";
#if defined(__x86_64__)
    __asm__ volatile ("syscall" : : "a"(39)); // 39 = getpid on x86_64
#elif defined(__aarch64__)
    __asm__ volatile ("svc #0" : : "r"(172)); // 172 = getpid on arm64
#endif
}

void file_io_operations() {
    int fd = open("/tmp/output.dat", O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        write(fd, "Data payload", 12);
        close(fd);
    }
}

void network_operations() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;

    connect(s, (struct sockaddr *)&addr, sizeof(addr));
    close(s);
}

void process_execution() {
    pid_t p = fork();
    if (p == 0) {
        char *args[] = {"/bin/ls", "-la", NULL};
        execve("/bin/ls", args, NULL);
        exit(0);
    }
}

void memory_manipulation() {
    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    mprotect(mem, 4096, PROT_READ | PROT_WRITE | PROT_EXEC); // RWX page allocation
    munmap(mem, 4096);
}

int main(int argc, char **argv) {
    perform_direct_syscall();
    file_io_operations();
    network_operations();
    process_execution();
    memory_manipulation();
    return 0;
}
