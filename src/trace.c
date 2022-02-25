#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <unistd.h>
#include <stdio.h>

#include "syscalls.h"

int main(int argc, char *argv[]) {

    if (argc < 2) {
        fprintf(stderr,"Usage: %s <elf>\n", argv[0]);
        return 1;
    }

    // check file exists
    if (access(argv[1], X_OK) != 0) {
        perror("access");
        return 1;
    }

    // run program in child process and trace with parent
    int status;
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(argv[1], argv+1);
        
        // if we get here, execv failed
        fprintf(stderr, "FAILED TO EXECUTE: %s\n", argv[1]);
        return 1;
    } 
    wait(&status);

    while (1) {

        // wait for syscall
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        wait(&status);
        if (WIFEXITED(status)) break;

        // get registers
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child, 0, &regs);

        // put registers in array for formating
        long long args[] = {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};

        // get and print formated syscall
        char formatstr[MAXSYSCALLFORMATLEN];
        get_syscall_format_string(regs.orig_rax, formatstr, args, child);
        fprintf(stderr, "%s = ",  formatstr);

        // wait for next syscall
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        wait(&status);
        if (WIFEXITED(status)) {
            fprintf(stderr, "?\n");
            break;
        }

        // get call return value
        long ret = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX);
        fprintf(stderr, "%ld\n", ret);
    }
    return 0;
}
