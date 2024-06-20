#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>

void run_target(const char* programname) {
    printf("Target started. Will run: %s\n", programname);

    // Allow tracing of this process
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("ptrace");
        exit(1);
    }

    // Replace this process's image with the target program
    execl(programname, programname, NULL);
}

void run_tracer(pid_t child_pid) {
    int wait_status;
    struct user_regs_struct regs;

    // Wait for child to stop on its first instruction
    waitpid(child_pid, &wait_status, 0);

    while (1) {
        // Wait for a system call entry or exit
        if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) == -1) {
            perror("ptrace");
            exit(1);
        }

        // Wait for child to stop again
        waitpid(child_pid, &wait_status, 0);

        // Get the current register values
        if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) == -1) {
            perror("ptrace");
            exit(1);
        }

        // Check if this is a syscall entry
        if (regs.orig_rax == -1) {
            // This is not a syscall entry, continue
            continue;
        }

        // Print the syscall number
        printf("Syscall intercepted: %lld\n", regs.orig_rax);

        // Continue to the next system call exit
        if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) == -1) {
            perror("ptrace");
            exit(1);
        }

        // Wait for child to stop again
        waitpid(child_pid, &wait_status, 0);

        // Get the current register values
        if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) == -1) {
            perror("ptrace");
            exit(1);
        }
    }
}

int main(int argc, char* argv[]) {
    pid_t child_pid;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program to trace>\n", argv[0]);
        return 1;
    }

    child_pid = fork();
    if (child_pid == 0) {
        // Child process: Run the target program
        run_target(argv[1]);
    } else if (child_pid > 0) {
        // Parent process: Trace the child
        run_tracer(child_pid);
    } else {
        perror("fork");
        return 1;
    }

    return 0;
}
