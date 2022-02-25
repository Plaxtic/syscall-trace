#include <string.h>
#include <ctype.h>
#include <sys/ptrace.h>

#define MAXSYSCALLNAMELEN 22
#define MAXSYSCALLFORMATLEN MAXSYSCALLNAMELEN + (50*9) 
#define LONGSIZ sizeof(long long)

struct syscall {
    int code;
    char *name;
    int nargs;
    char dref[6];
} syscall_table[] = {
    {0x00, "read", 3, {0, 1, 0, 0, 0, 0}},
    {0x01, "write", 3, {0, 1, 0, 0, 0, 0}},
    {0x02, "open", 3, {1, 0, 0, 0, 0, 0}},
    {0x03, "close", 1, {0, 0, 0, 0, 0, 0}},
    {0x04, "stat", 2, {1, 1, 0, 0, 0, 0}},
    {0x05, "fstat", 2, {0, 1, 0, 0, 0, 0}},
    {0x06, "lstat", 2, {1, 1, 0, 0, 0, 0}},
    {0x07, "poll", 3, {1, 0, 0, 0, 0, 0}},
    {0x08, "lseek", 3, {0, 0, 0, 0, 0, 0}},
    {0x09, "mmap", 6, {0, 0, 0, 0, 0, 0}},
    {0x0a, "mprotect", 3, {0, 0, 0, 0, 0, 0}},
    {0x0b, "munmap", 2, {0, 0, 0, 0, 0, 0}},
    {0x0c, "brk", 1, {0, 0, 0, 0, 0, 0}},
    {0x0d, "rt_sigaction", 4, {0, 1, 1, 0, 0, 0}},
    {0x0e, "rt_sigprocmask", 4, {0, 1, 1, 0, 0, 0}},
    {0x0f, "rt_sigreturn", 6, {0, 0, 0, 0, 0, 0}},
    {0x10, "ioctl", 3, {0, 0, 0, 0, 0, 0}},
    {0x11, "pread64", 4, {0, 1, 0, 0, 0, 0}},
    {0x12, "pwrite64", 4, {0, 1, 0, 0, 0, 0}},
    {0x13, "readv", 3, {0, 1, 0, 0, 0, 0}},
    {0x14, "writev", 3, {0, 1, 0, 0, 0, 0}},
    {0x15, "access", 2, {1, 0, 0, 0, 0, 0}},
    {0x16, "pipe", 1, {1, 0, 0, 0, 0, 0}},
    {0x17, "select", 5, {0, 1, 1, 1, 1, 0}},
    {0x18, "sched_yield", 0, {0, 0, 0, 0, 0, 0}},
    {0x19, "mremap", 5, {0, 0, 0, 0, 0, 0}},
    {0x1a, "msync", 3, {0, 0, 0, 0, 0, 0}},
    {0x1b, "mincore", 3, {0, 0, 1, 0, 0, 0}},
    {0x1c, "madvise", 3, {0, 0, 0, 0, 0, 0}},
    {0x1d, "shmget", 3, {0, 0, 0, 0, 0, 0}},
    {0x1e, "shmat", 3, {0, 1, 0, 0, 0, 0}},
    {0x1f, "shmctl", 3, {0, 0, 1, 0, 0, 0}},
    {0x20, "dup", 1, {0, 0, 0, 0, 0, 0}},
    {0x21, "dup2", 2, {0, 0, 0, 0, 0, 0}},
    {0x22, "pause", 0, {0, 0, 0, 0, 0, 0}},
    {0x23, "nanosleep", 2, {1, 1, 0, 0, 0, 0}},
    {0x24, "getitimer", 2, {0, 1, 0, 0, 0, 0}},
    {0x25, "alarm", 1, {0, 0, 0, 0, 0, 0}},
    {0x26, "setitimer", 3, {0, 1, 1, 0, 0, 0}},
    {0x27, "getpid", 0, {0, 0, 0, 0, 0, 0}},
    {0x28, "sendfile", 4, {0, 0, 1, 0, 0, 0}},
    {0x29, "socket", 3, {0, 0, 0, 0, 0, 0}},
    {0x2a, "connect", 3, {0, 1, 0, 0, 0, 0}},
    {0x2b, "accept", 3, {0, 1, 1, 0, 0, 0}},
    {0x2c, "sendto", 6, {0, 1, 0, 0, 1, 0}},
    {0x2d, "recvfrom", 6, {0, 1, 0, 0, 1, 1}},
    {0x2e, "sendmsg", 3, {0, 1, 0, 0, 0, 0}},
    {0x2f, "recvmsg", 3, {0, 1, 0, 0, 0, 0}},
    {0x30, "shutdown", 2, {0, 0, 0, 0, 0, 0}},
    {0x31, "bind", 3, {0, 1, 0, 0, 0, 0}},
    {0x32, "listen", 2, {0, 0, 0, 0, 0, 0}},
    {0x33, "getsockname", 3, {0, 1, 1, 0, 0, 0}},
    {0x34, "getpeername", 3, {0, 1, 1, 0, 0, 0}},
    {0x35, "socketpair", 4, {0, 0, 0, 1, 0, 0}},
    {0x36, "setsockopt", 5, {0, 0, 0, 1, 0, 0}},
    {0x37, "getsockopt", 5, {0, 0, 0, 1, 1, 0}},
    {0x38, "clone", 5, {0, 0, 1, 1, 0, 0}},
    {0x39, "fork", 0, {0, 0, 0, 0, 0, 0}},
    {0x3a, "vfork", 0, {0, 0, 0, 0, 0, 0}},
    {0x3b, "execve", 3, {1, 1, 1, 0, 0, 0}},
    {0x3c, "exit", 1, {0, 0, 0, 0, 0, 0}},
    {0x3d, "wait4", 4, {0, 1, 0, 1, 0, 0}},
    {0x3e, "kill", 2, {0, 0, 0, 0, 0, 0}},
    {0x3f, "uname", 1, {1, 0, 0, 0, 0, 0}},
    {0x40, "semget", 3, {0, 0, 0, 0, 0, 0}},
    {0x41, "semop", 3, {0, 1, 0, 0, 0, 0}},
    {0x42, "semctl", 4, {0, 0, 0, 0, 0, 0}},
    {0x43, "shmdt", 1, {1, 0, 0, 0, 0, 0}},
    {0x44, "msgget", 2, {0, 0, 0, 0, 0, 0}},
    {0x45, "msgsnd", 4, {0, 1, 0, 0, 0, 0}},
    {0x46, "msgrcv", 5, {0, 1, 0, 0, 0, 0}},
    {0x47, "msgctl", 3, {0, 0, 1, 0, 0, 0}},
    {0x48, "fcntl", 3, {0, 0, 0, 0, 0, 0}},
    {0x49, "flock", 2, {0, 0, 0, 0, 0, 0}},
    {0x4a, "fsync", 1, {0, 0, 0, 0, 0, 0}},
    {0x4b, "fdatasync", 1, {0, 0, 0, 0, 0, 0}},
    {0x4c, "truncate", 2, {1, 0, 0, 0, 0, 0}},
    {0x4d, "ftruncate", 2, {0, 0, 0, 0, 0, 0}},
    {0x4e, "getdents", 3, {0, 1, 0, 0, 0, 0}},
    {0x4f, "getcwd", 2, {1, 0, 0, 0, 0, 0}},
    {0x50, "chdir", 1, {1, 0, 0, 0, 0, 0}},
    {0x51, "fchdir", 1, {0, 0, 0, 0, 0, 0}},
    {0x52, "rename", 2, {1, 1, 0, 0, 0, 0}},
    {0x53, "mkdir", 2, {1, 0, 0, 0, 0, 0}},
    {0x54, "rmdir", 1, {1, 0, 0, 0, 0, 0}},
    {0x55, "creat", 2, {1, 0, 0, 0, 0, 0}},
    {0x56, "link", 2, {1, 1, 0, 0, 0, 0}},
    {0x57, "unlink", 1, {1, 0, 0, 0, 0, 0}},
    {0x58, "symlink", 2, {1, 1, 0, 0, 0, 0}},
    {0x59, "readlink", 3, {1, 1, 0, 0, 0, 0}},
    {0x5a, "chmod", 2, {1, 0, 0, 0, 0, 0}},
    {0x5b, "fchmod", 2, {0, 0, 0, 0, 0, 0}},
    {0x5c, "chown", 3, {1, 0, 0, 0, 0, 0}},
    {0x5d, "fchown", 3, {0, 0, 0, 0, 0, 0}},
    {0x5e, "lchown", 3, {1, 0, 0, 0, 0, 0}},
    {0x5f, "umask", 1, {0, 0, 0, 0, 0, 0}},
    {0x60, "gettimeofday", 2, {1, 1, 0, 0, 0, 0}},
    {0x61, "getrlimit", 2, {0, 1, 0, 0, 0, 0}},
    {0x62, "getrusage", 2, {0, 1, 0, 0, 0, 0}},
    {0x63, "sysinfo", 1, {1, 0, 0, 0, 0, 0}},
    {0x64, "times", 1, {1, 0, 0, 0, 0, 0}},
    {0x65, "ptrace", 4, {0, 0, 0, 0, 0, 0}},
    {0x66, "getuid", 0, {0, 0, 0, 0, 0, 0}},
    {0x67, "syslog", 3, {0, 1, 0, 0, 0, 0}},
    {0x68, "getgid", 0, {0, 0, 0, 0, 0, 0}},
    {0x69, "setuid", 1, {0, 0, 0, 0, 0, 0}},
    {0x6a, "setgid", 1, {0, 0, 0, 0, 0, 0}},
    {0x6b, "geteuid", 0, {0, 0, 0, 0, 0, 0}},
    {0x6c, "getegid", 0, {0, 0, 0, 0, 0, 0}},
    {0x6d, "setpgid", 2, {0, 0, 0, 0, 0, 0}},
    {0x6e, "getppid", 0, {0, 0, 0, 0, 0, 0}},
    {0x6f, "getpgrp", 0, {0, 0, 0, 0, 0, 0}},
    {0x70, "setsid", 0, {0, 0, 0, 0, 0, 0}},
    {0x71, "setreuid", 2, {0, 0, 0, 0, 0, 0}},
    {0x72, "setregid", 2, {0, 0, 0, 0, 0, 0}},
    {0x73, "getgroups", 2, {0, 1, 0, 0, 0, 0}},
    {0x74, "setgroups", 2, {0, 1, 0, 0, 0, 0}},
    {0x75, "setresuid", 3, {0, 0, 0, 0, 0, 0}},
    {0x76, "getresuid", 3, {1, 1, 1, 0, 0, 0}},
    {0x77, "setresgid", 3, {0, 0, 0, 0, 0, 0}},
    {0x78, "getresgid", 3, {1, 1, 1, 0, 0, 0}},
    {0x79, "getpgid", 1, {0, 0, 0, 0, 0, 0}},
    {0x7a, "setfsuid", 1, {0, 0, 0, 0, 0, 0}},
    {0x7b, "setfsgid", 1, {0, 0, 0, 0, 0, 0}},
    {0x7c, "getsid", 1, {0, 0, 0, 0, 0, 0}},
    {0x7d, "capget", 2, {0, 0, 0, 0, 0, 0}},
    {0x7e, "capset", 2, {0, 0, 0, 0, 0, 0}},
    {0x7f, "rt_sigpending", 2, {1, 0, 0, 0, 0, 0}},
    {0x80, "rt_sigtimedwait", 4, {1, 1, 1, 0, 0, 0}},
    {0x81, "rt_sigqueueinfo", 3, {0, 0, 1, 0, 0, 0}},
    {0x82, "rt_sigsuspend", 2, {1, 0, 0, 0, 0, 0}},
    {0x83, "sigaltstack", 2, {1, 1, 0, 0, 0, 0}},
    {0x84, "utime", 2, {1, 1, 0, 0, 0, 0}},
    {0x85, "mknod", 3, {1, 0, 0, 0, 0, 0}},
    {0x86, "uselib", 1, {1, 0, 0, 0, 0, 0}},
    {0x87, "personality", 1, {0, 0, 0, 0, 0, 0}},
    {0x88, "ustat", 2, {0, 1, 0, 0, 0, 0}},
    {0x89, "statfs", 2, {1, 1, 0, 0, 0, 0}},
    {0x8a, "fstatfs", 2, {0, 1, 0, 0, 0, 0}},
    {0x8b, "sysfs", 3, {0, 0, 0, 0, 0, 0}},
    {0x8c, "getpriority", 2, {0, 0, 0, 0, 0, 0}},
    {0x8d, "setpriority", 3, {0, 0, 0, 0, 0, 0}},
    {0x8e, "sched_setparam", 2, {0, 1, 0, 0, 0, 0}},
    {0x8f, "sched_getparam", 2, {0, 1, 0, 0, 0, 0}},
    {0x90, "sched_setscheduler", 3, {0, 0, 1, 0, 0, 0}},
    {0x91, "sched_getscheduler", 1, {0, 0, 0, 0, 0, 0}},
    {0x92, "sched_get_priority_max", 1, {0, 0, 0, 0, 0, 0}},
    {0x93, "sched_get_priority_min", 1, {0, 0, 0, 0, 0, 0}},
    {0x94, "sched_rr_get_interval", 2, {0, 1, 0, 0, 0, 0}},
    {0x95, "mlock", 2, {0, 0, 0, 0, 0, 0}},
    {0x96, "munlock", 2, {0, 0, 0, 0, 0, 0}},
    {0x97, "mlockall", 1, {0, 0, 0, 0, 0, 0}},
    {0x98, "munlockall", 0, {0, 0, 0, 0, 0, 0}},
    {0x99, "vhangup", 0, {0, 0, 0, 0, 0, 0}},
    {0x9a, "modify_ldt", 6, {0, 0, 0, 0, 0, 0}},
    {0x9b, "pivot_root", 2, {1, 1, 0, 0, 0, 0}},
    {0x9c, "_sysctl", 6, {0, 0, 0, 0, 0, 0}},
    {0x9d, "prctl", 5, {0, 0, 0, 0, 0, 0}},
    {0x9e, "arch_prctl", 6, {0, 0, 0, 0, 0, 0}},
    {0x9f, "adjtimex", 1, {1, 0, 0, 0, 0, 0}},
    {0xa0, "setrlimit", 2, {0, 1, 0, 0, 0, 0}},
    {0xa1, "chroot", 1, {1, 0, 0, 0, 0, 0}},
    {0xa2, "sync", 0, {0, 0, 0, 0, 0, 0}},
    {0xa3, "acct", 1, {1, 0, 0, 0, 0, 0}},
    {0xa4, "settimeofday", 2, {1, 1, 0, 0, 0, 0}},
    {0xa5, "mount", 5, {1, 1, 1, 0, 1, 0}},
    {0xa6, "umount2", 6, {0, 0, 0, 0, 0, 0}},
    {0xa7, "swapon", 2, {1, 0, 0, 0, 0, 0}},
    {0xa8, "swapoff", 1, {1, 0, 0, 0, 0, 0}},
    {0xa9, "reboot", 4, {0, 0, 0, 1, 0, 0}},
    {0xaa, "sethostname", 2, {1, 0, 0, 0, 0, 0}},
    {0xab, "setdomainname", 2, {1, 0, 0, 0, 0, 0}},
    {0xac, "iopl", 6, {0, 0, 0, 0, 0, 0}},
    {0xad, "ioperm", 3, {0, 0, 0, 0, 0, 0}},
    {0xae, "create_module", 6, {0, 0, 0, 0, 0, 0}},
    {0xaf, "init_module", 3, {1, 0, 1, 0, 0, 0}},
    {0xb0, "delete_module", 2, {1, 0, 0, 0, 0, 0}},
    {0xb1, "get_kernel_syms", 6, {0, 0, 0, 0, 0, 0}},
    {0xb2, "query_module", 6, {0, 0, 0, 0, 0, 0}},
    {0xb3, "quotactl", 4, {0, 1, 0, 1, 0, 0}},
    {0xb4, "nfsservctl", 6, {0, 0, 0, 0, 0, 0}},
    {0xb5, "getpmsg", 6, {0, 0, 0, 0, 0, 0}},
    {0xb6, "putpmsg", 6, {0, 0, 0, 0, 0, 0}},
    {0xb7, "afs_syscall", 6, {0, 0, 0, 0, 0, 0}},
    {0xb8, "tuxcall", 6, {0, 0, 0, 0, 0, 0}},
    {0xb9, "security", 6, {0, 0, 0, 0, 0, 0}},
    {0xba, "gettid", 0, {0, 0, 0, 0, 0, 0}},
    {0xbb, "readahead", 3, {0, 0, 0, 0, 0, 0}},
    {0xbc, "setxattr", 5, {1, 1, 1, 0, 0, 0}},
    {0xbd, "lsetxattr", 5, {1, 1, 1, 0, 0, 0}},
    {0xbe, "fsetxattr", 5, {0, 1, 1, 0, 0, 0}},
    {0xbf, "getxattr", 4, {1, 1, 1, 0, 0, 0}},
    {0xc0, "lgetxattr", 4, {1, 1, 1, 0, 0, 0}},
    {0xc1, "fgetxattr", 4, {0, 1, 1, 0, 0, 0}},
    {0xc2, "listxattr", 3, {1, 1, 0, 0, 0, 0}},
    {0xc3, "llistxattr", 3, {1, 1, 0, 0, 0, 0}},
    {0xc4, "flistxattr", 3, {0, 1, 0, 0, 0, 0}},
    {0xc5, "removexattr", 2, {1, 1, 0, 0, 0, 0}},
    {0xc6, "lremovexattr", 2, {1, 1, 0, 0, 0, 0}},
    {0xc7, "fremovexattr", 2, {0, 1, 0, 0, 0, 0}},
    {0xc8, "tkill", 2, {0, 0, 0, 0, 0, 0}},
    {0xc9, "time", 1, {1, 0, 0, 0, 0, 0}},
    {0xca, "futex", 6, {1, 0, 0, 1, 1, 0}},
    {0xcb, "sched_setaffinity", 3, {0, 0, 1, 0, 0, 0}},
    {0xcc, "sched_getaffinity", 3, {0, 0, 1, 0, 0, 0}},
    {0xcd, "set_thread_area", 6, {0, 0, 0, 0, 0, 0}},
    {0xce, "io_setup", 2, {0, 1, 0, 0, 0, 0}},
    {0xcf, "io_destroy", 1, {0, 0, 0, 0, 0, 0}},
    {0xd0, "io_getevents", 5, {0, 0, 0, 1, 1, 0}},
    {0xd1, "io_submit", 3, {0, 0, 1, 0, 0, 0}},
    {0xd2, "io_cancel", 3, {0, 1, 1, 0, 0, 0}},
    {0xd3, "get_thread_area", 6, {0, 0, 0, 0, 0, 0}},
    {0xd4, "lookup_dcookie", 3, {0, 1, 0, 0, 0, 0}},
    {0xd5, "epoll_create", 1, {0, 0, 0, 0, 0, 0}},
    {0xd6, "epoll_ctl_old", 6, {0, 0, 0, 0, 0, 0}},
    {0xd7, "epoll_wait_old", 6, {0, 0, 0, 0, 0, 0}},
    {0xd8, "remap_file_pages", 5, {0, 0, 0, 0, 0, 0}},
    {0xd9, "getdents64", 3, {0, 1, 0, 0, 0, 0}},
    {0xda, "set_tid_address", 1, {1, 0, 0, 0, 0, 0}},
    {0xdb, "restart_syscall", 0, {0, 0, 0, 0, 0, 0}},
    {0xdc, "semtimedop", 4, {0, 1, 0, 1, 0, 0}},
    {0xdd, "fadvise64", 4, {0, 0, 0, 0, 0, 0}},
    {0xde, "timer_create", 3, {0, 1, 1, 0, 0, 0}},
    {0xdf, "timer_settime", 4, {0, 0, 1, 1, 0, 0}},
    {0xe0, "timer_gettime", 2, {0, 1, 0, 0, 0, 0}},
    {0xe1, "timer_getoverrun", 1, {0, 0, 0, 0, 0, 0}},
    {0xe2, "timer_delete", 1, {0, 0, 0, 0, 0, 0}},
    {0xe3, "clock_settime", 2, {0, 1, 0, 0, 0, 0}},
    {0xe4, "clock_gettime", 2, {0, 1, 0, 0, 0, 0}},
    {0xe5, "clock_getres", 2, {0, 1, 0, 0, 0, 0}},
    {0xe6, "clock_nanosleep", 4, {0, 0, 1, 1, 0, 0}},
    {0xe7, "exit_group", 1, {0, 0, 0, 0, 0, 0}},
    {0xe8, "epoll_wait", 4, {0, 1, 0, 0, 0, 0}},
    {0xe9, "epoll_ctl", 4, {0, 0, 0, 1, 0, 0}},
    {0xea, "tgkill", 3, {0, 0, 0, 0, 0, 0}},
    {0xeb, "utimes", 2, {1, 1, 0, 0, 0, 0}},
    {0xec, "vserver", 6, {0, 0, 0, 0, 0, 0}},
    {0xed, "mbind", 6, {0, 0, 0, 1, 0, 0}},
    {0xee, "set_mempolicy", 3, {0, 1, 0, 0, 0, 0}},
    {0xef, "get_mempolicy", 5, {1, 1, 0, 0, 0, 0}},
    {0xf0, "mq_open", 4, {1, 0, 0, 1, 0, 0}},
    {0xf1, "mq_unlink", 1, {1, 0, 0, 0, 0, 0}},
    {0xf2, "mq_timedsend", 5, {0, 1, 0, 0, 1, 0}},
    {0xf3, "mq_timedreceive", 5, {0, 1, 0, 1, 1, 0}},
    {0xf4, "mq_notify", 2, {0, 1, 0, 0, 0, 0}},
    {0xf5, "mq_getsetattr", 3, {0, 1, 1, 0, 0, 0}},
    {0xf6, "kexec_load", 4, {0, 0, 1, 0, 0, 0}},
    {0xf7, "waitid", 5, {0, 0, 1, 0, 1, 0}},
    {0xf8, "add_key", 5, {1, 1, 1, 0, 0, 0}},
    {0xf9, "request_key", 4, {1, 1, 1, 0, 0, 0}},
    {0xfa, "keyctl", 5, {0, 0, 0, 0, 0, 0}},
    {0xfb, "ioprio_set", 3, {0, 0, 0, 0, 0, 0}},
    {0xfc, "ioprio_get", 2, {0, 0, 0, 0, 0, 0}},
    {0xfd, "inotify_init", 0, {0, 0, 0, 0, 0, 0}},
    {0xfe, "inotify_add_watch", 3, {0, 1, 0, 0, 0, 0}},
    {0xff, "inotify_rm_watch", 2, {0, 0, 0, 0, 0, 0}},
    {0x100, "migrate_pages", 4, {0, 0, 1, 1, 0, 0}},
    {0x101, "openat", 4, {0, 1, 0, 0, 0, 0}},
    {0x102, "mkdirat", 3, {0, 1, 0, 0, 0, 0}},
    {0x103, "mknodat", 4, {0, 1, 0, 0, 0, 0}},
    {0x104, "fchownat", 5, {0, 1, 0, 0, 0, 0}},
    {0x105, "futimesat", 3, {0, 1, 1, 0, 0, 0}},
    {0x106, "newfstatat", 4, {0, 1, 1, 0, 0, 0}},
    {0x107, "unlinkat", 3, {0, 1, 0, 0, 0, 0}},
    {0x108, "renameat", 4, {0, 1, 0, 1, 0, 0}},
    {0x109, "linkat", 5, {0, 1, 0, 1, 0, 0}},
    {0x10a, "symlinkat", 3, {1, 0, 1, 0, 0, 0}},
    {0x10b, "readlinkat", 4, {0, 1, 1, 0, 0, 0}},
    {0x10c, "fchmodat", 3, {0, 1, 0, 0, 0, 0}},
    {0x10d, "faccessat", 3, {0, 1, 0, 0, 0, 0}},
    {0x10e, "pselect6", 6, {0, 1, 1, 1, 1, 1}},
    {0x10f, "ppoll", 5, {1, 0, 1, 1, 0, 0}},
    {0x110, "unshare", 1, {0, 0, 0, 0, 0, 0}},
    {0x111, "set_robust_list", 2, {1, 0, 0, 0, 0, 0}},
    {0x112, "get_robust_list", 3, {0, 1, 1, 0, 0, 0}},
    {0x113, "splice", 6, {0, 1, 0, 1, 0, 0}},
    {0x114, "tee", 4, {0, 0, 0, 0, 0, 0}},
    {0x115, "sync_file_range", 4, {0, 0, 0, 0, 0, 0}},
    {0x116, "vmsplice", 4, {0, 1, 0, 0, 0, 0}},
    {0x117, "move_pages", 6, {0, 0, 1, 1, 1, 0}},
    {0x118, "utimensat", 4, {0, 1, 1, 0, 0, 0}},
    {0x119, "epoll_pwait", 6, {0, 1, 0, 0, 1, 0}},
    {0x11a, "signalfd", 3, {0, 1, 0, 0, 0, 0}},
    {0x11b, "timerfd_create", 2, {0, 0, 0, 0, 0, 0}},
    {0x11c, "eventfd", 1, {0, 0, 0, 0, 0, 0}},
    {0x11d, "fallocate", 4, {0, 0, 0, 0, 0, 0}},
    {0x11e, "timerfd_settime", 4, {0, 0, 1, 1, 0, 0}},
    {0x11f, "timerfd_gettime", 2, {0, 1, 0, 0, 0, 0}},
    {0x120, "accept4", 4, {0, 1, 1, 0, 0, 0}},
    {0x121, "signalfd4", 4, {0, 1, 0, 0, 0, 0}},
    {0x122, "eventfd2", 2, {0, 0, 0, 0, 0, 0}},
    {0x123, "epoll_create1", 1, {0, 0, 0, 0, 0, 0}},
    {0x124, "dup3", 3, {0, 0, 0, 0, 0, 0}},
    {0x125, "pipe2", 2, {1, 0, 0, 0, 0, 0}},
    {0x126, "inotify_init1", 1, {0, 0, 0, 0, 0, 0}},
    {0x127, "preadv", 5, {0, 1, 0, 0, 0, 0}},
    {0x128, "pwritev", 5, {0, 1, 0, 0, 0, 0}},
    {0x129, "rt_tgsigqueueinfo", 4, {0, 0, 0, 1, 0, 0}},
    {0x12a, "perf_event_open", 5, {1, 0, 0, 0, 0, 0}},
    {0x12b, "recvmmsg", 5, {0, 1, 0, 0, 1, 0}},
    {0x12c, "fanotify_init", 2, {0, 0, 0, 0, 0, 0}},
    {0x12d, "fanotify_mark", 5, {0, 0, 0, 0, 1, 0}},
    {0x12e, "prlimit64", 4, {0, 0, 1, 1, 0, 0}},
    {0x12f, "name_to_handle_at", 5, {0, 1, 1, 1, 0, 0}},
    {0x130, "open_by_handle_at", 3, {0, 1, 0, 0, 0, 0}},
    {0x131, "clock_adjtime", 2, {0, 1, 0, 0, 0, 0}},
    {0x132, "syncfs", 1, {0, 0, 0, 0, 0, 0}},
    {0x133, "sendmmsg", 4, {0, 1, 0, 0, 0, 0}},
    {0x134, "setns", 2, {0, 0, 0, 0, 0, 0}},
    {0x135, "getcpu", 3, {1, 1, 1, 0, 0, 0}},
    {0x136, "process_vm_readv", 6, {0, 1, 0, 1, 0, 0}},
    {0x137, "process_vm_writev", 6, {0, 1, 0, 1, 0, 0}},
    {0x138, "kcmp", 5, {0, 0, 0, 0, 0, 0}},
    {0x139, "finit_module", 3, {0, 1, 0, 0, 0, 0}},
    {0x13a, "sched_setattr", 3, {0, 1, 0, 0, 0, 0}},
    {0x13b, "sched_getattr", 4, {0, 1, 0, 0, 0, 0}},
    {0x13c, "renameat2", 5, {0, 1, 0, 1, 0, 0}},
    {0x13d, "seccomp", 3, {0, 0, 1, 0, 0, 0}},
    {0x13e, "getrandom", 3, {1, 0, 0, 0, 0, 0}},
    {0x13f, "memfd_create", 2, {1, 0, 0, 0, 0, 0}},
    {0x140, "kexec_file_load", 5, {0, 0, 0, 1, 0, 0}},
    {0x141, "bpf", 3, {0, 1, 0, 0, 0, 0}},
    {0x142, "execveat", 5, {0, 1, 1, 1, 0, 0}},
    {0x143, "userfaultfd", 1, {0, 0, 0, 0, 0, 0}},
    {0x144, "membarrier", 2, {0, 0, 0, 0, 0, 0}},
    {0x145, "mlock2", 3, {0, 0, 0, 0, 0, 0}},
    {0x146, "copy_file_range", 6, {0, 1, 0, 1, 0, 0}},
    {0x147, "preadv2", 6, {0, 1, 0, 0, 0, 0}},
    {0x148, "pwritev2", 6, {0, 1, 0, 0, 0, 0}},
    {0x149, "pkey_mprotect", 4, {0, 0, 0, 0, 0, 0}},
    {0x14a, "pkey_alloc", 2, {0, 0, 0, 0, 0, 0}},
    {0x14b, "pkey_free", 1, {0, 0, 0, 0, 0, 0}},
    {0x14c, "statx", 5, {0, 1, 0, 0, 1, 0}},
    {-1, NULL, 0, {0, 0, 0, 0, 0, 0}}
};

long long gettdata(pid_t child, long long addr, char *str, int len) {
    long long word;
    long long read = 0;

    while (read < len) {
        word = ptrace(PTRACE_PEEKDATA, child, addr + read);
        read += LONGSIZ;
        
        if (read > len) {
            memcpy(str, &word, LONGSIZ - (read-len));
            break;
        }
        memcpy(str, &word, LONGSIZ);
        str += LONGSIZ;
    }
    return read;
}

int get_syscall_format_string(int code, char format_string[MAXSYSCALLFORMATLEN], long long regs[6], pid_t child) {
    struct syscall *sc;

    memset(format_string, 0, MAXSYSCALLFORMATLEN);
    for (sc = syscall_table; sc->code >= 0; sc++) {
        if (sc->code == code) {
            strncpy(format_string, sc->name, MAXSYSCALLNAMELEN);
            strcat(format_string, "(");

            int i;
            for (i = 0; i < sc->nargs; i++) {
                char format[40];

                if (sc->dref[i] != 0) {
                    if (sc->code == 1) {
                        format[0] = '"';

                        int len = (regs[2] < 30) 
                                  ? regs[2] 
                                  : 30;

                        gettdata(child, regs[i], format+1, len);
                        format[len+1] = 0;

                        if (len < regs[2])
                            strcat(format, "...\", ");
                        else 
                            strcat(format, "\", ");
                    }
                    else {
                        sprintf(format, "%#llx, ", regs[i]);
                    }
                }
                else {
                    sprintf(format, "%lld, ", regs[i]);
                }
                strcat(format_string, format);
            }
            int len = strlen(format_string);
            if (sc->nargs != 0) len -= 2;

            format_string[len] = ')';
            format_string[len+1] = 0;

            return i;
        }
    }   
    return -1;
}

