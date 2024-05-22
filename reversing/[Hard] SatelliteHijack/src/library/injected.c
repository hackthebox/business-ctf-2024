#include <sys/types.h>
#include <stdarg.h>

ssize_t _start(int fd, char* buf, size_t sz);
static ssize_t read(int fd, void *buf, size_t count);
static unsigned long long syscall(int number, ...);
static int check_flag(char* buf, size_t max_sz);
static void memset(char* buf, char val, size_t sz);
int puts(const char* s);

// hooks the 'read' function
ssize_t _start(int fd, char* buf, size_t sz) {
    ssize_t ret = read(fd, buf, sz);
    if (ret < 0) {
        return ret;
    }
    if (fd != 1) {
        return ret;
    }
    char marker[4] = "HTB{";
    int marker_i = *(int*)&marker;
    for (size_t i = 0; i + 4 < ret; i++) {
        int as_int = *(int*)(buf + i);
        if (marker_i == as_int) {
            if (check_flag(buf + i + 4, sz - i - 4)) {
                memset(buf, 0, ret);
                return -1;
            }
        }
    }
    return ret;
}

/*

>>> flag = "l4y3r5_0n_l4y3r5_0n_l4y3r5!}"
>>> f = bytes([ord(c) ^ i for i, c in enumerate(flag)])
*/

static int check_flag(char* buf, size_t max_sz) {
    char real[] = "l5{0v0Y7fVf?u>|:O!|Lx!o$j,;f";
    for (size_t i = 0; i < max_sz; i++) {
        if (i == sizeof(real) - 1) {
            return 1;
        }
        if ((int)(buf[i] ^ real[i]) != i) {
            return 0;
        }
    }
    return 0;
}

static void memset(char* buf, char val, size_t sz) {
    for (size_t i = 0; i < sz; i++) {
        buf[i] = val;
    }
}

static unsigned long long syscall(int number, ...) {
    unsigned long long ret;
    va_list args;
    va_start(args, number);

    asm volatile(
        "mov %1,  %%eax\n\t"
        "movq %2, %%rdi\n\t"
        "movq %3, %%rsi\n\t"
        "movq %4, %%rdx\n\t"
        "movq %5, %%r10\n\t"
        "movq %6, %%r8\n\t"
        "movq %7, %%r9\n\t"
        "syscall\n\t"
        "movq %%rax, %0\n\t"
        : "=r"(ret)
        : "g"(number), "g"(va_arg(args, unsigned long long)), "g"(va_arg(args, unsigned long long)), "g"(va_arg(args, unsigned long long)), 
          "g"(va_arg(args, unsigned long long)), "g"(va_arg(args, unsigned long long)), "g"(va_arg(args, unsigned long long))
        : "%rax", "%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9", "memory"
    );

    va_end(args);
    return ret;
}

static ssize_t read(int fd, void *buf, size_t count) {
    return syscall(0, fd, buf, count);
}

/*
static ssize_t write(int fd, const void *buf, size_t count) {
    return syscall(1, fd, buf, count);
}

int puts(const char *s) {
    size_t len = 0;
    const char *p = s;
    while (*p != '\0') {
        ++p;
        ++len;
    }
    ssize_t ret = write(1, s, len);
    if (ret < 0) {
        return -1;
    }
    ret = write(1, "\n", 1);
    if (ret < 0) {
        return -1;
    }
    return 0;
}
*/