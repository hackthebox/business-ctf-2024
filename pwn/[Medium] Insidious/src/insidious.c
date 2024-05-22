#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/syscall.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>

scmp_filter_ctx ctx;
unsigned long shellcode_addr = 0;

#define CTF_UID 1000

void setup() {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    srand(time(NULL));
}

void banner() {
    puts("⠀⠀⠀⠀⠀⢀⡠⠔⠂⠉⠉⠉⠉⠐⠦⡀⠀⠀⠀⠀⠀⠀");
    puts("⠀⠀⠀⢀⠔⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡄⠀⠀⠀⠀⠀");
    puts("⠀⠀⢠⠋⠀⠀⠀⠀⠖⠉⢳⠀⠀⢀⠔⢢⠸⠀⠀⠀⠀⠀");
    puts("⠀⢠⠃⠀⠀⠀⠀⢸⠀⢀⠎⠀⠀⢸⠀⡸⠀⡇⠀⠀⠀⠀  _____           _     _ _                 ");
    puts("⠀⡜⠀⠀⠀⠀⠀⠀⠉⠁⠾⠭⠕⠀⠉⠀⢸⠀⢠⢼⣱⠀ |_   _|         (_)   | (_)                ");
    puts("⠀⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡌⠀⠈⠉⠁⠀   | |  _ __  ___ _  __| |_  ___  _   _ ___  ");
    puts("⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⣖⡏⡇   | | | '_ \\/ __| |/ _` | |/ _ \\| | | / __|");
    puts("⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢄⠀⠀⠈⠀  _| |_| | | \\__ \\ | (_| | | (_) | |_| \\__ \\");
    puts("⢸⠀⢣⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡬⠇⠀⠀⠀ |_____|_| |_|___/_|\\__,_|_|\\___/ \\__,_|___/");
    puts("⠀⡄⠘⠒⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢣⠀⠀⠀⠀");
    puts("⠀⢇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡀⠀⠀⠀");
    puts("⠀⠘⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡤⠁⠀⠀⠀");
    puts("⠀⠀⠘⠦⣀⠀⢀⡠⣆⣀⣠⠼⢀⡀⠴⠄⠚⠀⠀⠀⠀");
    puts("");

    puts("Fleeing a haunting dimension, a desperate family seeks your guidance. To navigate the ");
    puts("supernatural obstacles and ensure their safe escape.");
}

unsigned int create_passcode(){
    for (int i=0 ; i<7 ; i++){rand();}
    unsigned int passcode = rand();
    for(unsigned int x=(unsigned int)rand() % 100;x>0;x--){
        passcode <<= 5;
        passcode ^=  15;
        passcode >>= 7;
        passcode ^=  500;
        passcode *=  27;
    }
    return passcode;
}

void drop_privs(){
    assert(setuid(CTF_UID) == 0);   // just a precaution even tho busybox will drop privs by default
}

void shell(){
    char* argv[] = {
        "/bin/sh",
        NULL,
    };
    execve( argv[0], argv, NULL);
}

void load_flag(){
    void *address = NULL;
    void *allocation = NULL;
    int fd;

    // random bytes for address of the allocation
    fd = open("/dev/urandom", O_RDONLY);
    read(fd,&address, 3);
    read(fd,&shellcode_addr,4);
    close(fd);

    // page aligned
    address = (void *)((unsigned long)address << 16);

    // create a hidden allocation for the flag
    allocation = mmap(address, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    assert(allocation == address);

    ctx = seccomp_init(SCMP_ACT_KILL);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,SCMP_A1_64(SCMP_CMP_EQ,(unsigned long)allocation)) == 0);

    // read the flag to the allocation
    fd = open("./flag.txt", 0);
    assert(fd>0);
    assert(read(fd, allocation, 50)>0);
    assert(close(fd)==0);

    // clear all references to the allocation
    // munmap(allocation, 0x1000); this also clear the flag inside the allocation, not viable
    allocation = NULL;
    address = NULL;

}

int main(int argc, char** argv) {
    int passcode;
    void *shellcode;

    setup();
    banner();

    printf("Will you confront the spectral trials head-on, or retreat from the daunting path ahead? [y/n]");
    char c = getchar();

    switch (c){
        case 'y':
        case 'Y':
            load_flag();
            drop_privs();
            break;
        case 'n':
        case 'N':
            puts("Welcome to practice mode, where you can sharpen your abilities");
            puts("and master the art of navigating supernatural realms");
            drop_privs();
            shell();
            exit(EXIT_SUCCESS);
            break;
        default:
            puts("Wrong input");
            exit(EXIT_FAILURE);
    }

    printf("Can you share the crucial passcode that will unlock the mysterious realm's exit? ");
    scanf("%u%*c",&passcode);
    if (passcode != create_passcode()){
        puts("Wrong pass code");
        exit(EXIT_FAILURE);
    }

    // shellcode allocation
    shellcode = (void *)mmap((void*)(shellcode_addr<<12), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
    assert (shellcode != (void *)-1);

    printf("Can you share the detailed 80-step guide for a systematic path to the exit? ");
    assert(read(STDIN_FILENO, shellcode, 80)>0);

    // seccomp load
    assert(seccomp_load(ctx)==0);
    seccomp_release(ctx);

    // remove everything related to the ctx on the heap
    for (int i = 0; i < 0x1000; i++){
        ((char *)ctx)[i] = 0;
    }

    // clear everything
    asm (
        "mov rbx, 0\n"
        "mov rcx, 0\n"
        "mov rdx, 0\n"
        "mov rdi, 0\n"
        "mov rsi, 0\n"
        "mov r8,  0\n"
        "mov r9,  0\n"
        "mov r10, 0\n"
        "mov r11, 0\n"
        "mov r12, 0\n"
        "mov r13, 0\n"
        "mov r14, 0\n"
        "mov r15, 0\n"
        "mov rbp, 0\n"
        "mov rsp, %0\n"
        "add rsp, 0x500\n"
        "wrfsbase rbx\n" // try to clear FS register
        "jmp rax\n"
        : "=r" (shellcode)          // Output operand
        : "r" (shellcode)           // Input operand (zero-initialized ebx)
        :                           // Clobbered registers
    );

    return 0;
}

