<img src="../../../../../assets/banner.png" style="zoom: 80%;" align=center />

<img src="../../../../../assets/htb.png" style="zoom: 80%;" align='left' /><font size="6">SatelliteHijack</font>

  14<sup>th</sup> 04 24 / Document No. D24.102.58

  Prepared By: clubby789

  Challenge Author: clubby789

  Difficulty: <font color=red>Hard</font>

  Classification: Official




# Synopsis

SatelliteHijack is a Hard reversing challenge. Players will reverse engineer a multi-layered backdoor, starting with an `ifunc` resolver. They will then uncover function hooking via GOT overwrite, decrypt a runtime-decoded code chunk, and discover the flag within the embedded backdoor.

## Skills Required
    - Decompiler use
## Skills Learned
    - `ifunc` internals
    - ELF structure and parsing

# Solution

We are provided a binary (`satellite`) and a library, `library.so`. If we use `ldd` we can see that the binary requires the library in the current directory:
```
$ ldd satellite
    linux-vdso.so.1 (0x00007ffc07302000)
    libc.so.6 => /usr/lib/libc.so.6 (0x00007fd2b78fb000)
    ./library.so (0x00007fd2b78f5000)
    /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fd2b7b40000)
```
If we run the binary, we are prompted for text which is then 'sent':

```
         ,-.
        / \  `.  __..-,O ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈ ≈
       :   \ --''_..-'.'
       |    . .-' `. '.
       :     .     .`.'
        \     `.  /  ..
        \      `.   ' .
          `,       `.   \
         ,|,`.        `-.\
        '.||  ``-...__..-`
         |  |
         |__|
         /||\
        //||\\
       // || \\
    __//__||__\\__
   '--------------' 
| READY TO TRANSMIT |
> foo
Sending `foo`
> bar
Sending `bar`
> 
```

## Binary Analysis
We'll open the binary in a decompiler.

```c
int32_t main(int32_t argc, char** argv, char** envp)
    setbuf(fp: stdin, buf: nullptr)
    puts(str: "....") // satellite banner ASCII art
    send_satellite_message(0, "START")
    char buf[0x400]
    __builtin_memset(s: buf, c: 0, n: 0x400)
    while (true) {
        putchar(c: '>')
        putchar(c: ' ')
        ssize_t n = read(fd: 1, buf: &buf, nbytes: 0x400)
        if (n s< 0) {
            puts(str: "ERROR READING DATA")
        } else {
            if (n s> 0) {
                buf[n - 1] = 0
            }
            printf(format: "Sending `%s`\n", &buf)
            send_satellite_message(0, &buf)
        }
    }
```
We begin by calling `send_satellite_message` - this is not a function in the binary, likely provided by the library.

In a loop, we then read a chunk of input, null terminate it, then pass it to `send_satellite_message` again.

## Library Analysis

```c
void* send_satellite_message()
    char name[0x14]
    name[0].q = 'TBU`QSPE'
    name[8].q = '`FOWJSPO'
    name[0xd].q = 'SPONFOU'
    for (int32_t i = 0; i u<= 0x13; i = i + 1) {
        name[sx.q(i)] = name[sx.q(i)] - 1
    }
    if (getenv(name: &name) != 0) {
        sub_23e3()
    }
    return sub_24db
```

`send_satellite_message` is indeed defined in the library - however, it seems to take no params, does some strange action, and returns another function pointer. If we use `nm -D library.so` to investigate the symbols of the library, we will see why:

```
$ nm -D library.so
[ .. SNIP .. ]
                 U realloc@GLIBC_2.2.5
00000000000025d0 i send_satellite_message
                 U strcat@GLIBC_2.2.5
[ .. SNIP .. ]
```

Checking the [man page](https://linux.die.net/man/1/nm) of `nm`, we can see `i` refers to:

> For ELF format files this indicates that the symbol is an indirect function.

Indirect functions (or 'ifuncs') are documented [here](https://sourceware.org/glibc/wiki/GNU_IFUNC). Essentially, when the dynamic loader wishes to resolve an indirect function, it will call a provided function. This allows libraries to, for example, check if certain CPU features are supported and return a more optimized implementation.

In this case, we first check an environment variable, the name of which is constructed by subtracting 1 from each byte of a static string. We can recover this name:

```python
>>> bytes([x - 1 for x in b"TBU`QSPE`FOWJSPOSPONFOU"])
b'SAT_PROD_ENVIRONRONMENT'
```

If `SAT_PROD_ENVIRONRONMENT` is set, we enter a hidden function.

```c
void* sub_23e3()
    void* rax_4 = sub_21a9(getauxval(type: 3) & 0xfffffffffffff000, "read")
    int64_t s = mmap(addr: nullptr, len: 0x2000, prot: 7, flags: 0x22, fd: 0xffffffff, offset: 0)
    memcpy(s, &data_11a9, _init)
    memfrob(s)
    *rax_4 = s
    return rax_4
```

`getauxval` retrieves a value from the 'auxiliary vector' - a small list of values that the kernel passes to executed programs to help them set up their environment. We can determine that this corresponds to `AT_PHDR` - the location of the program headers of the running executable.

## ELF file structure

The program headers are a list of structures (of type `Elf64_Phdr`) defined within the ELF header. They define the segments that the kernel should create for the program at runtime. By ANDing this value with `& ~0xfff`, we get the start of the memory page that the program headers are within - the base address of the ELF.

```c
void* sub_21a9(struct Elf64_Header* hdr, char* name)
    struct Elf64_ProgramHeader* phdrs = hdr + hdr->program_header_offset
    void* s
    __builtin_memset(s: &s, c: 0, n: 0x18)
    void* var_40_1
    void* var_38_1
    for (int32_t i = 0; i s< zx.d(hdr->program_header_count); i = i + 1) {
        if (phdrs[sx.q(i)].type == PT_DYNAMIC) {
            void* var_30_1 = hdr + phdrs[sx.q(i)].offset
            while (*var_30_1 != 0) {
                if (*var_30_1 == 6) {
                    s = hdr + *(var_30_1 + 8)
                } else if (*var_30_1 == 5) {
                    var_38_1 = hdr + *(var_30_1 + 8)
                } else if (*var_30_1 == 0x17) {
                    var_40_1 = hdr + *(var_30_1 + 8)
                }
                var_30_1 = var_30_1 + 0x10
            }
        }
    }
```

The function begins by iterating over each program header (until the value of `program_header_count`). If it identifies one of type 'PT_DYNAMIC' (which specifies dynamic linking information), we enter the next part.

The value at `hdr + offset` will therefore be an `Elf64_Dyn` structure - we'll change the types accordingly.

```c
        while (dyn->d_tag != DT_NULL) {
            if (dyn->d_tag == DT_SYMTAB) {
                symtab = hdr + dyn->d_val
            } else if (dyn->d_tag == DT_STRTAB) {
                strtab = hdr + dyn->d_val
            } else if (dyn->d_tag == DT_JMPREL) {
                jmprel = hdr + dyn->d_val
            }
            dyn = &dyn[1]
        }
```

We iterate over the dynamic linking structures until we reach `DT_NULL` (the end of the array). We save the value of the `DT_SYMTAB` (offset of the `.dynsym` section), `DT_STRTAB` (offset of the `.dynstr` section) and `DT_JMPREL` (offset of the `.rela.plt` section).

## Symbol Resolution

`.dynsym` contains an array of `Elf64_Sym` structures. Each of these contains an `st_name` field which contains the offset into the `.dynstr` section (a large array of bytes) of the symbol name, while the `.rela.plt` section contains a list of PLT entries.

```c
void* retval
if (symtab == 0 || (symtab != 0 && strtab == 0) || (symtab != 0 && strtab != 0 && jmprel == 0)) {
    retval = nullptr
}
if (symtab != 0 && strtab != 0 && jmprel != 0) {
    int32_t located_sym_idx = 0xffffffff
    int32_t sym_idx = 0
    while (true) {
        if (&symtab[sx.q(sym_idx)] u>= strtab) {
            break
        }
        struct Elf64_Sym* cur_sym = &symtab[sx.q(sym_idx)]
        if (cur_sym->st_name != 0 && strcmp(strtab + zx.q(cur_sym->st_name), name) == 0) {
            located_sym_idx = sym_idx
            break
        }
        sym_idx = sym_idx + 1
    }
    if (located_sym_idx s< 0) {
        retval = nullptr
```

We begin walking the symbol array (after checking that we have resolved all the sections we need). For each one, we locate its name value and compare it against our `name` argument (in this case, the value is `read`).

Once we find the desired symbol, we save its symbol number - if we fail to find it, we'll return null.

```c
    while (true) {
        if (jmprel->r_offset == 0) {
            retval = nullptr
            break
        }
        if (jmprel->r_info u>> 0x20 == sx.q(located_sym_idx)) {
            retval = hdr + jmprel->r_offset
            break
        }
        jmprel = &jmprel[1]
    }
```
Finally, we iterate over our relocations until we find one with `r_offset == 0`, indicating the end of the array. We right-shift the value of `r_info` by 0x20 - this corresponds to the macro `ELF64_R_SYM`; multiple values are packed into the `r_info` field.

The resulting value is the symbol index this relocation corresponds to. If it represents our desired symbol, we return the value of `hdr + r_offset` - which will be a pointer to the GOT entry of our function!

## GOT overwrite

Returning to our earlier function, we can see that this is therefore overwriting the GOT entry for the `read` function, effectively hijacking it.

```c
void* sub_23e3()
    void* rax_4 = sub_21a9(hdr: getauxval(type: 3) & 0xfffffffffffff000, name: "read")
    int64_t s = mmap(addr: nullptr, len: 0x2000, prot: 7, flags: 0x22, fd: 0xffffffff, offset: 0)
    memcpy(s, &data_11a9, 0x1000)
    memfrob(s)
    *rax_4 = s
    return rax_4
```

We copy 4096 bytes of static data into a new page of memory (mapped `PROT_READ|PROT_WRITE|PROT_EXEC`), then call `memfrob` on it. [`memfrob`](https://linux.die.net/man/3/memfrob) simply XORs a region of memory with 42. We'll extract this data and decode it in order to reverse it.

## Reversing injected code

```c
int64_t hooked_read(int32_t fd, char* buf, uint64_t count)
    int64_t amnt = sub_1a4(fd, buf, count)
    int64_t ret = amnt
    if (fd == 1 && amnt s>= 0 && amnt u> 4) {
        void* i = &buf[4]
        do {
            if (*(i - 4) == 'HTB{' && sub_8c(i, &buf[count] - i) != 0) {
                sub_109(buf, 0, amnt)
                ret = -1
                break
            }
            i = i + 1
        } while (i != &buf[amnt])
    }
    return ret
```

`sub_1a4` is a wrapper around a function passing arguments to `syscall` - it is most likely a basic `read` implementation. After this, we check that at least 4 bytes were input and begin iterating over the data. If we find a chunk that reads `HTB{`, we call `sub_8c` on the following data.

If the function returns `true`, we call `sub_109` which appears to be a `memset`, and return an error to the caller.

```c
bool sub_8c(char* data, int64_t max_sz)
    char check[0x1c]
    check[0].q = 0x37593076307b356c
    check[8].q = 0x3a7c3e753f665666
    check[0xd].q = 0x784c7c214f3a7c3e
    check[0x15].q = 0x663b2c6a246f21
    int64_t i = 0
    if (max_sz == 0) {
        return 0
    }
    do {
        if (sx.q(data[i] ^ check[i]) != i) {
            return 0
        }
        i = i + 1
        if (max_sz == i) {
            return 0
        }
    } while (i != 0x1c)
    return 1
```

This sets up a large array of bytes. For each byte of our input, it is XORed against the corresponding constant byte. If the result does not equal the index, we return false.

By extracting this as a string, we can recover the flag:

```python
from pwn import *

buf = bytearray(b"l5{0v0Y7fVf?u>|:O!|Lx!o$j,;f")
print(buf)
print(len(buf))
for i in range(len(buf)):
    buf[i] ^= i

print((b"HTB{" + buf).decode())
```
