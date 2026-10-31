#ifndef ELF_H
#define ELF_H

#include <stdint.h>

#define ELF_MAGIC 0x464C457F /* "\x7FELF" */

#define EI_MAG0    0
#define EI_MAG1    1
#define EI_MAG2    2
#define EI_MAG3    3
#define EI_CLASS   4
#define EI_DATA    5
#define EI_VERSION 6
#define EI_PAD     7
#define EI_NIDENT  16

#define ELFCLASSNONE 0
#define ELFCLASS32   1
#define ELFCLASS64   2

#define ELFDATANONE  0
#define ELFDATA2LSB  1
#define ELFDATA2MSB  2

#define EV_NONE    0
#define EV_CURRENT 1

/* e_machine */
#define EM_386     3
#define EM_X86_64  62

/* e_type */
#define ET_NONE    0
#define ET_REL     1
#define ET_EXEC    2
#define ET_DYN     3
#define ET_CORE    4

/* sh_flags */
#define SHF_WRITE     0x1
#define SHF_ALLOC     0x2
#define SHF_EXECINSTR 0x4

/* --- ELF64 ---------------------------------------------------------------
 * The class the x86_64 kernel executes.  Note the field orders differ from
 * ELF32 (p_flags sits right after p_type; st_value/st_size come after the
 * fixed 4-byte symbol prefix) — these layouts are ABI, not a choice. */
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

typedef struct {
    uint8_t    e_ident[16];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off  e_phoff;
    Elf64_Off  e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf64_Word  p_type;
    Elf64_Word  p_flags;
    Elf64_Off   p_offset;
    Elf64_Addr  p_vaddr;
    Elf64_Addr  p_paddr;
    Elf64_Xword p_filesz;
    Elf64_Xword p_memsz;
    Elf64_Xword p_align;
} Elf64_Phdr;

typedef struct {
    Elf64_Word  sh_name;
    Elf64_Word  sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr  sh_addr;
    Elf64_Off   sh_offset;
    Elf64_Xword sh_size;
    Elf64_Word  sh_link;
    Elf64_Word  sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;
} Elf64_Shdr;

typedef struct {
    Elf64_Word  st_name;
    uint8_t     st_info;
    uint8_t     st_other;
    Elf64_Half  st_shndx;
    Elf64_Addr  st_value;
    Elf64_Xword st_size;
} Elf64_Sym;

typedef struct {
    Elf64_Addr  r_offset;
    Elf64_Xword r_info;
    Elf64_Sxword r_addend;
} Elf64_Rela;

#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_SHLIB   5
#define PT_PHDR    6
#define PT_GNU_STACK 0x6474E551

#define SHT_NULL       0
#define SHT_PROGBITS   1
#define SHT_SYMTAB     2
#define SHT_STRTAB     3
#define SHT_RELA       4
#define SHT_DYNAMIC    6
#define SHT_NOBITS     8
#define SHT_REL        9
#define SHT_DYNSYM     11

#define STB_LOCAL   0
#define STB_GLOBAL  1
#define STB_WEAK    2

#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2

#define SHN_UNDEF   0
#define SHN_ABS     0xFFF1

/* x86_64 relocation types (SHT_RELA).  The module loaders link GOT/PLT-free
 * images (a -mcmodel=kernel object), so only the direct relocations such a
 * build emits are handled; unsupported types are rejected. */
#define R_X86_64_NONE    0
#define R_X86_64_64      1   /* S + A             */
#define R_X86_64_PC32    2   /* S + A - P         */
#define R_X86_64_PLT32   4   /* S + A - P (no PLT) */
#define R_X86_64_32      10  /* S + A, zero-extended */
#define R_X86_64_32S     11  /* S + A, sign-extended */

/* The bind/type packing is identical for both classes (st_info is one byte
 * whether or not the rest of the symbol is 32- or 64-bit). */
#define ELF32_ST_BIND(i)    ((i) >> 4)
#define ELF32_ST_TYPE(i)    ((i) & 0xF)
#define ELF32_ST_INFO(b,t)  (((b) << 4) + ((t) & 0xF))
#define ELF64_ST_BIND(i)    ((i) >> 4)
#define ELF64_ST_TYPE(i)    ((i) & 0xF)
#define ELF64_ST_INFO(b,t)  (((b) << 4) + ((t) & 0xF))

/* r_info packing (64-bit: symbol index in the high dword, type in the low). */
#define ELF64_R_SYM(i)      ((uint32_t)((uint64_t)(i) >> 32))
#define ELF64_R_TYPE(i)     ((uint32_t)((uint64_t)(i) & 0xFFFFFFFFu))
#define ELF64_R_INFO(s,t)   ((((uint64_t)(s)) << 32) | ((uint32_t)(t)))

/* True when `eh` is an ELF64 / EM_X86_64 relocatable object — the only shape
 * the `.cctk` module loaders accept. */
static inline int elf64_is_rel_object(const Elf64_Ehdr *eh) {
    return *(const uint32_t *)eh->e_ident == ELF_MAGIC &&
           eh->e_ident[EI_CLASS] == ELFCLASS64 &&
           eh->e_type == ET_REL &&
           eh->e_machine == EM_X86_64;
}

/* Width in bytes of a supported x86_64 relocation, or 0 if unsupported. */
static inline uint32_t elf64_rela_width(uint32_t type) {
    switch (type) {
    case R_X86_64_64:  return 8;
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_32:
    case R_X86_64_32S: return 4;
    default:           return 0;
    }
}

/* Apply one supported SHT_RELA relocation in place.  `patch` is the fixup site
 * (its address is P), `S` the symbol value and `A` the RELA addend. */
static inline void elf64_apply_rela(uint32_t type, uint8_t *patch, uint64_t S, int64_t A) {
    uint64_t P = (uint64_t)(uintptr_t)patch;
    switch (type) {
    case R_X86_64_64:
        *(uint64_t *)patch = S + (uint64_t)A;
        break;
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
        *(int32_t *)patch = (int32_t)(S + (uint64_t)A - P);
        break;
    case R_X86_64_32:
        *(uint32_t *)patch = (uint32_t)(S + (uint64_t)A);
        break;
    case R_X86_64_32S:
        *(int32_t *)patch = (int32_t)(S + (uint64_t)A);
        break;
    }
}

#endif
