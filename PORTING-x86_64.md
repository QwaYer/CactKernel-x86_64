# План работ: x86_64 (CactOS 3.0.0)

Форк от `2.0.0` (i686, no PAE) — точка старта 64-битного поколения. `MAJOR`
меняется на 3 по правилу `ROADMAP.md` («`MAJOR` = architecture generation»):
меняется арх и ABI-эпоха, а не набор фич.

Этот файл — план, а не обещание: этапы упорядочены так, чтобы после каждого
был работающий, проверяемый артефакт. Инвентарь ниже снят по коду, а не по
памяти; при расхождении верить коду.

## Что есть на старте

Репозиторий — снимок 2.0.0 **без git** (`.git` нет).

Тулчейн жёстко 32-битный:

| Место | Сейчас | Нужно |
|---|---|---|
| `cross/i686-cact-clang.ini` | `c_args=['-m32']`, `cpu='i686'` | новый `x86_64-cact-clang.ini` |
| `meson.build` (финальная линковка) | `ld -m elf_i386` | `-m elf_x86_64` |
| `meson.build` (версия) | `+abi.<vermagic>.i686` | `.x86_64` |
| `*.json` (8 шт., спека цели) | `p:32:32`, `target-pointer-width: 32`, `features: -mmx,-sse` | `p:64:64`, `arch: x86_64`, `pre-link-args.ld: ["-m","elf_x86_64"]` |
| `.cargo/config.toml` (8 шт.) | `build.target = i686-cact.json`, `-C target-cpu=pentium4` | `x86_64-cact.json`, `-C target-cpu=x86-64` |
| `tools/cact_rust_build.sh:36` | `cp .../i686-cact/release/$lib` | `.../x86_64-cact/...` |
| `linker.ld` | `. = 1M`, без `OUTPUT_FORMAT` | `OUTPUT_FORMAT(elf64-x86-64)`, higher-half |
| nasm | `-f elf32` (6 `meson.build`, 10 целей) + `objcopy -O elf32-i386` (SMP) | `-f elf64` / `elf64-x86-64` |

PAE/long mode в коде нет — только CPUID-хелперы `cpu_has_pae()`/`CPU_FEATURE_LM`
(`Cact/kernel/cpudev/cpudev.c`). Единственное упоминание 4 ГиБ как жёсткого
предела — `Cact/drivers/pci/msi/msix.c:196-198`.

Хорошая новость: тулчейн-базы хватает уже сейчас. Проверено на этой машине:
`clang 23.1.3` с включённой целью `x86-64` и рабочим `-m64`; `rustc 1.100.0-nightly`
со штатной целью `x86_64-unknown-none` (то есть `build-std` возможен без нового
тулчейна — и 64-битная сборка перестаёт быть кросс-сборкой); `ld` 2.47 с
эмуляцией `elf_x86_64`; `nasm 3.02 -f elf64`; `objcopy` с `elf64-x86-64`.

## Инвентарь 32-битных поверхностей

### Ассемблер — 11 файлов, ≈950 строк, все 32-битные

Переписываются целиком: `Cact/kernel/core/kernel.asm` (Multiboot2 entry, `push ebx/eax`,
`call init`), `exception_stubs.asm` (`pusha`/`iretd`), `device_isrs.asm`,
`msidev_stubs.asm` (192 MSI-заглушки, macro-generated), `syscall_entries.asm`
(`SYSENTER`+`SYSCALL`, 60-байтный кадр руками), `Cact/kernel/gdt/gdt.asm`,
`Cact/kernel/proc/task.asm` (`switch_to`, три трамплина), `Cact/kernel/memory/mm.asm`
(CR0/CR2/CR3), `Cact/kernel/idt/fpu/fpu_entry.asm`, `Cact/kernel/smp/trampoline.asm`
(`[bits 16] org 0x8000` → PM → `jmp [info_entry]`). Порт-ввод/вывод
(`Cact/drivers/input/io.asm`) — почти арх-независим, меняется только способ
доступа к аргументам.

### Дескрипторы и прерывания

- `Cact/kernel/gdt/gdt.h:24-44` — 32-битный TSS (104 байта), тип `0xE9`,
  **IST-массива нет**. Зеркало в Rust: `Cact/kernel/proc/sched/src/smp.rs:87-186`.
- `Cact/kernel/idt/idt.c:29-36` — гейт `flags=0x8E` (32-битный interrupt gate),
  адрес хендлера двумя 16-битными половинами; `IDTR.base` — `uint32_t`.
- Общий кадр контекста: `Cact/kernel/proc/task.h:136-149` (17×u32), зеркала в
  `rust_mm/src/ffi.rs:242-262` и `sched/src/ffi.rs:13`.

### Syscall

- Механизм: `int 0x80` удалён; есть `SYSENTER` (`syscall_entries.asm:32`) и AMD
  `SYSCALL` (`:107`), выбор в `cpudev.c:323-336`, MSR — `cpudev.c:348-388`
  (`SYSENTER_CS/ESP/EIP`; `EFER.SCE`, `STAR`, `FMASK`).
- Соглашение: `EAX`=номер, `EBX`/`ESI`/`EDI` — аргументы; 60-байтный
  `struct syscall_frame` (`syscall/mod.h:6-11`) собран руками.
- Диспетчер `syscall/mod.c` (15 записей в `syscalls.h`, `_needs_frame`) —
  арх-независим, остаётся.
- Трамплин sigreturn — сырой 32-битный машинный код, включая **абсолютный**
  32-битный адрес возврата: `Cact/kernel/proc/sched/src/task_sigreturn.rs:43-85`.

### Память

- Двухуровневый walk захардкожен: `rust_mm/src/vmm/paging.rs:7-16`
  (`page_directory: [u32;1024]`, `PAGE_TABLES: [[u32;1024];1024]`), индексы —
  `ffi.rs:221-226`, маски `& !0xFFF` по всему `vmm/*`.
- PMM: битмап + refcount'ы, `TOTAL_PAGES = 1024*1024` (4 ГиБ), `ffi.rs:65-74`;
  потолок `<4 ГиБ` — `PMM_MAX_ADDR`, `clip_to_limit` (`pmm_math.rs:36`),
  обрезка карты MB2 (`Cact/kernel/core/multiboot2.c:173-178`).
- Физ. адреса = виртуальные (identity), конверсии нет; `read_cr2() -> u32`.
- Константы раскладки: `PCI_HOLE_START 0xC0000000`, `RESERVED_END 0x20000000`,
  `USER_FRAME_CEIL 0x80000000`, `HEAP_START 0x20000000`+16 МиБ,
  `MMAP_BASE/MMAP_LIMIT`, `SHM_VA_*`, `USER_STACK_TOP/LIMIT`, `USER_SPACE_START`
  (`memory/memory.h`, `memory/mmap.h`, `memory/page_fault.h`, `ffi.rs:126-190`).
  Инвариант `USER_FRAME_CEIL` существует именно из-за identity-map: ядро
  трогает кадр через identity-VA, поэтому пользовательская страница не смеет
  встать на тот же адрес.

### Задачи

- `switch_to` (`task.asm:14-30`) сохраняет `ebp/edi/esi/ebx` и `esp`;
  `task_struct` — **48 байт**, все поля 32-битные (`task.h:311-324`,
  `sync/src/task_abi.rs:33-48`).
- Начальные кадры строятся руками: kernel (6 слов), user (10 слов,
  `iret`+`cs 0x1B`/`ss 0x23`), fork (20 слов) — `task_create.rs:60-68,155-166`,
  `task_fork.rs:327-338`, `task_thread.rs:160-171`.
- TLS — через **`%gs`**-дескриптор (`gdt.c:69-71`, `smp.rs:756-778`).
- `ProcMeta`/`ProcShared`: offset-ассерты зафиксированы в
  `sched/src/lib.rs:52+` (например `sigreturn_trampoline == 92`, `tls_base == 676`)
  — в 64 битах все неверны и падают на компиляции.

### SMP

- `Cact/kernel/smp/trampoline.asm` — real mode `org 0x8000`, 2-записный AP-GDT,
  `mov cr3,[info_cr3]`; AP'ы работают на **общем** PD BSP (`smp.rs:440,487-490`).
- Per-CPU GDT/TSS — `smp.rs:281-327`, `install_tss_descriptor` (`:275-286`).
- Векторы IPI `0xF8`/`0xF9` (`cstate.rs:36-37`), LAPIC-таймер `0xFE` — переносимы.

### ABI и модули

- `Cact/kernel/core/syscall/ioctl_abi.h` (963 строки) — весь на `uint32_t`;
  десятки полей-указателей (`cact_getdents_arg.buf`, `cact_thread_create_arg.entry`,
  `cact_epoll_wait_arg.events`, …) меняют размер и выравнивание структур.
  `cact_mq_attr_t` (`:936-942`) явно описывает `long == int32_t` — на x86_64 `long`
  8 байт. `cact_uname_t.machine` берётся из `procfs_std.c:374` (`"i686"`).
- `Cact/drivers/gpu/drm/uapi/drm_types.h`: `__kernel_long/size_t` = 32 бита.
- Три независимых ELF32-лоадера: exec (`elf/elf_loader.c`, требует
  `ELFCLASS32`+`EM_386`), PCI `.cctk` (`drivers/pci/loader/pci_loader.c`),
  ФС `.cctk` (`fs/vfs/fs_mod.c`). Релокации только `R_386_32`/`R_386_PC32`,
  `SHT_REL`, `uint32_t *patch` — GOT/PLT нет вообще.
- Вермиджик (`tools/modsign.py`, `elf/ksym.c:232-267`) — FNV-1a по
  отсортированным **именам** `ksym`, без арх-строки: изменится сам при
  переезде. Арх-строка живёт только в метаданных версии.

## Решения

1. **Арх-поколение:** `VERSION` → `3.0.0`, arch-строка `.x86_64`. Вермиджик не
   трогаем — он пересчитается.
2. **Спека цели:** свой `x86_64-cact.json` в каждом из 8 кратов, а не голый
   `x86_64-unknown-none` — нужен контроль фич и `pre-link-args`.
   `-C target-cpu=pentium4` → `x86-64` (baseline).
3. **Отказ от `-mno-mmx -mno-sse -mno-sse2`.** Флаг ставился ради инварианта
   «ядро не исполняет SSE до создания IDT» (`movsd` в `multiboot2_parse` →
   `#UD` → `#DF`). На x86-64 SysV ABI **требует** SSE2, инвариант несохраним.
   Вместо него: `CR4.OSFXSR|OSXMMEXCPT` включаются в самом раннем asm, до
   первого C-кода; дальше XMM ядру доступны. Это упрощение, а не потеря.
4. **Раскладка VA: higher-half + direct map.** Ядро на `0xFFFFFFFF80000000`,
   вся физическая память — direct map на `0xFFFF800000000000`, пользователь —
   младший канонический диапазон; появляются `p2v()`/`v2p()`.
   `USER_FRAME_CEIL`, `PCI_HOLE_START`, сплит 3G/1G и правило «identity-map
   только как разделяемые таблицы» умирают.
   *Почему не minimal-change (оставить ядро identity-mapped на 1 МиБ):* это
   тянет в адресное пространство каждого процесса отображение всей RAM — ровно
   та проблема, из-за которой появился `USER_FRAME_CEIL`. В 64 битах причин
   сохранять identity-alias нет.
   Бутстрап Фазы 1 — временный identity-map на первые ГиБ; переезд на
   higher-half делаем **до** портирования подсистем, потому что позже это
   дороже.
5. **Syscall: `SYSCALL`/`SYSRET`.** `EFER.SCE`, `LSTAR` (64-битная точка входа),
   `STAR`, `SFMASK`. Вход: `swapgs` + per-CPU kernel RSP (`SYSCALL` стек не
   переключает). `SYSENTER` выкидывается. Номер — в `rax`, аргументы
   `rdi/rsi/rdx`. `%gs` становится per-CPU ядра, TLS пользователя уезжает в
   `%fs` (текущая схема `%gs`-дескриптора несовместима с `swapgs`).
   Таблица 15 трапов и `_needs_frame` не трогаем.
6. **64-битный TSS + IST.** IST сейчас нет вообще; в long mode без отдельного
   стека `#DF` уходит в тройной фолт. IST1 = `#DF`, IST2 = NMI; `RSP0` — для
   прерываний из ring 3.
7. **Модули: ELF64 + `SHT_RELA` + `R_X86_64_*`.** GOT/PLT в лоадерах нет,
   поэтому модули собирать `-mcmodel=kernel -fno-plt -mno-red-zone`: GOT не
   нужен вовсе. Приделывать GOT/PLT к лоадеру — дороже и не нужно.
8. **ABI пользователя — эпохальный разрыв, это и есть повод для MAJOR.** Все
   структуры с указателями и `long` расширяются, `machine` → `"x86_64"`,
   libc/ld.so/ELF'ы перелинковываются в соседних репах.

## Этапы

### Фаза 0 — каркас и тулчейн

Новый `cross/x86_64-cact-clang.ini`; `x86_64-cact.json` ×8 и
`.cargo/config.toml` ×8; `tools/cact_rust_build.sh`; `meson.build`
(`-m elf_x86_64`, arch-строка); `linker.ld` (`OUTPUT_FORMAT`, higher-half);
nasm/objcopy форматы; `git init` (сейчас репозиторий без VCS).

**Milestone:** `ninja` собирает и линкует `kernel.bin`; `readelf -h` даёт
ELF64/`EM_X86_64`. Ядро пока нерабочее — это нормально.

### Фаза 1 — long mode до первой строки в COM1

Новый `kernel.asm`: проверка CPUID.LM → PML4+PDPT+PD на 2 МиБ страницах →
`CR4.PAE`, `CR3`, `EFER.LME|NXE`, `CR0.PG` → загрузка 64-битного GDT → far jump
в 64-битный код. 64-битный TSS + IST. 64-битный IDT и `exception_stubs.asm`
(`iretq`, error-code, слоты 8 байт). COM1. Раннее включение SSE.

**Milestone:** QEMU печатает баннер `3.0.0` на COM1; `#PF`/`#GP` печатают dump
и не уходят в тройной фолт (то есть IST и 64-битные гейты реально работают).

### Фаза 2 — память

PMM: размер из MB2-карты, без потолка 4 ГиБ и без статического массива на 4 ГиБ.
4-уровневый walk во всех `rust_mm/vmm/*` и `fault/*`. `p2v()/v2p()`, новая
раскладка VA, MMIO-окно выше RAM. heap/slab/`kalloc` на `usize`.
`pmm_math.rs` и логика решений `%PF` переносятся почти без изменений.

**Milestone:** `kalloc`/slab работают; demand-zero, COW, clone-адресного-
пространства; страничный фолт и swap-маркеры; host-тесты `pmm_math` зелёные.

### Фаза 3 — задачи, планировщик, syscall

`task.asm`: `switch_to` на callee-saved x86-64 (`rbx/rbp/r12-r15`), три
трамплина и начальные кадры (`iretq`, `ss/rsp/rflags/cs/rip`). Раскладки
`TaskStruct`/`ProcMeta`/`ProcShared` + offset-ассерты. `%fs`-TLS. Syscall-вход
(решение 5) и переписанный `syscall_frame`. Futex, сигналы, `task_sigreturn.rs`
(RIP-relative вместо абсолютных 32-битных адресов).

**Milestone:** bootstrap-задача стартует, MLFQ тикает и переключает контексты,
syscall round-trip из тестовой задачи.

### Фаза 4 — SMP

Новый AP-трамплин: real mode → 4-уровневый бутстрап → long mode, свой PML4 или
разделяемый kernel-часть. Per-CPU GDT/TSS/PML4. IPI-векторы переносятся.

**Milestone:** 4 vCPU в QEMU, `IPI_HALT`/`IPI_WAKEUP`, governor и C-states,
кросс-runqueue балансировка.

### Фаза 5 — драйверы и файловые системы

Механический sweep `u32 → uintptr_t/usize` (десятки мест: `rust_mm`,
`uptru()` в `rust_drm/src/ffi.rs:106`, `fn as *const () as u32` в
`task_create.rs`/`task_fork.rs`/`task_thread.rs`). Затем PCI+MSI/MSI-X, xHCI+HID,
blkdev/partitions/page cache, VFS/`rust_vfs`, tty, video.

**Milestone:** клавиатура и диск в QEMU; VFS монтирует раздел.

### Фаза 6 — userspace, модули, ISO

ELF64-лоадеры (exec, PCI, ФС) на `SHT_RELA`; пересборка libc/ELF'ов в соседних
репах; `cact_sign`/`cact_sign_cctkfs.py`; `grub.cfg`; `run_qemu.sh` →
`qemu-system-x86_64`; расширение `tools/cact_check.sh`.

**Milestone:** `/usr/bin/init` из binfs; `ninja -C build-meson check` зелёный;
`.cctk` грузится и проходит ECDSA + vermagic.

### Фаза 7 — то, ради чего 64 бита

i915 **in-tree**, и до него — 64-бит-гейпы из `ROADMAP.md`: order-N/непрерывный
аллокатор, WC-маппинг как API, загрузчик прошивок, workqueue, ACPI OpRegion/VBT,
GMBUS/DDC + парсер EDID. Порядок в `ROADMAP.md` сохраняется.

## Сквозные потоки

- sweep `u32 → usize/uintptr_t` по всему дереву;
- расширение ABI-структур (`ioctl_abi.h`, `stat`, `statx`, `utsname`, `mq_attr`,
  DRM uapi);
- ELF64 в трёх лоадерах + `elf.h`;
- документация: README и бейджи `i686` → `x86_64`.

## Проверки

- Штатный рантайм-тест — `ninja -C build-meson check` (headless QEMU, грепает
  COM1-маркеры и падает на несоответствии).
- `run_qemu.sh` уже даёт `-accel kvm -cpu host -smp 4 -m 4G`, но запускает
  `qemu-system-i386` — заменить на `qemu-system-x86_64`.
- `tools/cact_check.sh:172` сверяет Python- и C-значения вермиджика; после
  переезда это должно продолжать сходиться.

## Открытые вопросы (проверить до Фазы 1)

- **Как GRUB отдаёт управление x86_64-ядру.** Ожидание: арх-поле Multiboot2
  остаётся `i386`, вход идёт в 32-бит protected mode, long mode поднимает само
  ядро. Сверить со спекой Multiboot2 / GRUB — от этого зависит вся Фаза 1.
- **ACPICA под 64 бита:** `ACPI_MACHINE_WIDTH`, `ACPI_MUTEX_TYPE=0`
  (`Cact/drivers/acpi/meson.build`).
- **`cact_crypto`** (vendored rustls/webpki, force-soft cfgs, `u64_digit`,
  `max-atomic-width`) — что ре-сборка под 64 бита проходит целиком.
- **`-mno-red-zone`** обязателен для всего ядра и модулей (в 64 битах красная
  зона ломает обработчики прерываний).
