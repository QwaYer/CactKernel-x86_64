# План работ: гипервизор в CactOS (хост / VMM)

Цель: CactOS как **хост-гипервизор** — ядро само управляет аппаратной
виртуализацией (**Intel VT-x** и **AMD-V**), запускает гостевые ВМ и отдаёт ими
управление в юзерспейс через `ioctl`-uAPI («KVM-подобный сервис»). Это новый
подсистемный слой ядра, а не драйвер.

Этот файл — план, а не обещание: этапы упорядочены так, чтобы после каждого был
работающий, проверяемый артефакт. Один этап — один коммит (как в
`PORTING-x86_64.md`).

## Что есть на старте

Инвентарь снят по коду (индекс `cactkernel-x86-64-docs`).

| Механизм | Где | Состояние для VMM |
|---|---|---|
| CPUID | `cpudev.c` (`cpuid_raw`), экспорт `cact_cpuid()` | есть; бит `CPU_FEATURE_VMX` детектится, `SVM` — нет (ext ECX не читается) |
| MSR read/write | `static inline` копии в `cpudev.c`, `apic.c`, `gdt.c`, `pat.c` | **только file-local**, общего `cpu_msr.h` нет — вводим |
| CR0/2/3/4 | асм-строки по месту (`mm.asm`, `smp.rs`, `pat.c`) | общего доступа нет — вводим `cpu_cr.h` |
| 4-уровневый VMM | `rust_mm/src/vmm/paging.rs` (`vmm_map`, `vmm_v2p`/`vmm_p2v`, `vmm_create_address_space`) | годится для host-таблиц; **EPT/NPT — свой формат**, этими функциями не выражаются |
| Аллокатор кадров | `kalloc()` (4 КиБ, direct-map VA) + `kmalloc_aligned`; `vmm_v2p()` даёт физический | VMXON/VMCS-регионы и EPT/NPT из него собираются |
| IDT / исключения | `idt.c` (256 векторов, IST `#DF`/NMI), `exception_stubs.asm` | VM-exit/#VM через IDT не идут — это отдельный канал |
| Per-CPU | блок через `%gs`, `percpu_gs_init`, SMP bring-up | VMX operation per-CPU; SVM — host-mode тоже per-CPU |
| PAT / WC | `pat.c` | понадобится для EPT-памятей гостя (WB) |
| Hypervisor-бит | `CPU_FEATURE_HYPERVISOR` (`cpudev.h`), `/proc/cpuinfo` | используем для вложенного режима |

**Нет ничего:** ни `vmxon`/`VMCS`/`vmlaunch`, ни `EPT`/`NPT`, ни
`IA32_FEATURE_CONTROL`/`IA32_VMX_BASIC`, ни входа в VMX root. Подсистема
пишется с нуля.

## Решения

1. **Оба бэкенда сразу, но за абстракцией.** Общее ядро (`Cact/kernel/hypervisor/`)
   держит модель VM/vCPU и не знает про VT-x/SVM; два бэкенда в подпапках
   `vmx/` и `svm/` реализуют операции. Выбор бэкенда — по `CPUID` на раннем
   этапе, позже — параметром uAPI. Общий интерфейс (`hv_vcpu_*`) — единственное,
   что видит остальное ядро и uAPI.
2. **Intel VT-x и AMD-V как равноправные**, а не «сначала один». Каждый бэкенд
   самодостаточен; там, где модели совпадают (exit-reason → действие), диспетчер
   общий.
3. **EPT (Intel) и NPT (AMD) с самого начала, без shadow paging.** Nested
   paging короче выводит к рабочему гостю и не требует ловить смены CR3;
   shadow-путь не пишем.
4. **Без device-emulation на первых этапах.** Пока только VM-exit'ы на:
   `HLT`, `VMCALL`, EPT/NPT-violation (как хук MMIO), `CPUID`, `IO`. Полная
   эмуляция устройств — после того, как гость реально загрузится.
5. **Раскладка файлов** — `Cact/kernel/hypervisor/` (ядро + uAPI),
   `.../vmx/` (VT-x + EPT), `.../svm/` (AMD-V + NPT), `.../uapi/` (ioctl-ABI).
   Общие CPU-примитивы (`cpu_msr.h`, `cpu_cr.h`) — в `Cact/kernel/cpudev/`.
6. **Проверка.** Основной путь — вложенная виртуализация: QEMU с `-cpu host`
   на хосте с включённым nested (`kvm_intel nested=1` / `kvm_amd nested=1`)
   отдаёт VMX/SVM гостю-CactOS. Где nested недоступен — тест идёт на
   `-accel tcg -cpu max` (TCG умеет и VMX, и SVM). Маркеры этапов печатаются на
   COM1 и грепаются `tools/cact_check.sh`.
7. **Языки.** Низкоуровневые примитивы (asm-обёртки инструкций VMX/SVM,
   доступ к MSR/CR, регионы VMXON/VMCB, таблицы EPT/NPT) — на **C/asm**. Модель
   VM/vCPU, диспетчер exit-ов и uAPI — на **Rust** отдельным крейтом, как
   `sched`/`rust_mm`/`rust_drm`. То есть H1–H2 (и низкоуровневая часть H3–H4)
   на C, а логика уезжает в Rust.

## Этапы

### Фаза H1 — возможности CPU и общий CPU-слой

Общий `cpu_msr.h` (`cpu_rdmsr`/`cpu_wrmsr`) и `cpu_cr.h` (доступ к CR0/2/3/4).
Детект: `IA32_FEATURE_CONTROL`, `IA32_VMX_BASIC` (revision + размер региона),
`CPUID.40000000h` (кто нас宿主ит, для вложенного режима), бит `SVM`
(`CPUID.80000001h:ECX[2]`), SVM-features (`CPUID.8000000Ah`: NPT, ASID count),
`VM_CR`/`EFER.SVME`. Всё — только чтение, без входа в режим.

**Milestone:** на COM1 строки `hv: vmx present (VMCS rev …, region … B, …)` и/или
`hv: svm present (npt=…, asid=…, …)`; при отсутствии расширения — явное
`hv: no hardware virtualization extension`. Ядро грузится дальше без изменений.

### Фаза H2 — вход в режим хоста (VMX root / SVM host), per-CPU

VMXON/VMXOFF-регионы, `VMREAD`/`VMWRITE`/`VMCLEAR`/`VMPTRLD`; для SVM —
VMCB (`VMSAVE`/`VMLOAD`, `CLGI`/`STGI`), host-mode enable (`EFER.SVME`,
`VM_HSAVE_PA`). Включение/выключение на каждом ядре.

**Milestone:** вход/выход в режим хоста на BSP и AP; после выхода система
продолжает работать (SMP, syscalls, сеть — без регрессий). Boot самопроверку не
запускает: host mode входит по требованию (см. H3, `/dev/chv`).

### Фаза H3 — минимальный гость и VM-exit

VMCS/VMCB: host-state, guest-state (минимальный 64-битный контекст), контролы
(pin/proc/exit/entry; Intel — VM-execution controls, AMD — intercept-битмапы).
`VMLAUNCH`, рукописный крошечный гость, обработчик exit-ов (`HLT`, `CPUID`,
`IO`).

**Milestone:** гость исполняется и его `HLT` трапится хостом:
`hv: guest ran, exit reason …`.

**Сделано (Intel, 2026-11-04):** 64-битный гость (`mov eax,0xdeadbeef; hlt`),
identity-карта кодовой страницы 4-уровневыми таблицами, `VMLAUNCH` без EPT;
`HLT` даёт VM-exit 12. По пути выяснилось, что
(1) **гостевой CR4 обязан нести все биты `CR4_FIXED0`** — а туда входит
`CR4.VMXE` (иначе `VM entry failure due to invalid guest state`, reason 33);
(2) **`HLT` не выходит в хост без контрола `HLT exiting`** (proc-based бит 7) —
иначе гость просто останавливает логический процессор.
Два бага в C/asm пойманы тем же прогоном: `vmread`/`vmwrite` — порядок
операндов AT&T (`vmwrite value, field`) и ширина приёмника `setcc` (байт, не
`int`).

### Фаза H4 — EPT / NPT

EPT-структуры (PML4/PDPT/PD/PT со своими флагами) и NPT (NCR3 + NPT-таблицы),
identity-карта гостевого физического пространства, EPTP/NCR3 в контексте,
включение nested paging. EPT/NPT-violation как хук MMIO: запись в магический GPA
даёт exit с информацией о доступе.

**Milestone:** гость трогает выделенные ему кадры; обращение по адресу вне карты
даёт EPT/NPT-violation с корректными GPA/правами.

**Сделано (Intel, 2026-11-20):** EPT построен примитивами на C —
`Cact/kernel/hypervisor/vmx/ept.{c,h}`: детект (`IA32_VMX_PROCBASED_CTLS2` +
`IA32_VMX_EPT_VPID_CAP`: нужны EPT, WB-память и INVEPT single-context),
`vmx_ept_build()` (4-уровневая иерархия PML4/PDPT/PD/PT со своими битами
R/W/X, страницы из `kalloc` + `vmm_v2p`, EPTP = физ. PML4 | walk-len<<3 |
WB), `vmx_ept_free()` и `vmx_ept_invept_single()` (INVEPT type 1 — обязателен:
переводы тегируются EPTP, а `kalloc` может вернуть тот же физический PML4, то
есть тот же EPTP, следующему запуску). Модель (Rust) строит карту и пишет EPTP.

Карта гостя **не identity**: каждая GPA (0x1000…0x6000 — таблицы гостя, код,
данные) называет свой host-кадр, так что адрес X у гостя — это вовсе не
host-физический X. Гость считает, что его CR3 указывает на GPA 0x1000, а на
самом деле EPT переводит это в кадр ядра. Гостевой программы теперь две записи:
в маппленную GPA (хост затем читает магию обратно **из host-кадра** — это и есть
доказательство трансляции) и в `GPA_TRAP` = 0x9000, которую гостевые таблицы
описывают, а EPT — нет.

**Проверено (KVM, nested, headless).** `/dev/chv` `RUN` → exit reason 0x30
(EPT violation), GPA = 0x9000, guest-linear = 0x402000, qualification с битом
записи; и строка `EPT translation OK — mapped-GPA store reached the host frame`
(магия дошла до host-кадра, которого гость не называл). Обычная загрузка без
регрессий: ACPI, SMP online, init запускается.

**Грабли, которые стоят записи.** `EPT_POINTER` — это VMCS-поле **0x201A**, а не
0x2018: 0x2018 — `VM_FUNCTION_CONTROL`, тоже валидное 64-битное поле, поэтому
VMWRITE «удавался», а реальный EPT pointer оставался нулём, и `VMLAUNCH` падал с
vm-instruction error 7 («invalid control field(s)») — аппаратура проверяет EPTP
как control-поле и отвергает нулевой. Ещё одно: сообщения модели в консоль
попадали только после того, как их подняли до `KERN_NOTICE` — с запуском
userspace-init ядро поднимает порог консоли до NOTICE, и INFO-строки уезжают
только в `/dev/kmsg`, то есть в headless-лог не попадают (маркеры фаз должны
печататься не ниже NOTICE).


### Фаза H5 — реальный гость

Загрузка образа 64-битного гостевого ядра в память гостя (через EPT/NPT),
построение boot-state как у загрузчика (long mode, GDT/IDT гостя, page tables),
обработка нужных exit-ов (HLT, IO, CPUID, MMIO). Сначала — свой fixture-гость,
затем Linux `bzImage`.

**Milestone:** 64-битный гость грузится под CactOS и доходит до собственной
точки (для Linux — вывод на эмулируемый последовательный порт).

**Сделано (Intel, 2026-11-23) — H5.1: замкнутый exit-путь, I/O и CPUID,
эмулируемый COM1.** VM-exit-стаб больше не «доигрывает» первую остановку: он
отдаёт управление модели и, если та вернула 1, восстанавливает (возможно,
поправленный) кадр GPR и входит в гостя через `VMRESUME` — один `VMLAUNCH`
прогоняет весь запуск (`vmx/vmx_launch.c`). Модель (Rust) обрабатывает `CPUID`
(reason 10, pass-through: результаты хостового CPUID пишутся назад в
RAX/RBX/RCX/RDX) и `I/O` (reason 30; qualification несёт порт/направление/
размер): `OUT 0x3F8` релеится в хостовый `serial_putc`, `IN` LSR отдаёт
«transmitter ready». Fixture-гость печатает строку в COM1, делает CPUID, кладёт
магию по маппленной GPA, затем по `GPA_TRAP` — тот самый EPT-violation, но
теперь он хук и пропускается (MMIO-образ из открытого вопроса H4) — и
завершается `hlt`. Включены `CPUID exiting` и `unconditional I/O exiting` (без
I/O-битмапов); счётчики io/cpuid и последний EPT-violation печатаются на COM1.

**Грабля.** `mov dx, imm16` — это `66 BA iw`; эмиссия голого `BA iw` — уже
`mov edx, imm32`, она съедает 2 байта следующей инструкции (первый байт строки
гостя) и оставляет первый `out` со «старым» AL. Порт берётся 32-битным
`mov edx, 0x3F8`.

**Проверено (KVM, nested, headless).** Временный запуск гостя на загрузке:
COM1 несёт `[guest] hello over emulated COM1`, затем `guest ran, VM-exit reason
0xc`, `I/O exits 0x24`, `CPUID exits 1`, `EPT translation OK`, EPT violation
0x9000 (skipped as MMIO), `hlt -> exit 12`. Обычная загрузка без запуска гостя
доходит до шелла — без регрессий.

**Сделано (Intel, 2026-11-24) — H5.2: старт в 16-битном real mode (unrestricted
guest).** Включён secondary-контроль `UNRESTRICTED_GUEST` (bit 7; требует EPT) —
без него CPU не даёт гостю `CR0.PG=0`. Режим запуска модель выбирает по `CR0.PG`:
`PG=1` — прежний 64-битный фикстур, `PG=0` — 16-битный real-mode гость. Для
real-mode модель владеет всем состоянием: плоские 16-битные сегменты (base 0,
limit 0xFFFF, AR `0x009B`/`0x0093`), `EFER.LMA` сброшен, VM-entry без IA-32e
контроля, а RIP/RSP указывают прямо в EPT-мапленные GPA (0x5000/0xB800 <
0x10000) — пейджинга нет, линейный адрес и есть guest-physical. Отдельный
16-битный фикстур печатает строку в эмулируемый COM1, кладёт 16-битную магию
через маппленный GPA (доказательство EPT уже в real mode) и трогает `GPA_TRAP`
(тот же MMIO-хук), затем `hlt`.

**Проверено (KVM, nested, headless).** COM1 несёт `[guest] real mode,
unrestricted guest`; модель — `guest launched in 16-bit real mode (unrestricted
guest)`, `EPT translation OK — real-mode mapped-GPA store reached the host
frame`, EPT violation 0x9000, `hlt -> exit 12`. Обычная загрузка — без
регрессий.

### Фаза H6 — паритет бэкендов

Доведение обоих бэкендов до одного множества сценариев; общий диспетчер exit-ов
без `#ifdef` в логике VM.

**Milestone:** один и тот же гость проходит H3–H5 и на VT-x, и на AMD-V.

### Фаза H7 — uAPI для юзерспейса

`ioctl`-ABI (`Cact/kernel/hypervisor/uapi/`): create/destroy VM, create vCPU,
set/get regs, memory regions (mmap в гостя), run (с возвратом exit-reason),
inject interrupt. Файловые узлы `/dev/vmm`/`/dev/vmm<N>`; загрузка гостевого
образа юзерспейсом. Начало положено: нода **`/dev/chv`**
(`CACT_CHVCTL_CAPS`/`RUN`, `Cact/kernel/hypervisor/chv.c`) уже в дереве;
per-VM-узлы `/dev/vmm<N>` — следующий шаг.

**Milestone:** userspace-программа создаёт ВМ, загружает гостя, делает `run` и
обрабатывает exit-ы (полный цикл без участия ядра-инициатора).

**Сделано (Intel, 2026-11-23) — H7.1: vCPU-стейт и uAPI регистров/MSR/прерывания.**
Модель держит один живой `Vcpu` (GPR, RIP/RFLAGS, сегменты/CR/DR, набор MSR);
`RUN` сеет из него VMCS, а по выходу складывает состояние обратно. На `/dev/chv`
добавлены ioctl `GET/SET_REGS` (GPR+RIP/RFLAGS, KVM-раскладка), `GET/SET_SREGS`,
`GET/SET_MSRS` (индекс → значение; EFER/FS_BASE/GS_BASE доходят до гостя) и
`INJECT_IRQ` (внешнее прерывание через VM-entry interruption-information). Дефолт
`Vcpu` воспроизводит fixture, так что RUN без SET — как раньше; GPR грузятся перед
`VMLAUNCH` новым asm-примитивом `cact_vmx_launch_regs`. ABI продублирован в
зеркала `CactLibc`/`CactPkg` (`ioctl_abi.h`). Fixture обзавёлся GDT/IDT/стеком:
инжектированный вектор попадает в обработчик (`I`), остальные паркуются (`P`).

**Две грабли.** (1) exit-стаб на завершении не восстанавливал хостовые
rbx/rbp/r12–r15 — теперь гость стартует с наших GPR, и отчёт падал на `[r15]`;
стаб кладёт callee-saved обратно (launch их сохраняет). (2) Доставка прерывания
грузит CS **из GDT**, а у гостя его не было (GDTR 0/0) → #GP→#DF→triple fault;
понадобилась настоящая GDT (плюс IDT-лимит 0xFFF, а не 0xFF).

**Проверено (KVM, nested, headless).** Временный boot-хук: дефолтный RUN — как
раньше; `SET_REGS{rip=hlt, rflags=0x402}` → `RUN` завершается сразу HLT, `GET_REGS`
отдаёт заданное; `SET_MSRS{STAR}` и `SET_SREGS{cr2}` читаются назад; `INJECT_IRQ(0x80)`
→ COM1 несёт `I` (обработчик), exit HLT. Обычная загрузка без запуска гостя
доходит до шелла — без регрессий.

**Сделано (Intel, 2026-11-24) — H7.2: инжекция через interrupt-window exiting.**
`INJECT_IRQ` больше не форсирует `RFLAGS.IF` в госте: если вектор есть, а `IF=0`,
модель взводит primary-контроль `INTR_WINDOW_EXITING` (bit 2) и оставляет `IF`
как есть. CPU выходит (reason 7) в первый момент, когда гость готов принять
прерывание (после STI и его «тени»); обработчик снимает бит окна и кладёт вектор
в VM-entry interruption-information, а stub делает `VMRESUME` — вектор
доставляется. Если `IF` уже 1, вектор уходит на входе, как раньше. Фикстур
обзавёлся `sti; nop; nop` перед `hlt` (окно открывается после STI-тени), так что
`INJECT_IRQ(0x80)` по-прежнему даёт `I` на COM1.

**Проверено (KVM, nested, headless).** `INJECT_IRQ(0x80)` + RUN с дефолтным
гостем (`IF=0`): `interrupt-window exit — guest ready, injecting vector 0x…80`,
`I` на COM1, `interrupt-window exits 0x1`, финальный exit HLT. Обычная загрузка —
без регрессий.

**Сделано (Intel, 2026-11-24) — H7.3: слоты памяти (`MAP/UNMAP_MEMORY`).**
Гостевая память приходит из юзерспейса: ioctl `CACT_CHVCTL_MAP_MEMORY` принимает
`cact_chv_memory_t` `{slot, flags, gpa, hva, size}` — буфер `hva` (QEMU-подобный
mmap гостевой RAM/ROM), который кладётся в гостевое физическое `[gpa, gpa+size)`.
Ядро обходит таблицы страниц вызывающего процесса (`current_task->page_directory`),
материализует ленивые demand-страницы (свежий `mmap` их не заселяет), берёт доп.
ссылку на каждый фрейм (`vmm_pin_range`) и на следующем `RUN` пишет его hpa в EPT
по адресу gpa (по одному листу на страницу). `UNMAP_MEMORY` снимает пин и удаляет
слот. Слоты не могут перекрывать собственные страницы модели (`GPA 0x1000..0xD000`)
и друг друга; всего ≤8 слотов, ≤256 страниц (1 МиБ).

Низкоуровневый слой (`rust_mm`): `vmm_pin_range`/`vmm_unpin_frames` — обход
`pte_get` + page-in и `page_ref_inc`; **swap-aware пиннинг** — `swap_evict_page`
теперь пропускает фреймы с refcount > 1 (пин или COW-шаринг), иначе swap вынес бы
фрейм, который гость ещё маппит. `cact_chv_memory_t` продублирован в `CactLibc`.

**Проверено (KVM, nested, headless).** Временный boot-хук: `vmm_map_demand` двух
пользовательских страниц → `MAP_MEMORY` (`rc=0`) → `RUN` → строка
`hv: guest memory slots mapped, pages 0x2` (2 листа слота в EPT) → `UNMAP` (`rc=0`).
Дефолтный гость отработал как раньше (EPT translation OK, `hlt -> 12`); обычная
загрузка доходит до шелла — без регрессий. Полный гостевой заход в страницу слота
(доказательство трансляции именно пользовательского фрейма) требует
юзерспейс-клиента (`/dev/chv` + `mmap`) — следующий шаг.

## Сквозные потоки

- общий `hv_*` интерфейс не протекает бэкенд-спецификой в uAPI: поля exit-ов
  нормализуются (одинаковый `enum hv_exit_reason` для VT-x и SVM);
- per-CPU состояние режима хоста (`vmxon`-регион / VMCB) живёт рядом с
  per-CPU-блоком планировщика;
- EPT/NPT-карты строятся теми же аллокаторами кадров (`kalloc` + `vmm_v2p`),
  но своими таблицами;
- мост к `drivers/quirks`: обходы «этот гипервизор врёт про CPUID X» — строкой в
  `quirk_blacklist[]`, не в коде бэкенда.

## Проверки

- Штатный рантайм-тест — `ninja -C build-meson check` (headless QEMU, грепает
  COM1-маркеры). Для проверки именно гипервизорных этапов ISO задавать явно.
- Вложенный режим: `qemu-system-x86_64 -accel kvm -cpu host` при
  `nested=1` на хосте; иначе `-accel tcg -cpu max`.
- После каждого этапа — убедиться, что обычная загрузка (H1: без входа в режим)
  не регрессировала: SMP online, syscall round-trip, VFS монтируется.

## Открытые вопросы

- **Вложенный доступ на целевой машине.** Отдаёт ли тестовый хост VMX/SVM
  гостю-CactOS (`nested=1`), или проверка пойдёт только на TCG.
- **AMD-V 64-битный host-state** в VMCB: какие поля обязательны для long-mode
  гостя/хоста (сверить с AMD APM, как `PORTING-x86_64.md` сверялся со спекой).
- **EPT/NPT и MMIO-окно:** отсутствующий в EPT диапазон уже приходит как
  `EPT violation` (exit 48) с корректными GPA/правами и guest-linear адресом
  (H4); осталось решить, как из этого сделать «MMIO»-хук — то есть эмулировать
  доступ к устройству по этому exit, а не просто логировать его.
- **Взаимодействие VMX root с существующими MSR-программами** (SYSCALL, APIC,
  PAT): в VMX root operation ограничения VMCS применяются только после VM-entry,
  но `IA32_FEATURE_CONTROL` и `CR4.VMXE` трогают общий контекст ядра.
