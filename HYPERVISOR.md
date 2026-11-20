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

**2026-11-20 — boot-self-test убран, запуск гостя — по требованию.** Ядро
больше не входит в VMX на загрузке: старый `hv_selftest()` делал VMXON +
`VMLAUNCH`, но **не вызывал `VMXOFF`**, поэтому ядро оставалось в VMX-root
(`CR4.VMXE`, живой VMCS, `CR0.NE`) на всю жизнь и на первом ring-3-таске тихо
сбрасывалось — VMX abort по архитектуре не доставляет исключения, отсюда
«triple fault без вывода». Теперь `hv_run_guest()` входит в host mode, запускает
гостя и **всегда выходит обратно**; дёргает его нода **`/dev/chv`**
(`CACT_CHVCTL_CAPS` / `CACT_CHVCTL_RUN`). На этом пути вылез второй баг:
VM-entry отвергал host-state (`vm-instruction error 8`) — ядро оставляет `DS/ES`
с RPL=3 после возврата в ring-3, а VMX валидирует host-селекторы (в IA-32e они
игнорируются, но проверяются). Host-селекторы DS/ES/FS/GS публикуются kernel
data-селектором; базы по-прежнему из снимка.

### Фаза H4 — EPT / NPT

EPT-структуры (PML4/PDPT/PD/PT со своими флагами) и NPT (NCR3 + NPT-таблицы),
identity-карта гостевого физического пространства, EPTP/NCR3 в контексте,
включение nested paging. EPT/NPT-violation как хук MMIO: запись в магический GPA
даёт exit с информацией о доступе.

**Milestone:** гость трогает выделенные ему кадры; обращение по адресу вне карты
даёт EPT/NPT-violation с корректными GPA/правами.

### Фаза H5 — реальный гость

Загрузка образа 64-битного гостевого ядра в память гостя (через EPT/NPT),
построение boot-state как у загрузчика (long mode, GDT/IDT гостя, page tables),
обработка нужных exit-ов (HLT, IO, CPUID, MMIO). Сначала — свой fixture-гость,
затем Linux `bzImage`.

**Milestone:** 64-битный гость грузится под CactOS и доходит до собственной
точки (для Linux — вывод на эмулируемый последовательный порт).

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
- **EPT/NPT и MMIO-окно:** как отображается отсутствующий в EPT диапазон, чтобы
  exit приходил как «MMIO», а не как жёсткая ошибка.
- **Взаимодействие VMX root с существующими MSR-программами** (SYSCALL, APIC,
  PAT): в VMX root operation ограничения VMCS применяются только после VM-entry,
  но `IA32_FEATURE_CONTROL` и `CR4.VMXE` трогают общий контекст ядра.
