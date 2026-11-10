# Приёмка изменений аудита 2026-11-09

Пользователь разрешил проверки на изолированных Linux/FreeBSD/OpenWrt стендах.
Исправления экспортёра статистики и переносимости тестов проверяются поверх
`a61fa20011465d5679654eaf84c90fbca3ec001c`; это локальное дерево, не remote HEAD PR #14.

## Идентичность кандидата

- Архив исходников: SHA256 `da5bfe9b631970146bde80ff87856a4537eee96dc2ade30badc9cc750ce0fd19`.
- После его создания изменены только три test harness: добавлен FreeBSD raw RA
  transport, исправлен поиск bash через PATH и устранён ложный SKIP UDP drain guard. Содержимое `src/`, `mk/`,
  `packaging/`, `container/` сверено с архивом побайтно перед завершением приёмки.
- OpenWrt SDK runner сохраняет собственный ограниченный архив сборочных входов:
  SHA256 `52ffcc08f03dfd5f8002b4a4a8b54056e5512f843c1233aaaee71f9f90c773d4`.
- A/B baseline: `origin/main`, `7acb2fe71f0574fc4f258fe4a5ebb77d160132d1`.
- Полные hashes бинарников, compiler/kernel identity, source manifest, patch,
  команды и журналы находятся в `improvenments/audit-acceptance-20261109/`.
  Исходные диски одноразовых OpenWrt VM оставлены вне репозитория в
  `/tmp/tayga-acceptance-20261109.mNPMBA/`.

## Выполненные проверки

| Стенд / набор | Результат и граница проверки |
|---|---|
| Debian trixie ARM64, GCC 14, WITH_URING=1 | Все 15 C unit PASS, финальный portable 368: OK, без SKIP; первоначальные пропуски benchmark tools устранены и перепроверены |
| Clang, ASan + UBSan | Все C unit PASS, `detect_leaks=1`, `-fno-sanitize-recover=all` |
| Clang, TSan | Все C unit PASS, `halt_on_error=1`, non-PIE build |
| Linux Debian 13 ARM64, kernel 6.12.113 | `test/run-system.py` PASS: negotiation, rollback, burst, NAPI, UDP/TCP offload wire, protocol translation, stats, ICMP, RA, BPF steering/lifecycle |
| Linux io_uring | dispatch=flows lifecycle PASS; groups/flows steering lifecycle PASS; UDP auto/off, workers=3, MTU 1280/1500: все 100 wire cases PASS |
| Linux integrity | Production startup, kernel/groups/flows: `test_correctness.py` и `test_pmtud.py` PASS; установленные бинарник и startup восстановлены |
| FreeBSD 15.1 ARM64, Clang 19 | Все C unit PASS; portable 368: OK, 23 платформенных SKIP (Linux affinity, /proc, preload и UDP APIs) |
| FreeBSD RA supervisor | Реальный epair/raw ICMPv6: renewal, replacement, signals, withdrawal, expiry, snapshot cleanup PASS; порядок NAT66 controller и rollback проверены отдельным fixture controller |
| FreeBSD installer | Реальные SFX install, PF/routes/TUN, rc.d restart, boot recovery, rejected apply/rollback, uninstall PASS |
| FreeBSD rc.d + RA | Реальные daemon(8), production rc.d template с изолированными путями, network controller, PF/TUN и raw RA на epair: renewal без смены PID, replacement, expiry, respawn, stop/cleanup PASS. SIIT readiness fixture; внешний translated HTTP и NAT66 смена firewall этим сценарием не проверяются |
| OpenWrt 24.10.8 / 25.12.6 SDK | Все четыре target-specific IPK/APK пакета собраны, contract/manifest verification PASS; SDK hashes проверены, feed pins не ослаблены |

Сбой первого FreeBSD portable запуска вызван отсутствием git/bash, затем
непереносимым `/bin/bash` в benchmark regression. Зависимости установлены только
в VM, тест теперь ищет bash через PATH. Исправленный набор прошёл полностью с
перечисленными платформенными пропусками.

Один первоначальный параллельный Linux lifecycle запуск отказался брать общий
workflow lock. После завершения владельца оба режима последовательно прошли.
Отказ блокировки не засчитан как успешный прогон.

## OpenWrt VM

Обе реальные VM (24.10.8 IPK и 25.12.6 APK, native ARM64 QEMU/HVF) завершились
с `passed=true`. Пройдены install/start/stop/restart/reload/procd respawn,
WAN down/up и renumber/device handover, reboot и SIGKILL/power-cut recovery,
stateful DHCPv6 IA_NA/IA_PD renewal, renumber и retirement через вторую VM,
managed NAT64/DNS64/SIIT/CLAT с forwarded LAN traffic, readiness rollback,
активное удаление и сохранение чужих LAN/firewall/DHCP настроек.

Это приёмка текущих пакетов без `--upgrade-*`: package version upgrade matrix
в этом проходе не выполнялась. Runtime packages устанавливались offline;
сетевые интерфейсы VM изолированы, SSH доступен только на loopback.
Для 24.10.8 использован ранее сохранённый offline coreutils/timeout; отдельно
скачаны текущие IPK, их SHA256 совпали с пинами CI `89a616aa…` / `d2ed4d22…`.
Data payload совпадает с кэшем, control archive различается. Таким образом,
VM-результат проверяет runtime этого payload, не повторяет установку нового
control archive. Сравнения hashes/contents сохранены в `feed-current/`.

## Фаззинг и производительность

Семь libFuzzer harness (`pkt4`, `pkt6`, `gso`, `pref64`, `conffile`, `flow`,
`maps`) прошли по 60 секунд с ASan/UBSan и leak detection; crashes не найдены.
Перед этим прошёл 30-секундный smoke каждого harness.

Первичная A/B матрица завершена: 35/35 запусков, 70 направленных измерений,
валидные capture/workload, 0 TUN/worker drops/errors, restore hashes совпали.
Performance gate этой матрицы не пройден: default kernel/off — по retransmits/GB,
groups — по throughput и распределению workers, flows — по throughput.
См. [таблицу и методику](../performance/audit-2026-11-09.md).
Дополнительные 5 пар kernel/off с 20-секундным окном: 10/10 запусков,
20 направленных измерений, capture/workload и cleanup PASS. Throughput и
upload retransmits/GB проходят; download retransmits/GB — 10.87 против 6.82
(+59.4%), FAIL. Причина по этим данным не установлена; **B1 остаётся блокером
performance acceptance**, а первая матрица сохранена целиком.

## Решения по архитектуре и выпуску

Synchronous kernel steering остаётся production default. Experimental steering,
dispatch и io_uring сохраняют явный opt-in. SPSC/IOSQE_IO_LINK, полное шардирование
map/cache, передача владения bucket с ageing и массовый `-Wconversion` не входят
в завершение исправлений: для них нужны отдельные дизайн и доказательство пользы.

Удалённые Basic run 42671315894 и Correctness run 42671315714 имеют общий
`failure`, хотя доступные jobs показывают success, а failed-job logs пусты.
Эти результаты относятся к старому remote `a61fa20`; локальная приёмка их не
меняет. Полностью зелёный CI последнего опубликованного дерева, ручной merge,
назначение версии/даты, тег и release остаются отдельными условиями выпуска.
До их выполнения также требуется закрыть описанный выше B1; локальная приёмка
не объявляется полностью зелёной.
