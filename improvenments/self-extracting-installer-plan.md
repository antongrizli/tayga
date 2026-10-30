# План реализации: Универсальный Self-Extracting Shell-инсталлятор TAYGA (`tayga-installer.sh`)

> **Основание:** Анализ сессии развертывания в Google Cloud (`3383050c-f170-4a9a-acff-18d5f0cb7229`) и текущего релизного конвейера [`.github/workflows/release.yml`](../.github/workflows/release.yml).


## Статус реализации (2026-10-29)

Реализованы SFX с проверкой payload, установка бинарников с сохранением прежних
файлов, генератор CLAT/NAT64/SIIT, RFC 7050, интерактивный мастер, установка и
переключение CLAT/NAT64 на systemd/OpenRC/FreeBSD rc.d, readiness и откат,
управление/удаление, iptables, native nftables и FreeBSD pf (anchors). Полный путь
CLAT → NAT64 → IPv4 HTTP/ICMP проверен в изолированном Linux-контейнере на обоих
firewall backend. Файловые транзакции, мастер и операции init проверяются portable-тестами
с подставными init-командами; реальные boot/reboot/power-cut тесты выполнены в отдельных
Debian 13/systemd, Alpine 3.23/OpenRC и FreeBSD 15.1 arm64 VM.

Поддержка FreeBSD полностью реализована и протестирована:
- Сетевой контроллер (`tayga-net-ctl.sh`): интерфейсы `tun64`, sysctl (`net.inet.ip.forwarding`,
  `net.inet6.ip6.forwarding`, `net.inet6.ip6.accept_rtadv`), авто-солиситация SLAAC через `rtsol`,
  маршрутизация `route -n get/add`.
- Межсетевой экран `pf`: загрузка правил в якоря `tayga_sfx/*`, TCP MSS clamp через `scrub`,
  NAT44 и stateful фильтрация со строгим порядком секций PF (scrub → nat → pass).
- Управление сервисом `rc.d`: скрипты `/usr/local/etc/rc.d/tayga-managed` и раннего восстановления
  `/usr/local/etc/rc.d/tayga-recovery`, переменные в `/etc/rc.conf.d/tayga_managed` и
  `/etc/rc.conf.d/tayga_recovery`, корректная очистка и восстановление пользовательских файлов.
- Верификация и откат: проверены readiness (`tayga-verify`), перезапуск сервиса,
  автоматический откат на предыдущий рабочий профиль при сбое применения кандидата
  и двухстадийное полное удаление.
- В реальной VM FreeBSD 15.1 arm64 (Lima) успешно пройдены системные тесты:
  `test/system/installer-freebsd-binary-smoke.sh` и `test/system/installer-freebsd-smoke.sh`.

Ограничение ранней фазы копирования файлов (Шаг 4 плана) закрыто:
- В `$tx/files.sh` сохраняется неизменяемая копия скрипта файловых транзакций.
- `tayga-boot-recover.sh` при старте системы обнаруживает висящую директорию `$tx`
  при отсутствии активной транзакции профиля и выполняет автоматический откат файлов.
- `install-header.sh` перед началом новой распаковки проверяет наличие прерванной
  транзакции и очищает её, предотвращая повреждение файлов.

CI и релизный конвейер:
- В `.github/workflows/basic.yml` шаги FreeBSD VM дополнены запуском системного теста
  `installer-freebsd-smoke.sh`.
- В `scripts/ci/release_artifacts.py` и `bench/tests/test_release_pipeline.py` верифицирована
  сборка и хэширование пяти отдельных SFX (`tayga-installer-linux-{amd64,arm64,armv7}.sh`,
  `tayga-installer-freebsd-{amd64,arm64}.sh`), а также универсального `tayga-installer-universal.sh`.
- Все 232 переносимых теста (`test/portable/run_portable.py`) успешно проходят.

Интеграция с `firewalld` и межсетевыми экранами:
- В `packaging/installer/configure.sh` и `tayga-net-ctl.sh` добавлена поддержка бэкенда `firewalld`.
- При `firewall=auto` наличие запущенного демона `firewalld` определяется через `firewall-cmd --state`.
- Для интерфейса TAYGA настраивается принадлежность зоне `trusted` (`firewall-cmd --zone=trusted --add-interface=$dev`).
- TCP MSS Clamping настраивается через direct-правила mangle (`FORWARD` и `OUTPUT` для CLAT).
- В режиме NAT64 маскарадинг динамического пула применяется через точечные rich rules на внешней зоне (`firewall-cmd --zone=$wan_zone --add-rich-rule="rule family='ipv4' source address='$pool' masquerade"`).
- Межсетевой транзит настраивается через direct filter FORWARD правила, обеспечивая совместимость с любыми политиками межзонной маршрутизации firewalld.
- Все рантайм-изменения firewalld обратимы и регистрируются в журнале отката `$journal` без засорения персистентных файлов конфигурации.

Параллельный опрос RFC 7050 и публичных NAT64 по RTT:
- В `src/helpers/pref64-discover.c` реализована параллельная отправка DNS-запросов к списку известных публичных шлюзов через неблокирующие сокеты и `poll()`.
- Выбирается шлюз с минимальным временем отклика (RTT), префикс извлекается математически точно по RFC 7050.
- Добавлены флаги `-p` / `--public`, `-v` / `--verbose`, `--json`. В `configure.sh` поддержаны `--pref64=auto` и `--pref64=public`.

Pre-flight проверки облачных окружений и вывод верификации:
- В `wizard.sh` добавлены проверки Cloud Metadata (`169.254.169.254` для GCP/AWS) и наличия внешнего IPv4; предлагаются интеллектуальные рекомендации режима CLAT на IPv6-only инстансах.
- Автоматически выводится адрес клиента вида `<prefix>::464` из глобального IPv6 интерфейса uplink.
- В `tayga-verify.sh` и `install-header.sh` сформирован итоговый протокол верификации:
  `[PASS] TUN Interface & Routes active`, `[PASS] Outbound TCP/HTTPv4 connectivity`, `[PASS] Routing isolation verified`, `=== TAYGA <profile> active and verified ===`.

Добавлены явные DNS-политики `public-resolvconf` и `public-file`:
отдельная запись resolvconf и постоянная резервная копия обычного resolv.conf,
защита пользовательских правок и восстановление после потери runtime-маркера.
Новые ветки проверены portable-тестами и нативным тестом Debian 13: DNS-запросы
из приложений, openresolv, защита пользовательских правок, восстановление файла
после потери runtime-маркера и сохранение посторонней resolver-записи.

Добавлен `public-nm`: временные DNS-настройки активного управляемого CLAT
через NetworkManager с checkpoint только этого устройства и привязкой к D-Bus
owner демона. В Debian VM проверены назначение/восстановление DNS на TUN и
неизменность IPv4-маршрутов; ошибка назначения покрыта portable-тестом.

Остаются:
автоматическое выделение IPv6 и расширение Proxy NDP/NAT66 на FreeBSD/pf и
firewalld; подпись/публикация пакетов APK/DEB/RPM, live package upgrade и OpenWrt.

Реализован явный архитектурный fallback: `--fallback=build` из встроенных
проверяемых payload-исходников или `--fallback=download` с HTTPS URL и двумя
заранее заданными SHA-256. До файловых изменений проверяются версия TAYGA и
RFC 7050 helper. Native source build/stage/uninstall проверены в Linux arm64
и FreeBSD arm64; download-контракт проверен offline fault-injection тестами.
Добавлены идентификаторы Linux armv6/riscv64/ppc64le/s390x; нативная CI-матрица
этих дополнительных CPU и публикация готовых бинарников остаются отдельной работой.

Linux CLAT: добавлены явные `--clat-address-mode=routed|proxy-ndp|nat66` и
`--nat66-address`. Proxy NDP использует только переданные дополнительные адреса
(при разрешении upstream); NAT66 использует ULA и уже назначенный uplink `/128`.
Оба режима проверяются HTTP/ICMP/1 МиБ и очисткой на iptables/nftables в реальной
Linux VM. Автоматическая выдача дополнительных адресов провайдером не реализована.

Добавлена активация SIIT на Linux: двусторонние HTTP/ICMP, сохранение IPv4
источника без NAT44 и передача 1 МиБ проверены на iptables и nftables. Реализованы
опциональный Unbound DNS64 sidecar и public DNS для CLAT через принадлежащий
профилю link systemd-resolved. Новые DNS-операции прошли portable-тесты;
сквозной DNS64/Unbound-тест выполнен: RFC 7050, DNS-resolved HTTP через NAT64,
побайтовая проверка 1 МиБ и остановка принадлежащего профилю DNS-listener прошли.
Реальный systemd-resolved в Debian 13 проверен: DNS на отдельном link, запрос и scoped cleanup прошли. Live DNSSEC проверен: подписанный ответ принят, некорректная подпись отклонена; конфиг перенесён в принадлежащий установщику каталог /etc/unbound, доступный профилю Debian AppArmor. DNSSEC validation — default;
валидирующий конфиг прошёл unbound-checkconf, а unsigned offline DNS-стенд
выбирает `off` явно и не меняет production default.


В реализации намеренно не используется `2001:db8::/…` как рабочий адрес и не
угадывается префикс NAT64 по адресу DNS64. Адреса CLAT должны быть явно назначены
и маршрутизированы на хост. `armv6l` не считается совместимым с ARMv7 бинарником.

---

## 1. Общая концепция и формат релизного пакета

В качестве дополнительного артефакта релиза создается **самораспаковывающийся POSIX-совместимый shell-скрипт (SFX bundle)**, содержащий внутри себя:
- Статически скомпилированный бинарник [`tayga`](../src/tayga.c)
- Вспомогательную утилиту RFC 7050 [`pref64-discover`](../src/helpers/pref64-discover.c)
- Man-страницы (`tayga.8`, `tayga.conf.5`)
- Шаблоны сервисов (`systemd`, `OpenRC`, `FreeBSD rc.d`) и скрипты управления сетью (`tayga-net-up`, `tayga-net-down`, `tayga-ctl`)

### Варианты упаковки в релизе (GitHub Releases)

Предлагается генерировать **два типа SFX-скриптов** в [`scripts/ci/release_artifacts.py`](../scripts/ci/release_artifacts.py):

1. **Пер-архитектурные самодостаточные бандлы (100% offline, ~200–250 КБ каждый):**
   - `tayga-installer-linux-amd64.sh`
   - `tayga-installer-linux-arm64.sh`
   - `tayga-installer-linux-armv7.sh`
   - `tayga-installer-freebsd-amd64.sh`
   - `tayga-installer-freebsd-arm64.sh`
2. **Единый мульти-платформенный Fat-бандл (`tayga-installer-universal.sh`, ~850 КБ):**
   - Вмещает сжатый `tar.gz` payload со статическими бинарниками `tayga` и `pref64-discover` для всех поддерживаемых ОС и архитектур (`linux/amd64`, `linux/arm64`, `linux/armv7`, `freebsd/amd64`, `freebsd/arm64`).
   - При запуске скрипт определяет `uname -s` и `uname -m`, автоматически извлекает ровно тот бинарник, который соответствует текущей платформе, и проверяет его контрольную сумму SHA-256.
   - Если в будущем добавляется архитектура (например, `riscv64`, `ppc64le`, `s390x`) или пользователь запускает скрипт на редкой платформе, которой нет в payload, инсталлятор предлагает fallback: скачать бинарник из GitHub Releases или собрать из исходников на месте.

### Структура самораспаковывающегося скрипта (SFX)

```text
+-------------------------------------------------------------------+
| #!/bin/sh                                                         |
| # TAYGA Self-Extracting Installer (v0.9.x)                        |
| 1. Парсинг CLI-флагов (--mode, --non-interactive, --uninstall...) |
| 2. Определение ОС (Debian/Ubuntu, RHEL/CentOS, Alpine, FreeBSD)   |
|    и архитектуры CPU (amd64, arm64, armv7)                        |
| 3. Интерактивный мастер (TUI/CLI prompts с дефолтами по Enter)    |
| 4. Извлечение встроенного payload после маркера __PAYLOAD_BEGINS__|
|    (через base64 -d | tar -xzf - и верификацию SHA256)            |
| 5. Генерация конфига, сетевых хуков, настройка sysctl и firewall  |
| 6. Регистрация в systemd / OpenRC / FreeBSD rc.d и запуск         |
| 7. Post-install самодиагностика (ping/pref64/DNS/MTU check)       |
| exit 0                                                            |
+-------------------------------------------------------------------+
| __PAYLOAD_BEGINS__                                                |
| <Base64-encoded tar.gz с бинарниками tayga, pref64-discover, man> |
+-------------------------------------------------------------------+
```

> **Почему `base64` поверх `tar.gz`?**
> Чистый бинарный хвост может повреждаться при копировании или скачивании через текстовые пайпы, прокси или `curl | sh`. Кодирование в `base64` делает файл 100% текстовым, безопасным для передачи любым способом, а размер увеличивается всего на ~70 КБ (при размере сжатого `tayga` ~110 КБ).

---

## 2. Режимы работы и интерактивное меню (с параметрами по умолчанию)

При запуске без флагов (`sudo ./tayga-installer.sh`) скрипт сканирует сетевую среду хоста (интерфейсы, наличие внешнего/внутреннего IPv4, IPv6 GUA, облачные метаданные GCP/AWS/Hetzner) и выводит интерактивное меню с **умными значениями по умолчанию** (достаточно нажать `Enter` на каждом шаге, либо запустить с флагом `-y` / `--defaults`).

### Выбор режима работы (`MODE`)

Инсталлятор предлагает **5 режимов**:

| № | Режим | Описание | Когда рекомендуется (автовыбор дефолта) |
| :- | :--- | :--- | :--- |
| **1** | **`clat`** *(Customer-Side Translator, RFC 6877)* | Дает IPv6-only машине полноценный выход в IPv4-интернет через вышестоящий NAT64-шлюз (свой MikroTik, корпоративный NAT64 или публичный `nat64.net`). | **По умолчанию**, если на хосте обнаружен глобальный IPv6, но отсутствует внешний IPv4 (например, IPv6-only VM в Google Cloud). |
| **2** | **`nat64`** *(Server-Side Stateful NAT64, RFC 6146)* | Превращает сервер с внешним IPv4 и IPv6 в шлюз NAT64 (+ опциональный DNS64 Unbound) для других IPv6-only машин или сетей. | **По умолчанию**, если на хосте есть и глобальный IPv6, и рабочий выход в IPv4-интернет (Dual-Stack). |
| **3** | **`siit`** *(Stateless IP/ICMP Translation, RFC 7915)* | Статическая трансляция 1:1 или префикс-в-префикс без состояния (Border Router / Data Center Edge Relay) по таблицам `map`. | Для дата-центров и выделенных IPv4/IPv6 пулов. |
| **4** | **`binary-only`** *(Только установка бинарников)* | Устанавливает `tayga`, `pref64-discover`, man-страницы и шаблон юнита без изменения сетевых настроек и маршрутов. | Для ручной конфигурации или CI/CD образов. |
| **5** | **`diagnose` / `uninstall` / `reconfigure`** | Диагностика существующей установки, смена режима (с безопасной очисткой стейта) или полное удаление с откатом сетевых правил. | Если инсталлятор обнаружил уже установленный `tayga`. |

---

### Параметры и значения по умолчанию для режима `1) CLAT (464XLAT)`

Если пользователь выбирает `clat` (или просто жмет `Enter` на IPv6-only VM), предлагаются следующие параметры с автоопределением:

1. **Внешний интерфейс (`UPLINK_IF`):**
   - *Default:* Автоопределение по `ip -6 route show default` (напр., `ens4` в GCP, `eth0` на VPS, `vtnet0` на FreeBSD).
2. **Вышестоящий NAT64-префикс (`PREF64`) и источник:**
   - Подменю выбора источника NAT64:
     - `[1] Auto-discover via RFC 7050 (ipv4only.arpa)` — опрос через встроенный `pref64-discover` (если в сети оператора/VPC уже есть DNS64).
     - `[2] Public NAT64 Gateway (nat64.net — Europe/Global)` — автоматический пинг-тест доступных узлов (`2a00:1098:2c::1` London, `2a01:4f8:c2c:123f::1` Nuremberg, `2a01:4f9:c010:3f02::1` Helsinki, `2a00:1098:2b::1` Amsterdam), выбор узла с минимальным RTT и **автоматическое извлечение его реального префикса через `pref64-discover`** (например, `2a00:1098:2c:0:0:5::/96` вместо ошибочного угадывания `/96` от адреса DNS!).
     - `[3] Custom / Self-Hosted NAT64 (например, свой MikroTik или VPS)` — ввод своего префикса (дефолт: `64:ff9b::/96`) и при необходимости маршрута до шлюза.
   - *Default:* Если RFC 7050 на текущем системном DNS не вернул префикс — автоматически выбирается самый быстрый живой узел из списка или `64:ff9b::/96`.
3. **IPv6-адрес клиента CLAT (`CLAT_IPV6`) и адрес самого демона (`TAYGA_IPV6`):**
   - *Default:* Вычисляются автоматически из глобального префикса интерфейса (например, в GCP из выделенного `/96` берется `<prefix>::464` для клиента и `<prefix>::2` для демона TAYGA). Если на интерфейсе только одиночный `/128` без маршрутизируемой подсети — предлагается режим Proxy NDP или ULA `fd64::/64` с NAT66.
4. **Локальные IPv4-адреса DS-Lite (RFC 6877):**
   - *Default:* `192.0.0.1` (адрес на интерфейсе `clat` для хоста) и `192.0.0.2` (`ipv4-addr` самого демона TAYGA).
5. **MTU и Offload (`OFFLINK_MTU`, `TUN_OFFLOAD`):**
   - *Default:* `offlink-mtu 1400` (или `UPLINK_MTU - 60`, в GCP `1460 -> 1400`), **`tun-offload auto`** по умолчанию (на Linux автоматически согласует максимальный поддерживаемый ядром режим — UDP/TCP GSO/GRO с автоматическим фоллбэком; на FreeBSD автоматически переходит в `off`) + автоматическое правило **TCP MSS Clamping**.
6. **Настройка DNS (`/etc/resolv.conf`):**
   - *Default:* После поднятия CLAT хост имеет полноценный IPv4-стек, поэтому предлагается прописать чистые публичные DNS (`8.8.8.8`, `1.1.1.1`, `2001:4860:4860::8888`) без зависимости от стороннего DNS64, плюс опция защиты от перезаписи DHCP-клиентом.

---

### Параметры и значения по умолчанию для режима `2) NAT64 (Server-Side)`

1. **Внешний интерфейс (`WAN_IF`):**
   - *Default:* Автоопределение по `ip -4 route show default`.
   - **Pre-flight проверка:** Скрипт проверяет наличие реального выхода в IPv4 (включая проверку Cloud Metadata в GCP/AWS на наличие External IPv4). Если внешнего IPv4 нет и `ping -c 1 -W 2 8.8.8.8` не проходит — скрипт сразу предупреждает пользователя: *"На этой машине нет выхода в IPv4-интернет. Режим NAT64 требует наличия IPv4. Вероятно, вам нужен режим CLAT!"*
2. **Префикс трансляции (`PREF64`):**
   - *Default:* `64:ff9b::/96` (Well-Known Prefix, RFC 6052).
3. **Динамический пул IPv4 (`DYNAMIC_POOL`) и адрес TAYGA (`TAYGA_IPV4`):**
   - *Default:* `192.168.240.0/20` (4093 клиента) и `192.168.240.1`.
4. **Внутренний IPv6-адрес интерфейса `nat64`:**
   - *Default:* `2001:db8:64::1/64` или `fc64::1/64` (назначается на сам интерфейс `nat64`, чтобы локальные утилиты на самом сервере не использовали link-local `fe80::`, который TAYGA дропает по RFC).
5. **Автонастройка Stateful NAT44 (MASQUERADE) и Forwarding:**
   - *Default:* `yes` (автоматически включает IPv4/IPv6 forwarding и добавляет правило `MASQUERADE` для `192.168.240.0/20` и `FORWARD ACCEPT` в `nftables`/`iptables`/`firewalld`/`pf`).
6. **Установка и настройка локального DNS64 (`Unbound`):**
   - *Default:* `no` (или `yes`, если пользователь хочет сразу поднять DNS64-резолвер с валидацией DNSSEC и `edns-buffer-size: 1232`).

---

## 3. Уроки из истории чата Google Cloud (`3383050c-f170-4a9a-acff-18d5f0cb7229`) — что обязательно встраивается в скрипт и код

В ходе реальной настройки TAYGA на VM в Google Cloud мы столкнулись с **9 практическими проблемами**. Все они должны быть решены автоматически внутри инсталлятора (и частично в коде C):

| № | Проблема из чата в Google Cloud | Как мы её решаем в инсталляторе и коде |
| :- | :--- | :--- |
| **1** | **Баг `SIGSEGV` при переключении NAT64 -> CLAT:** При наличии старого `/var/lib/tayga/dynamic.map` запуск в режиме CLAT (где `gcfg.dynamic_pool == NULL`) вызывал падение демона в `load_dynamic()` ([`src/dynamic.c`](../src/dynamic.c#L198)). | **Двойная защита:**<br>1. **В C-коде (`src/tayga.c` и `src/dynamic.c`):** вызывать `load_dynamic()` только если `gcfg.dynamic_pool != NULL`, и добавить проверку `if (!pool) return;` в начале `load_dynamic()`.<br>2. **В инсталляторе:** изолировать `StateDirectory` / `data-dir` по профилям (`/var/lib/tayga/nat64` vs `/var/lib/tayga/clat`) и очищать неактуальный `dynamic.map` при смене режима. |
| **2** | **Потеря SSH-сессии при добавлении `default` маршрута в CLAT:** В Google Cloud SSH (включая IAP/Cloud Console SSH) идет по внутреннему IPv4 (`10.128.0.x`, `35.235.240.0/20`), а метаданные живут на `169.254.169.254`. Замена `default` маршрута на `dev clat` без сохранения локальных маршрутов мгновенно рвет активную SSH-сессию. | Инсталлятор перед установкой маршрутов `0.0.0.0/1` и `128.0.0.0/1` в `clat`:<br>1. Определяет текущий IPv4-шлюз (`GW4`, напр. `10.128.0.1 dev ens4`).<br>2. Явно закрепляет через `GW4` маршруты к RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Cloud Metadata (`169.254.169.254/32`), Google IAP (`35.235.240.0/20`) и **текущему IP клиента из `$SSH_CONNECTION` (`/32`)**! |
| **3** | **Предупреждение `TUNSETOFFLOAD failed: flags=0x67` и MTU/MSS:** На ядрах без поддержки `TUN_F_USO` (`0x67`) `tun-offload auto` штатно выводит информационный warning и автоматически переключается на TCP-оффлоад (`0x07`), а реальная причина зависания `curl` в чате была не в оффлоаде, а в неверном префиксе NAT64 (`2a00:1098:2c::/96` вместо `2a00:1098:2c:0:0:5::/96`). | По умолчанию во всех режимах (`clat`, `nat64`, `siit`) ставится **`tun-offload auto`** для сохранения максимальной производительности (GSO/GRO). Инсталлятор поясняет штатный характер fallback-сообщения `0x67 -> 0x07`, выставляет оптимальный MTU (`1400` для GCP) и добавляет правило **TCP MSS Clamping** (`--clamp-mss-to-pmtu`). |
| **4** | **Неверный префикс NAT64 при ручном угадывании (`2a00:1098:2c::/96` вместо `2a00:1098:2c:0:0:5::/96`):** У публичных шлюзов (`nat64.net`) адрес DNS64 (`2a00:1098:2c::1`) отличается от префикса NAT64 (`2a00:1098:2c:0:0:5::/96`). Из-за этого ICMP пинговался (отвечал сам DNS-сервер), а TCP-трафик к `1.1.1.1` уходил в черную дыру. | Инсталлятор использует встроенный бинарник **`pref64-discover -s <dns64_ip>`**, который отправляет RFC 7050 запрос `AAAA ipv4only.arpa` напрямую к выбранному DNS64-серверу и математически точно извлекает настоящий префикс трансляции (например, `2a00:1098:2c:0:0:5::/96`). |
| **5** | **Исчезновение IPv6 default route после включения `forwarding=1`:** В Linux при включении `net.ipv6.conf.all.forwarding=1` ядро перестает принимать Router Advertisements (`accept_ra=1` игнорируется при `forwarding=1`), и через ~70 секунд (когда истекает `expires` у `proto ra` маршрута в GCP) IPv6-связь на VM полностью отваливается! | Инсталлятор **в обязательном порядке** перед включением `forwarding=1` выставляет `net.ipv6.conf.all.accept_ra=2` и `net.ipv6.conf.<uplink_if>.accept_ra=2` как в рантайме, так и в `/etc/sysctl.d/99-tayga.conf`. |
| **6** | **Путаница между NAT64 и CLAT на IPv6-only VM:** Пользователь изначально пытался запустить режим `nat64` на VM без внешнего IPv4 (`access-configs/0/external-ip` пуст), из-за чего пакеты транслировались в `10.128.0.5`, но GCP их дропал. | Инсталлятор на старте опрашивает сетевые интерфейсы и Cloud Metadata (`169.254.169.254`). Если внешнего IPv4 нет — он явно сообщает об этом и рекомендует режим **CLAT (`1`)** как дефолтный. |
| **7** | **Блокировка транзитных пакетов в `iptables FORWARD` и Link-Local source IPv6 в режиме NAT64:** При пинге `64:ff9b::8.8.8.8` с самого NAT64-хоста Linux выбирал `fe80::` (который TAYGA дропает), либо обратные пакеты резались цепочкой `FORWARD` (особенно если установлен Docker/UFW/firewalld). | В режиме **NAT64** инсталлятор автоматически:<br>1. Вешает на интерфейс `nat64` валидный глобальный/ULA адрес источника.<br>2. Прописывает правила `FORWARD` между `nat64` и `WAN_IF` (`RELATED,ESTABLISHED` + `MASQUERADE`). |
| **8** | **Слетевшие маршруты после перезагрузки VM:** Обычный systemd-юнит запускал только демон `tayga`, но не создавал `--mktun` и не поднимал `ip addr` / `ip route`. | Инсталлятор генерирует вспомогательный скрипт `/usr/local/libexec/tayga/tayga-net-ctl.sh` (`up` / `down`), который вызывается из `ExecStartPre` / `ExecStartPost` / `ExecStopPost` (в systemd), `start_pre` / `stop_post` (в OpenRC) и `start_cmd` / `stop_postcmd` (во FreeBSD `rc.d`). |
| **9** | **Зависимость от стороннего DNS64 в `/etc/resolv.conf` в режиме CLAT:** Сначала в `/etc/resolv.conf` прописывался `nat64.net`, хотя при работающем CLAT хост может ходить к обычным `8.8.8.8` / `1.1.1.1` напрямую через туннель `clat`. | Инсталлятор после запуска CLAT настраивает стандартные DNS (`8.8.8.8`, `1.1.1.1`, `2001:4860:4860::8888`) через `resolvconf` / `systemd-resolved` / `NetworkManager` или `/etc/resolv.conf` и проверяет резолвинг. |

---

## 4. Совместимость с ОС и архитектурами

### 4.1. Матрица поддерживаемых операционных систем

| Семейство ОС | Поддерживаемые версии | Init-система | Сетевой стек в скрипте | Менеджер файрвола |
| :--- | :--- | :--- | :--- | :--- |
| **Ubuntu / Debian** | Ubuntu 20.04, 22.04, 24.04+; Debian 11, 12, 13+ | `systemd` | `iproute2` (`ip`), `/etc/sysctl.d/` | `nftables` / `iptables` / `ufw` |
| **RHEL / CentOS / Rocky / Alma / Fedora** | RHEL/CentOS 8, 9, 10; Fedora 39+ | `systemd` (+ учет SELinux контекстов `restorecon`) | `iproute2` (`ip`), `/etc/sysctl.d/` | `firewalld` / `nftables` / `iptables` |
| **Alpine Linux / Gentoo / Devuan** | Alpine 3.18+ | `OpenRC` (`/etc/init.d/tayga`) | `iproute2` (`ip`), `/etc/sysctl.d/` | `nftables` / `iptables` |
| **FreeBSD** *(вкл. OPNsense / pfSense)* | FreeBSD 13.x, 14.x, 15.x | `rc.d` (`/usr/local/etc/rc.d/tayga` + `/etc/rc.conf.d/tayga`) | `ifconfig`, `route`, `sysctl` | `pf` (`/etc/pf.conf`) / `ipfw` |

#### Особенности реализации для FreeBSD в скрипте:
- В [`src/tun.c`](../src/tun.c#L948-L954) на FreeBSD `--mktun` требует имя интерфейса вида `tun[0-9]+` (например, `tun64` или `tun0`), либо открывает `/dev/tun` и переименовывает его через `SIOCSIFNAME` при работе демона. Инсталлятор учтет это: на FreeBSD по умолчанию используется `tun64` (или создается `ifconfig tun create name clat`).
- На FreeBSD `tun-offload` автоматически выставляется в `off` (так как `TUNSETOFFLOAD` специфичен для Linux).
- Команды маршрутизации абстрагируются в функции `net_link_up()`, `net_addr_add()`, `net_route_add()`:
  - **Linux:** `ip link set dev ...`, `ip -4 addr replace ...`, `ip -6 route replace ...`
  - **FreeBSD:** `ifconfig <dev> inet 192.0.0.1 192.0.0.2 mtu 1400 up`, `route -6 add -host <v6_client> -interface <dev>`, `sysctl net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1`.

### 4.2. Матрица поддерживаемых архитектур CPU

Нормализация `uname -m` в инсталляторе:
- `x86_64`, `amd64` ➔ **`amd64`** (Linux & FreeBSD)
- `aarch64`, `arm64` ➔ **`arm64`** (Linux & FreeBSD)
- `armv7l`, `armv7`, `armhf`, `armv6l` ➔ **`armv7`** (Linux)
- Опциональное расширение в CI (`docker buildx` / cross-gcc): `riscv64`, `ppc64le`, `s390x` (в `Makefile` уже есть таргет `taygabe` для `s390x-linux-gnu-gcc`).

---

## 5. Что еще важно добавить (дополнительные возможности)

Помимо перечисленных вами пунктов, в промышленный инсталлятор стоит заложить следующие функции:

1. **Неинтерактивный режим (Cloud-Init / Startup Scripts / Ansible / Terraform):**
   - Поддержка запуска одной строкой при создании VM в Google Cloud (в поле *Automation -> Startup script*):
     ```bash
     curl -fsSL https://github.com/antongrizli/tayga/releases/latest/download/tayga-installer-universal.sh | \
       sudo sh -s -- --mode=clat --yes
     ```
   - Полная поддержка CLI-аргументов и переменных окружения:
     - `--mode=clat|nat64|siit|binary-only`
     - `--pref64=auto|<prefix/96>`
     - `--dns64-server=<ipv6>`
     - `--pool4=192.168.240.0/20`
     - `--mtu=1400`
     - `--workers=auto|<N>`
     - `--offload=off|tcp|udp|auto`
     - `-y` / `--yes` / `--non-interactive` (принять все автоопределенные значения по умолчанию без вопросов).

2. **Утилита управления после установки (`tayga-ctl`):**
   - Инсталлятор устанавливает компактный CLI-хелпер `/usr/local/sbin/tayga-ctl`:
     - `tayga-ctl status` — показывает режим, статус демона, текущие маршруты, префикс NAT64 и мгновенно снимает статистику пакетов через `SIGUSR2` (выводит `IPv4 RX/TX`, `IPv6 RX/TX`, `Drops`).
     - `tayga-ctl test` — проверяет сквозную связность (`ping6` до префикса, `ping 1.1.1.1`, `curl -4 https://icanhazip.com`, DNS резолвинг).
     - `tayga-ctl reconfigure` — перезапускает интерактивный мастер для смены префикса или переключения `clat <-> nat64`.
     - `tayga-ctl uninstall` — останавливает сервис, удаляет интерфейс `clat`/`nat64`, восстанавливает исходные маршруты, удаляет правила `sysctl`/`iptables` и бинарники.

3. **Автоматический Rollback (Dead-Man's Switch / Защита от потери доступа):**
   - При применении маршрутов в режиме CLAT скрипт сначала сохраняет дамп старой таблицы маршрутизации в `/run/tayga-backup-routes.sh`.
   - Если после старта демона тестовый пинг/проверка не проходит или интерфейс не поднялся, скрипт автоматически откатывает маршруты назад.

4. **Встроенный самотест после установки (Post-Install Verification):**
   - Сразу после запуска сервиса инсталлятор выполняет 4 автоматических теста и выводит красивую сводную таблицу:
     - `[PASS] TUN Interface & Routes active`
     - `[PASS] ICMPv4 via CLAT/NAT64 (1.1.1.1 reachable, RTT: 98ms)`
     - `[PASS] TCP/HTTPv4 Handshake & MSS Check (http://1.1.1.1 -> HTTP 301)`
     - `[PASS] Outbound Public IPv4 Address: 46.235.230.124`

---

## 6. Архитектура файлов и изменения в репозитории

Для реализации пакета будут созданы/обновлены следующие файлы:

```text
tayga-clat-perf/
├── src/
│   ├── tayga.c                         # [FIX] Защита от вызова load_dynamic() при gcfg.dynamic_pool == NULL
│   └── dynamic.c                       # [FIX] Проверка if (!pool) return; в load_dynamic() (устранение SIGSEGV)
├── packaging/
│   ├── installer/
│   │   ├── install-header.sh           # Основной POSIX-скрипт инсталлятора (TUI/CLI, OS/Arch detect, GCP/Linux/FreeBSD setup)
│   │   ├── tayga-net-ctl.sh            # Скрипт поднятия/очистки интерфейсов, маршрутов, MSS clamping и firewall (Linux & FreeBSD)
│   │   ├── tayga-ctl.sh                # Утилита управления: status (SIGUSR2), test, reconfigure, uninstall
│   │   └── freebsd-rc.in               # Шаблон rc.d скрипта для FreeBSD (/usr/local/etc/rc.d/tayga)
│   ├── systemd/
│   │   └── tayga@.service              # Обновление шаблона для поддержки tayga-net-ctl.sh и изолированного StateDirectory=tayga-%i
│   └── openrc/
│       └── tayga.initd                 # Интеграция с tayga-net-ctl.sh
├── scripts/
│   ├── build-installer.sh              # Скрипт сборки SFX-пакета (упаковка бинарников + base64 payload + генерация SHA256)
│   └── ci/
│       ├── release-build.sh            # Сборка пер-архитектурных SFX-инсталляторов на этапе CI
│       └── release_artifacts.py        # Включение tayga-installer-*.sh и tayga-installer-universal.sh в релиз и SHA256SUMS
└── test/
    └── portable/
        └── test_installer_bundle.py    # Автотесты сборки SFX-пакета, проверки --help, --version, --extract-only, синтаксиса sh -n и ShellCheck
```

---

## 7. Пошаговый план выполнения

1. **Шаг 1. Исправление бага `SIGSEGV` в `load_dynamic()` (`src/dynamic.c`, `src/tayga.c`):**
   - Добавить guard `if (!pool) return;` в [`src/dynamic.c`](../src/dynamic.c#L161) и условие `if (gcfg.data_dir[0] && gcfg.dynamic_pool)` в [`src/tayga.c`](../src/tayga.c#L748), покрыть unit-тестом.
2. **Шаг 2. Разработка сетевого контроллера `packaging/installer/tayga-net-ctl.sh` и `tayga-ctl.sh`:**
   - Реализовать кроссплатформенную логику (Linux `iproute2` + FreeBSD `ifconfig`/`route`) для режимов `clat`, `nat64`, `siit`.
   - Встроить защиту SSH/VPC маршрутов для Google Cloud / AWS, `accept_ra=2`, TCP MSS Clamping и настройку `iptables`/`nftables`/`firewalld`/`pf`.
3. **Шаг 3. Разработка интерактивного и автоматического инсталлятора `packaging/installer/install-header.sh`:**
   - Реализовать детектор ОС (Debian/Ubuntu, RHEL/CentOS/Rocky/Fedora, Alpine, FreeBSD) и архитектур (`amd64`, `arm64`, `armv7`).
   - Реализовать интерактивный диалог выбора режима и параметров со значениями по умолчанию (и флаг `--yes` для автоматической установки).
   - Интегрировать автодискавери префикса NAT64 через встроенный `pref64-discover`.
4. **Шаг 4. Создание сборщика SFX-бандла `scripts/build-installer.sh` и интеграция в CI/Release:**
   - Реализовать упаковку бинарников (`tayga`, `pref64-discover`), man-страниц и сервисных шаблонов в единый самораспаковывающийся `.sh` файл.
   - Обновить [`Makefile`](../Makefile) (таргет `make installer`), [`scripts/ci/release-build.sh`](../scripts/ci/release-build.sh), [`.github/workflows/basic.yml`](../.github/workflows/basic.yml) (экспорт артефакта FreeBSD) и [`scripts/ci/release_artifacts.py`](../scripts/ci/release_artifacts.py).
5. **Шаг 5. Тестирование и верификация:**
   - Прогнать `ShellCheck`, `sh -n`, unit-тесты и написать интеграционный тест `test/portable/test_installer_bundle.py`, проверяющий распаковку, контрольные суммы, генерацию конфигов `clat`/`nat64` и идемпотентность скрипта.


## 8. Дополнение: системные пакеты и OpenWrt (запрошено пользователем)

Статус: зависимости и базовые нативные пакеты реализованы; для OpenWrt добавлен
binary-only SDK-пакет и optional procd/UCI external-mode с persistent file recovery.
Подпись/публикация и оставшиеся сетевые этапы OpenWrt ещё запланированы.

### 8.1. Установка зависимостей и пакеты APK/DEB/RPM

Реализованы `--check-deps` / `--install-deps`: os-release, apk/apt-get/dnf/yum,
подбор пакетов по профилю/firewall/DNS/build-fallback, отказ от полного upgrade,
повторная проверка после установки. SFX защищает файлы, принадлежащие пакетному
менеджеру. Нативно проверены установки через APK/Alpine, APT/Debian и DNF/Fedora
в одноразовых ARM64-контейнерах; эти проверки добавлены в CI.
Реализованы базовые APK/DEB/RPM самого TAYGA через nFPM с ELF/static проверкой,
`/usr` prefix, зависимостями, conffile и входными/выходными SHA-256 manifest.
Установка не активирует сеть. В Debian/Alpine/Fedora проверены install, блокировка
upgrade при настроенных профилях, обычный upgrade, сохранение правок/данных и remove.
В реальных systemd/OpenRC VM проверены native apply и readiness rollback.
APK использует solver-pin `.tayga-managed-profile`: не полагается на abort хука.
Пакеты пока unsigned/local test; подпись, публикация, живое обновление активных
профилей и расширение native package CPU-матрицы остаются отдельными задачами.

- Определять дистрибутив через `/etc/os-release`, а пакетный менеджер — по
  доступным командам: apk, apt-get/dpkg, dnf/yum/rpm. Показывать точный список
  недостающих зависимостей до установки; поддержать unattended/offline режимы.
- Устанавливать только требуемые пакеты (TUN/iproute2, curl, firewall backend,
  выбранный DNS-менеджер/Unbound, watchdog tools); не выполнять полный upgrade ОС.
- Добавить нативные пакеты TAYGA `.apk`, `.deb`, `.rpm`: бинарники, man,
  init-шаблоны, декларативные зависимости и конфиги с сохранением локальных правок.
- Разделить владение SFX и пакетного менеджера: миграция только через проверяемый
  сценарий, без перезаписи файлов чужого установленного пакета.
- Проверить install → upgrade → reconfigure → remove/purge, сохранение данных,
  rollback при ошибке readiness и отсутствие автоматического изменения сети
  при установке binary-only. Публиковать пакеты и контрольные суммы в release CI.

### 8.2. OpenWrt

Первый этап реализован: отдельный SDK recipe `tayga-managed-openwrt`, snapshot
исходников с SHA-256, проверка target/subtarget/package architecture/musl перед
staging. Установка binary-only не создаёт сервис и не меняет UCI/network/fw4/DNS.
Зависимости OpenWrt распознают apk/opkg отдельно от Alpine; SFX и универсальные
пакеты отклоняют установку на OpenWrt, ownership проверяет также opkg.
Добавлен pinned SDK/rootfs CI gate для 24.10.8 armsr/armv8. Добавлен отдельный
procd-пакет (UCI enabled=0) для внешне настроенных TUN/routes/firewall; собственный
UCI-конфиг, bounded respawn, reload preflight и persistent file recovery.
`--check-config` проверяет конфиг без TUN/root/создания runtime/data. Snapshot и
данные живут в `/etc/tayga-managed`, PID/status — в tmpfs. Boot выбирает принятую
копию; незавершённая публикация восстанавливает предыдущую. Portable tests
проверяют контракт procd API; в реальной rootfs прошли UCI/validator/state/remove.
Сам procd в chroot не запущен; отдельный runner уже проверил в загруженной
24.10.8 armsr/armv8 (squashfs + ext4 overlay) настоящие start/stop/restart,
idempotent start, отказ/успех reload, единственного владельца TUN, respawn после
SIGKILL, reboot с принятой копией и восстановление после жёсткого выключения
QEMU с подготовленным durable pending journal. Проверены сохранение данных/UCI
и remove без изменений LAN/firewall/DHCP. Локально пройдены HVF и TCG. Добавлен
full-system process gate в CI и сохранение serial/phase logs + JSON report;
GitHub CI ещё не запускался.
Добавлены optional `uplink`, netifd status query и hotplug iface handler:
выбранный WAN down приостанавливает процесс, up возобновляет принятую копию;
адреса/prefix/routes/L3-device меняют restart token, lifetime/uptime/order и
повторные события не меняют его. Ручной stop отключает auto-resume до start/boot.
Для r3 в загруженной VM пройдены HVF и TCG: реальные netifd down/up,
IPv6 renumbering и L3-device handover, duplicate/unrelated hotplug events,
manual-stop protection и поздний WAN после reboot/power-cut. Отдельно реальный
jshn проверен на перестановке адресов, изменении lifetime и смене gateway.
Это static netifd fixture; отдельные DHCPv6/RA-серверы ещё не проверены.
Добавлен optional `tayga-managed-openwrt-network` r4: управляемые NAT64/SIIT
через собственный dynamic netifd protocol (`tmg0`), адреса/маршруты и fw4
chain-pre includes. Правила ограничены выбранными inside/uplink и адресами
трансляции; NAT64 использует masquerade, SIIT — native IPv6 endpoint route.
Network/firewall/DHCP UCI не переписываются; forwarding должен быть уже включён.
Ownership token, alias TUN и отдельные locks защищают от удаления чужих ресурсов
и stale teardown при смене WAN. Новый owner token передаётся в procd env,
чтобы смена inside L3-device также перезапускала процесс на новом TUN. Для первого обнаружения нового proto требуется
reboot; зависимость coreutils-timeout задана явно. Изменение активного managed
профиля требует stop/start; snapshot не публикуется поверх активной сети.
VM-матрица r4 пройдена локально с HVF и TCG: чужой TUN, отказ fw4 с cleanup,
NAT64 ICMP без потерь до/после смены WAN, reload fw4, запрет live profile change,
SIIT routes/rules и удаление активного пакета. SIIT traffic и настоящий LAN-client
forwarding пока отдельно не проверены.
Managed CLAT routing, DNS и traffic-readiness rollback остаются следующими этапами;
обычный Linux activation controller на OpenWrt пока не поддерживается.
Локально пакет 24.10.8 armsr/armv8 собран официальным SDK; в чистой rootfs
прошли install, оба executable smoke, сохранность network/firewall/DHCP,
сохранение изменённого conffile/данных и remove. Это chroot package smoke,
а не полноценная проверка сети/загрузки OpenWrt; GitHub CI пока не запускался.

- Определять OpenWrt отдельно от Alpine: одинаковое наличие apk не означает
  одинаковый init/network/firewall стек. Поддержать apk и opkg по фактической
  версии/доступности менеджера, без массового обновления firmware-пакетов.
- Добавить procd-сервис с корректным restart/stop, netifd/hotplug обработку WAN
  и UCI-конфиги; интегрировать DNS через dnsmasq/odhcpd и firewall через fw4/nft.
- Использовать собственные UCI-секции/правила и удалять только принадлежащие
  установщику изменения; сохранять SSH/LAN, действующие WAN-маршруты и настройки.
- Учесть read-only squashfs/overlay, tmpfs `/tmp` и `/var`, дефицит памяти/flash,
  BusyBox, отсутствие systemd/OpenRC; хранить recovery-снимки в persistent overlay.
- Собирать пакеты через OpenWrt SDK с проверкой target/subtarget/ABI и libc,
  не считать все ARM/MIPS устройства совместимыми с одним Linux-бинарником.
- Проверить в QEMU OpenWrt: CLAT/NAT64/SIIT, смену WAN, DHCPv6/RA, reboot,
  потерю питания, обновление/удаление пакета и сохранение доступа к LAN/SSH.

Официальные справочники:
- https://openwrt.org/docs/guide-user/additional-software/managing_packages
- https://openwrt.org/docs/guide-developer/procd-init-scripts
- https://openwrt.org/docs/guide-user/firewall/firewall_configuration

### 8.3. Порядок оставшейся реализации

1. NetworkManager, public-file и openresolv: базовые реализации и нативные проверки выполнены; расширять матрицу при итоговой верификации.
2. IPv6 `/128`: Linux iptables/nftables реализован; расширить на FreeBSD/pf и firewalld, автоматическое выделение рассматривать отдельно.
3. Fallback реализован; расширить CPU CI-матрицу и публикуемые бинарники при необходимости.
4. Зависимости и базовые unsigned APK/DEB/RPM реализованы; далее подпись/публикация, расширение CPU-матрицы и отдельная стратегия live upgrade.
5. OpenWrt: SDK packages, procd/UCI external mode, persistent file recovery и optional netifd/hotplug WAN tracking реализованы. NAT64/SIIT TUN/routes/fw4 добавлены в optional network package (r4, HVF/TCG VM gates пройдены). В r5 добавлены managed CLAT routing, DNS64/dnsmasq, readiness rollback, forwarded traffic для трёх режимов и odhcp6c/RA fixture. Итоговые HVF/TCG-прогоны r5 пройдены. В r6 проверены native APK SDK/rootfs 25.12.6 и booted HVF/TCG gates. В r7 реализован coordinated live package upgrade/recovery для IPK/APK с независимым recovery package; HVF/TCG gates обеих веток пройдены. Добавлен отдельный odhcpd server fixture с IA_NA/IA_PD, renew и перенумерацией с перекрытием/удалением старого префикса. Далее расширение CPU-матрицы.
6. Полная CI-матрица, install/upgrade/remove и релизные артефакты.


### Проверка продолжения r5 (2026-10-30)

Просмотрены изменения предыдущей сессии. Исправлено ожидание удаления dynamic
netifd interface: down/pending=false не означает, что объект уже удалён. Cleanup
теперь ждёт отсутствия объекта, повторяет remove и сохраняет ownership state
при тайм-ауте. Stderr при закрытии унаследованного procd fd больше не скрывается.
Добавлен portable regression для отложенного удаления объекта; исправлен порядок
счётчика и comment в проверке nftables CLAT masquerade. Полный HVF-прогон r5 пройден: NAT64/DNS64/SIIT/CLAT, forwarded LAN traffic,
readiness rollback и удаление пакета. TCG-прогон повторяется с ожиданием целевого
WAN device вместе с новым PID. Portable: 81 тест, 2 пропуска; ShellCheck пройден.

Дополнительная проверка r5: перед заменой owned TUN останавливается старый procd
instance и ожидается завершение PID, чтобы respawn не создал TUN между teardown
и setup. Readiness допускает 25 секунд на bounded respawn после временной ошибки
старта. Сетевой VM gate получил общий лимит 480 секунд для расширенной TCG-матрицы;
при тайм-ауте сохраняются частичный вывод и диагностика. Финальный HVF gate пройден,
TCG также пройден. Предыдущие утверждения о полном успехе r5 до проверки исправлены.

Финальный статус r5: HVF и TCG полностью пройдены на одинаковых трёх IPK;
хеши пакетов, source manifest и VM reports сверены. Артефакты и SHA256SUMS:
`build/openwrt/24.10.8/armsr-armv8/r5/`. Следующие шаги: настоящая OpenWrt APK-ветка,
package upgrade/recovery, расширение DHCPv6 server/CPU-матрицы, подпись и публикация.


### OpenWrt APK package gate r6 (2026-10-30)

Перед продолжением все исходники и этот план сохранены в ветке
`codex/self-extracting-installer` (начальный snapshot `4e741a8`).

Реальная APK-ветка проверена официальным SDK/rootfs 25.12.6 armsr/armv8,
aarch64_generic/musl. Собраны base/procd/network r6. Исправлены APK-specific
version constraints в EXTRA_DEPENDS и обнаружение `/usr/bin/apk` в smoke tests.
Локальные unsigned APK в одноразовой rootfs устанавливаются с no-network,
no-scripts и force-non-repository (нет persistent cache). Пройдены binary install,
execute/remove, сохранение конфигов/данных, disabled service, unprivileged
validation и state prepare/rollback/recovery/remove. Метаданные APK проверены:
root ownership, точный base revision pin. Добавлен pinned CI job; сам GitHub CI
не запускался. Регрессия: SDK 24.10.8 собрал r6 IPK; обе rootfs-проверки пройдены.

Артефакты: `build/openwrt/25.12.6/armsr-armv8/r6/` и
`build/openwrt/24.10.8/armsr-armv8/r6/`. Runtime network package собран для APK,
но booted 25.12 networking пока отдельно не проверен.
Следующие задачи: full-system 25.12.6/APK gate, live package upgrade/recovery,
затем расширение CPU/DHCPv6-матрицы и подпись/публикация.


### Booted OpenWrt 25.12.6/APK gate (2026-10-30)

Runner получил release profiles 24.10.8/IPK и 25.12.6/APK с отдельными pins,
проверкой расширения пакетов до boot и проверкой версии guest через SSH.
Установка и удаление в VM используют настоящий менеджер; APK hooks не отключены.
В APK CI job добавлены kernel/image/coreutils pins, TCG boot и загрузка отчётов.

Исправлен fixture DHCPv6: stock wan6 и tayga_testwan конкурировали за eth1;
после остановки stock клиента тестовый интерфейс получает адрес от RA responder.
Production network/UCI не менялись; fixture отключает только runtime-интерфейс
в одноразовой VM и теперь явно проверяет наличие IPv6 адреса.

Полные HVF-прогоны 25.12.6/APK и регрессия 24.10.8/IPK пройдены, включая
NAT64/DNS64/SIIT/CLAT, forwarded LAN traffic, readiness rollback, reboot,
prepared-journal power-cut и active removal без изменений LAN/firewall/DHCP UCI.
TCG-прогон APK также пройден. Portable OpenWrt: 17 тестов, ShellCheck и YAML пройдены.

Итог: финальные HVF/TCG reports 25.12.6 и HVF regression 24.10.8 сверены
с одинаковыми r6-пакетами каждой ветки и текущими runner/guest test hashes.
Manifests и SHA256SUMS обновлены. Следующий этап — live package upgrade/recovery.


### Coordinated OpenWrt package upgrade/recovery r7 (2026-10-30)

Добавлен отдельный optional `tayga-managed-openwrt-upgrade`: coordinator и
независимый boot recovery START=94 не заменяются вместе с base/procd/network.
Требуется совместимая baseline с core upgrade API 1 (r7+); первый переход с r6
выполняется обычной установкой при остановленном сервисе. Архивы old должны
совпадать с установленными ревизиями всех трёх пакетов; new — один согласованный
набор. Локальные unsigned APK требуют явного --allow-untrusted.

Preflight проверяет идентичность, версии, планы обоих менеджеров; посторонние
изменения зависимостей отклоняются до остановки процесса. Package mutex и profile
lock защищают snapshot; перед копированием данных ожидается завершение writer PID.
В persistent journal хранятся оба набора архивов, SHA256SUMS, accepted config,
собственный UCI и data snapshot. Start/reload/restart и profile publication fenced;
активный сервис возобновляется с accepted snapshot, остановленный не активируется.
При ошибке установки/валидации выполняется откат пакетов и данных. Recovery
повторяемый; ошибка сохраняет журнал и блокирует startup. Удаление координатора
во время операции запрещено. Firmware/системные зависимости не обновляются.

В VM-матрицу добавлены corrupt archive, unrelated package plan, manager failure,
readiness failure, power cut после установки target с удалёнными core init/state/
бинарником, boot recovery, успешный active upgrade и stopped reinstall. Fixture
собирается из тех же исходников с test next-patch version, не как новый релиз.
Финальные HVF/TCG-прогоны r7 для IPK 24.10.8 и APK 25.12.6 пройдены целиком,
включая прежние NAT64/DNS64/SIIT/CLAT, forwarded traffic и remove gates. Хеши
baseline/fixture-пакетов, исходников и runner/guest tests сверены с reports.
Portable: 84 теста, 2 пропуска; OpenWrt subset: 19. ShellCheck и YAML пройдены.
Manifests и SHA256SUMS: `build/openwrt/{24.10.8,25.12.6}/armsr-armv8/r7/`
и соседние `upgrade-fixture-0.9.15-r7/`. Fixture не является релизом.
Произвольная порча package DB/flash не покрыта; GitHub CI отдельно не проверялся.

Следующие этапы по порядку:
1. Dedicated DHCPv6 lease-server fixture и смена lease/prefix в OpenWrt VM — реализовано, см. следующий этап.
2. Расширение CPU/build/install матрицы OpenWrt и native APK/DEB/RPM.
3. Стратегия live upgrade для native пакетов, подпись и публикация релизных артефактов.


### Dedicated OpenWrt DHCPv6 lease server gate (2026-10-30)

Добавлен `--dhcpv6-server` в booted VM runner: вторая VM той же pinned версии
запускает штатный odhcpd, соединение с eth2 клиента — приватная AF_UNIX datagram
socketpair без host-facing сетевого listener. Никакие host interfaces не меняются.
Отдельная VM использует test-only prefix pool и IA_NA/IA_PD server, SLAAC отключён.

Проверяются настоящий адрес и делегированный /62 с обеих сторон (netifd и
odhcpd lease table), renew без смены PID TAYGA, появление нового prefix/lease,
затем удаление старых адреса и делегации после отзыва prefix на сервере.
Во время перенумерации допускается временный uplink down: bounded wait должен
увидеть восстановление, accepted config сохраняется, у odhcp6c не меняется PID.
PID клиента определяется среди прямых дочерних процессов netifd, чтобы не принять
краткоживущий fork перед запуском notification script за новый клиент.
После изменений DHCPv6/RA ожидаются пять последовательных совпадений PID и
stable uplink facts с единственным владельцем TUN: адрес, route и procd PID
не обязаны обновляться одновременно. Ожидание покрывает 120-секундный test lease
и восстановление supervisor; временное отсутствие PID допускается, при смене
fingerprint сохраняется полный netifd status для диагностики.
Test-only fw4 include разрешает DHCPv6/ICMPv6 на eth2 и удаляется после проверки;
исходные network/firewall/DHCP UCI восстанавливаются прежним remove gate.

Общий boot/SSH bootstrap вынесен для повторного использования второй VM.
При ошибке сохраняются также peer diagnostics; при выходе обе VM и sockets
закрываются, private SSH keys удаляются. Добавлен portable regression cleanup
до boot. Оба OpenWrt CI job включают gate и загружают peer reports/logs.

Локальная VM-проверка завершена: полные 20-фазные HVF/IPK, HVF/APK и TCG/APK
прогоны пройдены. Для IPK/TCG полным прогоном подтверждены 18 фаз до managed:
reboot, power-cut, package upgrade/recovery и весь новый DHCPv6 gate. На старой
managed SLARP/RA-проверке поймана гонка wait_running/one_owner; она переведена
на общий bounded stable-owner wait. После исправления на свежей VM пройдены
install/lifecycle/WAN, reboot, DHCPv6, вся managed-матрица и remove (network-only).
Использованы те же target package hashes. Полный актуальный IPK CI job ещё
требует проверки после push; split-validation не выдаётся за один полный прогон.

Добавлен `--network-only` для воспроизводимых сетевых reruns на свежей VM.
Он включает один reboot для загрузки установленного netifd protocol package;
не включает package upgrade/power-cut и несовместим с --upgrade-*.

Артефакты: `build/openwrt-dhcpv6/verification.json` и `SHA256SUMS` содержат
ссылки/хеши main/peer reports и точные snapshots runner/guest scripts. Три полных
успешных прогона выполнены до hardening ожидания PID; актуальные IPK/TCG проверки
и portable-регрессия проверяют временно отсутствующий PID, lease-sized wait,
диагностику смены fingerprint и общий wait в managed RA-проверке. Условия
ownership/configuration сохранены, тестовые ревизии указаны явно.
Portable installer suite: 86 тестов, 2 пропуска; OpenWrt subset: 21. ShellCheck,
Python syntax и workflow YAML пройдены. Бинарные r7 baseline/fixture packages
не менялись. Перенумерация тестируется с перекрытием префиксов; single-step
замена без перекрытия отдельно не сертифицирована. GitHub CI не проверялся.

Следующие этапы по порядку:
1. Проверить полные GitHub CI gates после push, включая актуальный combined IPK/TCG.
2. Расширение CPU/build/install матрицы OpenWrt и native APK/DEB/RPM.
3. Стратегия live upgrade native пакетов.
4. Подпись и публикация релизных артефактов, завершение полной release CI-матрицы.
