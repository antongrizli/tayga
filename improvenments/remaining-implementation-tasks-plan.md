# Детальный план реализации оставшихся улучшений TAYGA

Документ содержит пошаговые инструкции, архитектурные контракты, примеры кода, конфигураций и тестовых сценариев для автономной реализации агентом.

---

## Обзор оставшихся задач

Текущая реализация SFX-инсталлятора, multiarch-матрицы (7 платформ), скоординированного live upgrade и OpenWrt IPK/APK пакетов полностью покрыта тестами и верифицирована в CI. 

Для завершения полного скоупа проекта остаются 4 ключевые фазы:

1. **Фаза 1: Расширение адаптации адресов CLAT (NAT66 и Proxy NDP) на `firewalld` (Linux) и `pf` (FreeBSD)**
2. **Фаза 2: Автоматическое детерминированное выделение IPv6 (RFC 4193 ULA) и интеллектуальный авто-выбор режима CLAT**
3. **Фаза 3: Включение нативных пакетов (`.deb`, `.rpm`, `.apk`) и FreeBSD артефактов в релизный конвейер (`release.yml`)**
4. **Фаза 4: OpenWrt LAN/WAN DHCP-Gate и сквозная интеграция с клиентами локальной сети**

---

## Фаза 1: Расширение адаптации адресов CLAT на `firewalld` и FreeBSD `pf`

### Контекст проблемы
В настоящее время режимы `--clat-address-mode=proxy-ndp` и `--clat-address-mode=nat66` поддержаны **только** в Linux для бэкендов `iptables` и `nftables` (в [`packaging/installer/tayga-net-ctl.sh`](../packaging/installer/tayga-net-ctl.sh#L97-L102)). 
При попытке использования на `firewalld` (RHEL/Fedora/CentOS) или на `FreeBSD` скрипт завершается с ошибкой `Address adaptation requires Linux CLAT` / `Address adaptation requires iptables or nft`.

### 1.1. Реализация для Linux с `firewalld`

#### Механизм Proxy NDP
Proxy NDP работает на уровне ядра Linux через сетевой стек (`ip -6 neigh add proxy ...` и `sysctl net.ipv6.conf.<iface>.proxy_ndp=1`). Он не зависит от брандмауэра.
В `tayga-net-ctl.sh` необходимо разрешить `firewalld` при валидации:
```sh
case "$address_mode" in
    routed) ;;
    proxy-ndp)
        case "$firewall" in iptables|nft|firewalld) ;; *) fail 'Proxy NDP requires iptables, nft, or firewalld' ;; esac
        ;;
    nat66)
        case "$firewall" in iptables|nft|firewalld) ;; *) fail 'NAT66 requires iptables, nft, or firewalld' ;; esac
        ;;
esac
```

#### Механизм NAT66 для firewalld
В функции `fw_firewalld()` добавить правила трансляции адресов для исходящего IPv6-трафика от адресов CLAT к префиксу PLAT (`$pref64`):
```sh
if [ "$mode" = clat ] && [ "$address_mode" = nat66 ]; then
    for src in "$clat6" "$addr6"; do
        firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -o "$uplink6" -s "$src" -d "$pref64" -j SNAT --to-source "$nat66_address"
        printf 'firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -o %s -s %s -d %s -j SNAT --to-source %s >/dev/null 2>&1 || :\n' \
            "$uplink6" "$src" "$pref64" "$nat66_address" >> "$journal"
    done
fi
```

### 1.2. Реализация для FreeBSD `pf`

#### Механизм NAT66 в PF
Межсетевой экран FreeBSD `pf` нативно поддерживает IPv6 NAT в едином синтаксисе правил трансляции `nat on <interface> inet6 from <src> to <dst> -> <target>`.
В `tayga-net-ctl.sh` в функции `fw_pf()`:
```sh
elif [ "$mode" = clat ]; then
    printf 'pass in quick on %s inet from any to any keep state\n' "$dev"
    printf 'pass out quick on %s inet from any to any keep state\n' "$dev"
    if [ "$address_mode" = nat66 ]; then
        printf 'nat on %s inet6 from { %s, %s } to %s -> %s\n' "$uplink6" "$clat6" "$addr6" "$pref64" "$nat66_address"
    fi
    printf 'pass out quick on %s inet6 from %s to any keep state\n' "$uplink6" "$clat6"
    printf 'pass in quick on %s inet6 from any to %s keep state\n' "$uplink6" "$clat6"
fi
```

#### Механизм Proxy NDP в FreeBSD
В FreeBSD ядро не имеет отдельного флага `sysctl proxy_ndp` как в Linux, но отвечает на Neighbor Solicitation для адресов, назначенных на интерфейс как алиас `/128`:
```sh
if [ "$address_mode" = proxy-ndp ]; then
    if [ "$os" = FreeBSD ]; then
        for address in "$clat6" "$addr6"; do
            if ifconfig "$uplink6" inet6 | grep -Fwq "$address"; then
                fail 'Proxy address is already assigned to the uplink'
            fi
            ifconfig "$uplink6" inet6 "$address/128" alias
            printf 'ifconfig %s inet6 %s -alias >/dev/null 2>&1 || :\n' "$uplink6" "$address" >> "$journal"
        done
    else
        # Существующий Linux путь через ip -6 neigh add proxy
        set_sysctl "net.ipv6.conf.$uplink6.proxy_ndp" 1
        ...
    fi
fi
```

### 1.3. Тестирование Фазы 1
- **Модульные тесты**: в [`test/portable/test_installer_network.py`](../test/portable/test_installer_network.py) добавить:
  - `test_firewalld_nat66_rules_and_rollback`: эмуляция `firewall-cmd`, проверка добавления `direct --add-rule ipv6 nat POSTROUTING` и LIFO-отката в `$journal`.
  - `test_freebsd_nat66_rules_in_pf`: проверка генерации `nat on <uplink> inet6 ... -> ...` в `rules.pf`.
  - `test_freebsd_proxy_ndp_alias`: проверка применения `ifconfig <uplink> inet6 <clat6>/128 alias` и очистки.
- **Интеграционные тесты**: запуск `make test-portable` (277+ тестов).

---

## Фаза 2: Автоматическое выделение IPv6 (RFC 4193 ULA) и авто-выбор режима

### Контекст проблемы
При настройке CLAT администратор сталкивается с выбором:
- Если провайдер маршрутизирует префикс (например, `/60` или `/56`) на хост — работает чистый `routed`.
- Если провайдер выделил ровно один `/64` на WAN/uplink без маршрутизации дополнительных подсетей:
  - Либо `proxy-ndp` (требует, чтобы провайдер слал NS и принимал NA для адреса из своего `/64`).
  - Либо `nat66` (гарантированно работает в любых облаках GCP/AWS/Hetzner, где NS на чужие MAC блокируются).
Сейчас для NAT66 администратор должен вручную придумать ULA-префикс (`fd00:...`) и скопировать uplink IPv6.

### 2.1. Алгоритм детерминированной генерации ULA (RFC 4193)
RFC 4193 предписывает:
1. Взять системный идентификатор времени (NTP/POSIX timestamp) и аппаратный ID (EUI-48 MAC или `machine-id`).
2. Вычислить SHA-1 или SHA-256 хэш.
3. Взять младшие 40 бит хэша в качестве Global ID.
4. Префикс: `fd` + 40-битный Global ID + `:0001::/64`.

Реализация в POSIX shell в [`packaging/installer/wizard.sh`](../packaging/installer/wizard.sh) и [`packaging/installer/configure.sh`](../packaging/installer/configure.sh):
```sh
generate_deterministic_ula() {
    seed=
    if [ -f /etc/machine-id ] && [ -s /etc/machine-id ]; then
        seed=$(cat /etc/machine-id)
    elif [ -f /var/lib/dbus/machine-id ]; then
        seed=$(cat /var/lib/dbus/machine-id)
    elif command -v sysctl >/dev/null 2>&1 && sysctl -n kern.hostuuid 2>/dev/null; then
        seed=$(sysctl -n kern.hostuuid 2>/dev/null)
    fi
    [ -n "$seed" ] || seed="tayga-clat-$(uname -n)-$(date +%s)"
    
    # 40-bit Global ID из первых 10 hex-символов sha256
    hash=$(printf '%s\n' "$seed" | sha256sum 2>/dev/null | awk '{print $1}')
    [ -n "$hash" ] || hash=$(printf '%s\n' "$seed" | shasum -a 256 2>/dev/null | awk '{print $1}')
    
    p1=$(printf '%s' "$hash" | cut -c 1-2)
    p2=$(printf '%s' "$hash" | cut -c 3-6)
    p3=$(printf '%s' "$hash" | cut -c 7-10)
    
    printf 'fd%s:%s:%s:1' "$p1" "$p2" "$p3"
}
```

### 2.2. Авто-заполнение параметров CLAT при `--clat-ipv6=auto`
Если передан `--clat-ipv6=auto` или выбран авто-режим в `wizard.sh`:
1. Находится глобальный IPv6 на uplink-интерфейсе:
   `uplink_ip6=$(ip -6 -o addr show scope global | awk '{split($4,a,"/");print a[1]}' | head -n1)`
2. Если выбран режим `nat66`:
   - `ula_prefix=$(generate_deterministic_ula)`
   - `tayga_ip6="${ula_prefix}::1"`
   - `clat_ip6="${ula_prefix}::2"`
   - `nat66_address="$uplink_ip6"`
3. Если выбран режим `routed` или `proxy-ndp`:
   - `clat_ip6="${uplink_ip6%:*}:464"` (или авто-адрес из обнаруженного префикса)

### 2.3. Интеграция с интерактивным мастером (`wizard.sh`)
В мастере добавить авто-детекцию топологии:
- Если uplink имеет ровно `/64` и шлюз по умолчанию не маршрутизирует другие адреса: мастер предлагает режим:
  `[Recommended] NAT66 (Safe for single /64 uplinks, GCP, AWS, Hetzner)` с уже вычисленными ULA-адресами.
- Позволяет администратору подтвердить одним нажатием Enter без ручного ввода hex-адресов.

---

## Фаза 3: Включение нативных пакетов (`.deb`, `.rpm`, `.apk`) и FreeBSD в `release.yml`

### Контекст проблемы
В ветке `codex/self-extracting-installer` реализованы и протестированы:
- Скрипт сборки нативных пакетов [`scripts/build-native-packages.py`](../scripts/build-native-packages.py) (создает `.deb`, `.rpm`, `.apk`).
- Проверка статических ELF для 7 архитектур (`amd64`, `arm64`, `armv7`, `armv6`, `riscv64`, `ppc64le`, `s390x`).
- Загрузка и проверка `candidate-freebsd-amd64` и `candidate-freebsd-arm64` в `basic.yml`.
- Поддержка Minisign в `scripts/ci/release_artifacts.py`.

Однако [`.github/workflows/release.yml`](../.github/workflows/release.yml):
- Не запускает сборку нативных пакетов для релиза.
- Не выгружает их в директорию `candidates/candidate-native`, откуда их забирает `assemble`.
- Не включает `candidate-freebsd-*` в матрицу `prepare-artifacts`.

### 3.1. Обновление `.github/workflows/release.yml`

#### Добавление джобы `prepare-native-packages`
В `release.yml` перед `verify-assets`:
```yaml
  prepare-native-packages:
    name: Build native packages (DEB, RPM, APK) for release
    needs: [resolve, compiler-platform-gates]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ needs.resolve.outputs.sha }}
          persist-credentials: false
      - name: Install nFPM
        run: |
          mkdir -p "$RUNNER_TEMP/nfpm"
          curl -sSL "https://github.com/goreleaser/nfpm/releases/download/v2.48.0/nfpm_2.48.0_Linux_x86_64.tar.gz" | tar -xz -C "$RUNNER_TEMP/nfpm" nfpm
          echo "$RUNNER_TEMP/nfpm" >> $GITHUB_PATH
      - uses: actions/download-artifact@v8
        with:
          pattern: candidate-*
          path: candidates
      - name: Build packages across all supported Linux architectures
        run: |
          mkdir -p release-native
          version="${{ needs.resolve.outputs.version }}"
          commit="${{ needs.resolve.outputs.sha }}"
          # Собираем deb, rpm, apk для доступных статически скомпилированных артефактов
          for arch in amd64 arm64 armv7; do
            bin="candidates/candidate-$arch/tayga-linux-$arch"
            helper="candidates/candidate-$arch/pref64-discover-linux-$arch"
            if [ -f "$bin" ] && [ -f "$helper" ]; then
              python3 scripts/build-native-packages.py \
                --version "$version" --release 1 --arch "$arch" \
                --tayga "$bin" --helper "$helper" \
                --maintainer "TAYGA Community <antongrizli@gmail.com>" \
                --source-commit "$commit" \
                --nfpm "$RUNNER_TEMP/nfpm/nfpm" \
                --output release-native
            fi
          done
      - uses: actions/upload-artifact@v7
        with:
          name: candidate-native
          path: release-native/
          if-no-files-found: error
```

#### Обновление зависимостей `verify-assets`
В `verify-assets` в `release.yml`:
```yaml
  verify-assets:
    needs: [resolve, compiler-platform-gates, correctness-gates, integration, prepare-artifacts, prepare-native-packages]
```
Поскольку `verify-assets` уже использует `pattern: candidate-*`, артефакт `candidate-native` будет автоматически скачан в `candidates/candidate-native`, скопирован в `release-assets/` скриптом `release_artifacts.py assemble` и добавлен в `SHA256SUMS`.

### 3.2. Подпись релиза через Minisign
В шаге `verify-assets`:
```yaml
      - name: Assemble release assets and sign manifest
        env:
          MINISIGN_KEY_FILE: ${{ secrets.MINISIGN_KEY_FILE }}
          MINISIGN_PASSWORD: ${{ secrets.MINISIGN_PASSWORD }}
        run: |
          python3 scripts/ci/release_artifacts.py assemble --source release-source.json --directory candidates --output release-assets
          cd release-assets
          sha256sum -c SHA256SUMS
```
Если секрет `MINISIGN_KEY_FILE` задан, создается `SHA256SUMS.minisig`. Если секрет не задан (например, в тестовых PR), шаг корректно генерирует неподписанный `SHA256SUMS` без ошибок.

---

## Фаза 4: OpenWrt LAN/WAN DHCP-Gate и сквозная интеграция

### Контекст проблемы
Пакет `tayga-managed-openwrt` (IPK для 24.10 и APK для 25.12) успешно управляет демоном TAYGA через `procd`, привязывается к интерфейсам `netifd` (протокол `tayga`), настраивает `fw4` и перезапускается при падении.
Для полноценной работы роутера «из коробки» требуется автоматизация на стороне LAN:
1. Раздача DNS64 клиентам локальной сети через `dnsmasq` / `odhcpd`.
2. Анонс префиксов IPv6 и маршрутизация IPv4 через TAYGA TUN.

### 4.1. Автоматическая конфигурация DNS64 в dnsmasq на OpenWrt
В [`packaging/openwrt/openwrt-network.sh`](../packaging/openwrt/openwrt-network.sh) добавить секцию координации с `dnsmasq`:
```sh
configure_dns64_openwrt() {
    pref64=$1
    if uci -q get dhcp.@dnsmasq[0] >/dev/null; then
        # Добавляем синтез DNS64 или перенаправление на локальный sidecar/upstream
        uci -q delete dhcp.@dnsmasq[0].server_nat64 || :
        uci add_list dhcp.@dnsmasq[0].server="2001:4860:4860::64"
        uci add_list dhcp.@dnsmasq[0].server="2001:4860:4860::6464"
        uci commit dhcp
        /etc/init.d/dnsmasq reload || :
    fi
}
```

### 4.2. Тестирование сквозного сценария OpenWrt
В [`test/system/run-openwrt-vm.py`](../test/system/run-openwrt-vm.py) расширить фазу `managed`:
- Проверка, что после поднятия интерфейса `tayga-clat` или `tayga-nat64` трафик из виртуального LAN-клиента (`10.0.2.0/24`) транслируется в IPv6 и возвращается обратно.
- Проверка отката конфигурации `uci` при остановке сервиса.

---

## Чеклист готовности к релизу

- [x] **Фаза 1**: `tayga-net-ctl.sh` поддерживает `nat66` и `proxy-ndp` на FreeBSD `pf` и Linux `firewalld`.
- [x] **Фаза 1**: Модульные тесты в `test_installer_network.py` покрывают новые ветки firewalld и FreeBSD pf.
- [x] **Фаза 2**: Реализована генерация RFC 4193 ULA в `wizard.sh` и `configure.sh`.
- [x] **Фаза 2**: Поддержан режим `--clat-ipv6=auto` с автоматическим заполнением параметров NAT66.
- [x] **Фаза 3**: `release.yml` включает сборку `candidate-native` и подпись Minisign.
- [x] **Фаза 3**: `release_artifacts.py` упаковывает `.deb`, `.rpm`, `.apk` и FreeBSD артефакты в релизные ассеты.
- [x] **Фаза 4**: OpenWrt-скрипты координируют раздачу DNS64 для локальных клиентов (`openwrt-network.sh`).
- [x] **Интеграция**: Все переносимые тесты (`make test-portable`) и `check-doc-links.py` зеленые.
- [ ] **CI**: Полный прогон `Basic Test` и `Correctness and review gates` на GitHub Actions успешен.
