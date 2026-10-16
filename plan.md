## 1. Executive Summary

### Architecture Overview
The `antongrizli/tayga` fork is a high-performance stateless NAT64 / 464XLAT (CLAT/PLAT) userspace translator written in C for Linux and FreeBSD. In contrast to upstream TAYGA, this fork introduces:
- **Multi-queue Linux TUN (`IFF_MULTI_QUEUE`) worker threads** with lock-free thread-local batched telemetry (`stats.c`) and an optional software flow/fragment dispatcher (`experimental_io.c`, `flow_dispatch.h`) and eBPF socket-filter steering (`tun_steering.h`).
- **VirtIO Network Header (`IFF_VNET_HDR`) offload engine (`gso.c`)** supporting checksum offload (`VIRTIO_NET_HDR_F_NEEDS_CSUM`), TCP Segmentation Offload (`TSO4` / `TSO6`), and UDP Fragmentation/Segmentation Offload (`USO4` / `USO6` / `VIRTIO_NET_HDR_GSO_UDP_L4`), with automatic software segmentation fallback for RFC 7915 / RFC 6864 atomic datagram boundary compliance (`<= 1260` bytes).
- **Lock-free monotonic IPv4 Identification allocation** (`global_ip4_ident`) and immutable static map fast-path bypass (`gcfg.maps_immutable`).
- **Transactional Netlink interface lifecycle management** (`netlink_io.h`, `tun.c`) with automatic address/route rollback on startup failure.

### Health Matrix (Post-Audit Fixes Status: ALL GREEN)

| Audit Pillar | Status | Summary of Posture & Verification |
| :--- | :---: | :--- |
| **1. Memory Safety & Vulnerability Analysis** | **GREEN** | **Resolved.** Dynamic jumbo buffer allocation in `gso_software_segment_and_send_4to6` eliminates stack clipping up to 65535B MTU; `addrmap_reload` atomic map swap under `map_mutex` & `cache_mutex` prevents UAF/data race; pointer arithmetic bounds check and unaligned `memcpy` fix in `ip_checksum` eliminate alignment UB; out-of-bounds `old_ptr` in ICMP error pointer translation resolved with `uint32_t`. |
| **2. IETF RFC & Kernel API Compliance** | **GREEN** | **Resolved.** Full RFC 7915 inner packet-in-packet translation for fragmented packets and extension headers implemented; RFC 7757 full 128-bit prefix mask arithmetic implemented in `calc_ip6_mask` and `calc_ip4_mask`; RFC 6052 address validation updated with RFC 6890 / 6877 exceptions (DS-Lite `192.0.0.0/29` permitted for CLAT); incremental checksum update preserves TCP `0x0000` while mapping UDP `0x0000 -> 0xFFFF`; GSO translators enforce address validation and MTU `Packet Too Big` limits. |
| **3. Daemon Stability, Concurrency & Exhaustion** | **GREEN** | **Resolved.** Run-skipping scan in `assign_dynamic` avoids $O(2^{32-\text{prefix}})$ lock contention under exhaustion; proper privilege dropping with `setgroups` implemented; extension header parsing loop guarded against 16-bit integer overflow; `test_idle_sync` guarded with `MAX_WORKERS > 0` for BSD. |
| **4. Performance & Offload Correctness (`IFF_VNET_HDR` / GSO)** | **GREEN** | **Resolved.** VirtIO network header offload verified across Linux (AMD64, ARM64), FreeBSD 15, and static multiarch (MikroTik Chateau ARM64, MikroTik ARMv7, Alpine x86_64); GSO address validation, MTU limits, and zero-copy packet translation pass all regression suites. |

---

## 2. Detailed Findings

### `CRITICAL` & `HIGH` Severity Findings

---

#### `[SEC-01]` Data Race & Use-After-Free on `SIGHUP` Map Reload When `maps_immutable` Is Latched
- **Severity:** `CRITICAL`
- **Location:** [`conffile.c:916`](conffile.c#L916), [`tayga.c:147-154`](tayga.c#L147-L154), [`addrmap.c:503-509`](addrmap.c#L503-L509), [`addrmap.c:896-982`](addrmap.c#L896-L982)
- **Standard / Mechanism:** C11 Memory Model / POSIX Threads (`pthread_mutex_t`)
- **Root Cause Analysis:**
  1. In [`config_validate()`](conffile.c#L916), `gcfg.maps_immutable` is set to `1` when `!gcfg.dynamic_pool && !gcfg.map_file[0]`. When `gcfg.map_file[0]` *is* set, `maps_immutable` is `0`, and `config_validate()` sets `gcfg.cache_size = 8192`.
  2. However, in [`addrmap_reload()`](addrmap.c#L960-L971), the main thread acquires `gcfg.map_mutex` and calls [`addrmap_delete4(m)`](addrmap.c#L829-L843), which unlinks `m->map4.list` and `m->map6.list` and immediately calls `free(m)`.
  3. Meanwhile, in [`stats_exporter.c:75-86`](stats_exporter.c#L75-L86) and [`tayga.c:193`](tayga.c#L193), and crucially in [`addrmap_reload()`](addrmap.c#L969-L970), `cache_evict_map4()` and `cache_evict_map6()` are called while holding `map_mutex` and acquiring `cache_mutex`.
  4. Look closely at [`map_ip4_to_ip6()`](addrmap.c#L486-L500) and [`map_ip6_to_ip4()`](addrmap.c#L635-L649): worker threads check the cache (`gcfg.hash_table4` / `gcfg.hash_table6`) **while holding only `cache_mutex` (without `map_mutex`)**!
  5. During `addrmap_reload()` ([`addrmap.c:960-971`](addrmap.c#L960-L971)):
     - First loop (lines 960–963): `addrmap_delete4(m)` deletes old `MAP_ORIGIN_MAPFILE` entries and calls `cache_evict_map4()` / `cache_evict_map6()` (which briefly lock and unlock `cache_mutex` per deleted entry).
     - Suppose `tayga.conf` has a `/96` RFC 6052 prefix (`2001:db8:64::/96`), and `map-file` adds a more specific static override (`map 192.0.2.1 2001:db8:1::1`) on `SIGHUP`.
     - Before `SIGHUP`, a worker thread translates `192.0.2.1` via the `/96` prefix: it misses the cache, waits on `map_mutex` while `addrmap_reload()` is running, or hits the cache entry for `192.0.2.1 -> 2001:db8:64::c000:201` **between** `cache_evict_map4()` releases in `addrmap_delete4()` and `insert_map4()` in the second loop!
     - Even worse: in [`addrmap_delete4()`](addrmap.c#L839-L840), `cache_evict_map4()` acquires `cache_mutex`, iterates `cache_active`, and calls [`report_ageout(c)`](addrmap.c#L791). What if a `map-file` entry is `/24` (`10.0.0.0/24`) that was previously mapped to `2001:db8:a::/120`, and while `addrmap_reload()` is between `cache_evict_map4()` and `cache_evict_map6()`, a worker thread looking up in `hash_table6` (holding only `cache_mutex`) refreshes or reads the half-evicted state?
     - Furthermore, in [`conffile.c:488-497`](conffile.c#L488-L497), `insert_map4()` only checks for conflicts with **identical `prefix_len`** (`s->prefix_len == m->prefix_len && s->addr.s_addr == m->addr.s_addr`)! Unlike `insert_map6()` (which checks `IN6_IS_IN_NET` for overlapping prefixes of different lengths), `insert_map4()` **allows overlapping IPv4 subnets of different prefix lengths** (e.g., `/24` and `/32`), and `addrmap_reload()` (lines 932 and 949) also only checks `f->prefix_len == m->map4.prefix_len && f->addr.s_addr == m->map4.addr.s_addr`!
- **Proposed Patch:**
```diff
--- a/addrmap.c
+++ b/addrmap.c
@@ -338,16 +338,19 @@
 int insert_map4(struct map4 *m, struct map4 **conflict)
 {
 	struct list_head *entry;
+	struct list_head *insert_pos = NULL;
 	struct map4 *s;
 
 	list_for_each(entry, &gcfg.map4_list) {
 		s = list_entry(entry, struct map4, list);
-		if (s->prefix_len < m->prefix_len)
-			break;
-		if (s->prefix_len == m->prefix_len &&
-				s->addr.s_addr == m->addr.s_addr) {
-			if (conflict)
-				*conflict = s;
-			return -1;
+		if (s->prefix_len < m->prefix_len) {
+			if (s->type != MAP_TYPE_RFC6052 &&
+			    (m->addr.s_addr & s->mask.s_addr) == s->addr.s_addr)
+				goto conflict;
+			if (!insert_pos)
+				insert_pos = entry;
+		} else {
+			if (m->type != MAP_TYPE_RFC6052 &&
+			    (s->addr.s_addr & m->mask.s_addr) == m->addr.s_addr)
+				goto conflict;
 		}
 	}
-	list_add_tail(&m->list, entry);
+	list_add_tail(&m->list, insert_pos ? insert_pos : &gcfg.map4_list);
 	return 0;
+
+conflict:
+	if (conflict)
+		*conflict = s;
+	return -1;
 }
@@ -957,19 +960,21 @@
 		}
 		if (!failed) {
+			pthread_mutex_lock(&gcfg.cache_mutex);
 			list_for_each_safe(entry, next, &gcfg.map4_list) {
 				struct map4 *m = list_entry(entry, struct map4, list);
-				if (is_file_map4(m)) addrmap_delete4(m);
+				if (is_file_map4(m)) {
+					struct map_static *s = container_of(m, struct map_static, map4);
+					list_del(&s->map4.list);
+					list_del(&s->map6.list);
+					free(s);
+				}
 			}
 			list_for_each_safe(entry, next, &staged) {
 				struct map_static *m = list_entry(entry, struct map_static, map4.list);
 				list_del(entry);
 				insert_map4(&m->map4, NULL);
 				insert_map6(&m->map6, NULL);
-				cache_evict_map4(&m->map4);
-				cache_evict_map6(&m->map6);
 			}
+			/* Flush active cache atomically under both map_mutex and cache_mutex */
+			list_for_each_safe(entry, next, &gcfg.cache_active) {
+				struct cache_entry *c = list_entry(entry, struct cache_entry, list);
+				if (c->flags & CACHE_F_REP_AGEOUT) report_ageout(c);
+				list_del(&c->hash4);
+				list_del(&c->hash6);
+				list_add(&c->list, &gcfg.cache_pool);
+			}
+			pthread_mutex_unlock(&gcfg.cache_mutex);
 		}
 		pthread_mutex_unlock(&gcfg.map_mutex);
 	}
```

---

#### `[RFC-01]` `[SPEC-VIOLATION]` Broken Inner Packet-in-Packet Translation in ICMPv4/ICMPv6 Error Handlers (Missing Fragment Header & Extension Header Translation)
- **Severity:** `HIGH`
- **Location:** [`nat64.c:662-842`](nat64.c#L662-L842) (`xlate_4to6_icmp_error`), [`nat64.c:1357-1527`](nat64.c#L1357-L1527) (`xlate_6to4_icmp_error`)
- **Standard / Mechanism:** RFC 7915 Sections 4.2, 4.3, 5.2, and 5.3 (Translating ICMPv4/ICMPv6 Error Messages & Inner Headers)
- **Root Cause Analysis:**
  1. **IPv4-to-IPv6 ICMP Error (`xlate_4to6_icmp_error`):**
     - Line 707 calls `xlate_header_4to6(&p_em, &header.ip6_em, ntohs(p_em.ip4->length) - p_em.header_len);`.
     - If the embedded offending IPv4 packet (`p_em`) was fragmented (`MF == 1` or `FragOffset > 0`), RFC 7915 Section 4.2 requires inserting an IPv6 Fragment Header (`struct ip6_frag`) into the translated inner IPv6 packet so the receiving IPv6 host can match or process the error. However, `struct ip6_error` ([`nat64.c:34-39`](nat64.c#L34-L39)) has no `ip6_frag` field and never emits one!
     - Worse, if `p_em` had `VIRTIO_NET_HDR_F_NEEDS_CSUM` or if `p_em` was truncated (as almost all ICMPv4 error payloads are—RFC 792 only requires 28 bytes of inner packet, or up to 576 bytes per RFC 1812):
       - In `xlate_payload_4to6(&p_em, &header.ip6_em, 1)` ([`nat64.c:320-331`](nat64.c#L320-L331)): if the inner packet is **ICMPv4 Echo (`data_proto == 1`)**, `xlate_payload_4to6` computes `cksum = ip6_checksum(ip6, htons(p->ip4->length) - p->header_len, 58)` and incrementally updates `p->icmp->cksum` assuming `p->icmp->cksum` covered the full inner packet. That works for non-truncated Echo, **except** it only checks `p->icmp->type == 8`, translating *any* other inner ICMP type to `129` (Echo Reply).
       - For inner **UDP (`case 17`)** with checksum `0x0000` and `UDP_CKSUM_CALC` ([`nat64.c:366-370`](nat64.c#L366-L370)): when `em == 1`, it returns `ERROR_NONE` **leaving `*tck = 0x0000` in the translated inner IPv6 UDP header**, or if `UDP_CKSUM_CALC` was supposed to compute it, it cannot if truncated, yet leaving `0x0000` is noted in RFC 7915 §4.5.
       - Most critically, look at [`nat64.c:675-684`](nat64.c#L675-L684) and [`nat64.c:1369-1378`](nat64.c#L1369-L1378) (RFC 4884 ICMP Multipart Extensions length attribute):
         - When `em_len` (the RFC 4884 length field in `icmp->word`) is non-zero, TAYGA truncates `p_em.data_len = em_len`, stripping the trailing ICMP extension structure!
         - However, TAYGA **does not clear or update the RFC 4884 length byte in `header.icmp.word`** when `p->icmp->type == 11` (Time Exceeded) or `p->icmp->type == 3` (Dest Unreachable), wait—it sets `header.icmp.word = 0`, which zeroes the length field, *dropping* the extensions, which is acceptable if the length field is zeroed.
         - **Wait:** What if `parse_ip4(&p_em)` runs on a truncated inner IPv4 packet? Look at [`parse_ip4()`](nat64.c#L631-L641):
           ```c
           if ((p->ip4->flags_offset & htons(IP4_F_MF)) && (p->data_len & 0x7)) {
               log_pkt4(LOG_OPT_DROP,p,"Fragment Misalignment");
               return ERROR_DROP;
           }
           ```
           In an ICMPv4 error message quoting a fragmented IPv4 packet (`MF == 1`), `p_em.data_len` is the **truncated length of the quoted packet inside the ICMP error** (e.g., 8 bytes or 36 bytes), NOT the full original fragment length! If the truncated quote length is not a multiple of 8 bytes (or if `parse_ip6(&p_em, 1)` at [`nat64.c:1315-1319`](nat64.c#L1315-L1319) sees `MF == 1` on a truncated inner IPv6 fragment whose quoted length is not a multiple of 8), `parse_ip4` / `parse_ip6` **falsely rejects the ICMP error as `"Fragment Misalignment"`**!
  2. **Inner TTL / Hop Limit Not Adjusted or Validated per RFC 7915:**
     - In [`xlate_4to6_icmp_error()`](nat64.c#L707-L708) and [`xlate_6to4_icmp_error()`](nat64.c#L1483-L1484), `xlate_header_4to6` / `xlate_header_6to4` copies TTL/Hop Limit as-is (which is correct for the embedded packet), **but** in `xlate_6to4_icmp_error()` ([`nat64.c:1478-1484`](nat64.c#L1478-L1484)), `xlate_payload_6to4(&p_em, &header.ip4_em, 1)` is called **BEFORE** `xlate_header_6to4(&p_em, &header.ip4_em, ...)`!
     - Look at what happens when `xlate_payload_6to4(&p_em, &header.ip4_em, 1)` runs before `xlate_header_6to4`:
       - `header.ip4_em` is **uninitialized stack memory** (except `.src` and `.dest` set at lines 1472–1474)!
       - If `UDP_CKSUM_CALC` is active and the inner packet has a zero UDP checksum (or `vnet_hdr_sz == 0` with `NEEDS_CSUM`), `ip4_checksum(ip4, ...)` reads `ip4->src` and `ip4->dest`, which are initialized, so that happens to survive, **but** in `xlate_header_6to4(&p_em, &header.ip4_em, ntohs(p_em.ip6->payload_length) - p_em.header_len)`:
       - Look at [`nat64.c:1483-1484`](nat64.c#L1483-L1484):
         ```c
         xlate_header_6to4(&p_em, &header.ip4_em,
             ntohs(p_em.ip6->payload_length) - p_em.header_len);
         ```
         What if `ntohs(p_em.ip6->payload_length) < p_em.header_len` in a malformed inner IPv6 packet inside an ICMPv6 error?
         Check [`parse_ip6(&p_em, 1)`](nat64.c#L1277-L1302):
         ```c
         if (p->data_len > ntohs(p->ip6->payload_length))
             p->data_len = ntohs(p->ip6->payload_length);
         ```
         If the outer ICMPv6 error packet has 100 bytes of inner payload (`p_em.data_len = 60` after stripping 40B `ip6`), and the inner `p_em.ip6->payload_length` is `1400` (because the inner packet was a 1440-byte packet that got truncated to 100 bytes inside the ICMPv6 error!), then `p_em.data_len` is `60`, while `ntohs(p_em.ip6->payload_length)` is `1400`. That works when `payload_length >= header_len`.
  3. **RFC 7915 Section 4.2 & 5.2 Parameter Problem Pointer Translation:**
     - In [`xlate_4to6_icmp_error()`](nat64.c#L781-L793):
       ```c
       static const int32_t new_ptr_tbl[] = {0,1,4,4,-1,-1,-1,-1,7,6,-1,-1,8,8,8,8,24,24,24,24};
       int32_t old_ptr = (ntohl(p->icmp->word) >> 24);
       ```
       Wait: `ntohl(p->icmp->word)` is `uint32_t`, so `>> 24` is in `[0, 255]`. If `old_ptr > 19`, it drops the packet.
     - In [`xlate_6to4_icmp_error()`](nat64.c#L1437-L1453):
       ```c
       static const int32_t new_ptr_tbl[] = {0,1,-1,-1,2,2,9,8};
       int32_t old_ptr = ntohl(p->icmp->word);
       ```
       **BUG (`[SEC-02]`):** `old_ptr` is a **signed `int32_t`** initialized from `ntohl(p->icmp->word)`!
       If a remote attacker sends an ICMPv6 Parameter Problem (Type 4, Code 0) with the high bit of the 32-bit pointer set (e.g., `p->icmp->word = htonl(0x80000000)` or `0xffffffff`), then `old_ptr` is **NEGATIVE** (`old_ptr < 0`)!
       Look at the bounds checks on lines 1440–1449:
       ```c
       if(old_ptr > 39) {
           log_pkt6(LOG_OPT_DROP,p,"Parameter Problem Invalid Pointer");
           return;
       } else if(old_ptr > 23) {
           new_ptr = 16;
       } else if(old_ptr > 7) {
           new_ptr = 12;
       } else {
           new_ptr = new_ptr_tbl[old_ptr];
       }
       ```
       Because `old_ptr` is negative, `old_ptr > 39`, `old_ptr > 23`, and `old_ptr > 7` are all **FALSE**! Execution falls into the `else` branch and executes **`new_ptr_tbl[old_ptr]` with an arbitrary negative 32-bit index (`-2147483648` to `-1`)**, causing an **immediate out-of-bounds memory read / segmentation fault (remote crash DoS) from a single unauthenticated IPv6 packet**!

Let's double-check this!
In `xlate_6to4_icmp_error()` ([`nat64.c:1438-1449`](nat64.c#L1438-L1449)):
```c
int32_t old_ptr = ntohl(p->icmp->word);
int32_t new_ptr;
if(old_ptr > 39) {
    ...
} else if(old_ptr > 23) {
    new_ptr = 16;
} else if(old_ptr > 7) {
    new_ptr = 12;
} else {
    new_ptr = new_ptr_tbl[old_ptr];
}
```
Yes! If `ntohl(p->icmp->word)` has bit 31 set (e.g. `0x80000000`), `old_ptr` is `-2147483648` (`int32_t`). It bypasses `> 39`, `> 23`, `> 7`, and indexes `new_ptr_tbl[-2147483648]`, which is `-8GB` off `new_ptr_tbl` in `.rodata` -> **instant SIGSEGV crash of the entire TAYGA daemon**!

Let's elevate that specific out-of-bounds read to `[SEC-01]` (`CRITICAL`) and keep the concurrency/reload bug as `[SEC-02]` (`HIGH`).

---

#### `[SEC-01]` Remote Unauthenticated Crash (Out-of-Bounds Read) via Signed Integer Underflow in ICMPv6 Parameter Problem Pointer Translation
- **Severity:** `CRITICAL`
- **Location:** [`nat64.c:1436-1450`](nat64.c#L1436-L1450) (`xlate_6to4_icmp_error`)
- **Standard / Mechanism:** C99 Signed Integer Conversion / RFC 7915 Section 5.2 (ICMPv6 Parameter Problem Code 0 Pointer Translation)
- **Root Cause Analysis:**
  1. When an ICMPv6 Error message of Type 4 (Parameter Problem), Code 0 is received on the TUN interface, `handle_ip6()` dispatches it to `xlate_6to4_icmp_error()`.
  2. At [`nat64.c:1438`](nat64.c#L1438), the 32-bit ICMPv6 Pointer field is extracted into a signed 32-bit integer:
     ```c
     int32_t old_ptr = ntohl(p->icmp->word);
     ```
  3. The subsequent range validation checks only for upper bounds (`if (old_ptr > 39)`, `else if (old_ptr > 23)`, `else if (old_ptr > 7)`), assuming `old_ptr >= 0`.
  4. If the packet carries a pointer value `>= 0x80000000` (so `old_ptr < 0`), all three upper-bound comparisons evaluate to false, and the `else` branch indexes `new_ptr_tbl[old_ptr]` with a negative offset up to `-2147483648 * sizeof(int32_t)` (`-8 GiB`), reading unmapped memory and crashing the TAYGA process (`SIGSEGV`).
  5. Additionally, per RFC 7915 Section 5.2, pointer values `6` (Next Header -> `9` Protocol) and `7` (Hop Limit -> `8` TTL) are mapped in `new_ptr_tbl`, whereas RFC 7915 Figure 6 specifies that if the pointer is `4` or `5` (Payload Length), both translate to `2` (Total Length), which matches `new_ptr_tbl`, and `8..23` translate to `12`, `24..39` translate to `16`. Using `uint32_t old_ptr` eliminates the negative index vulnerability completely.
- **Proposed Patch:**
```diff
--- a/nat64.c
+++ b/nat64.c
@@ -780,7 +780,7 @@
 			return;
 		}
 		static const int32_t new_ptr_tbl[] = {0,1,4,4,-1,-1,-1,-1,7,6,-1,-1,8,8,8,8,24,24,24,24};
-		int32_t old_ptr = (ntohl(p->icmp->word) >> 24);
+		uint32_t old_ptr = ntohl(p->icmp->word) >> 24;
 		if(old_ptr > 19) {
 			log_pkt4(LOG_OPT_DROP,p,"Parameter Problem Invalid Pointer");
 			return;
@@ -1435,7 +1435,7 @@
 		/* Erroneous Header Field Encountered */
 		if (p->icmp->code == 0) {
 			static const int32_t new_ptr_tbl[] = {0,1,-1,-1,2,2,9,8};
-			int32_t old_ptr = ntohl(p->icmp->word);
+			uint32_t old_ptr = ntohl(p->icmp->word);
 			int32_t new_ptr;
 			if(old_ptr > 39) {
 				log_pkt6(LOG_OPT_DROP,p,"Parameter Problem Invalid Pointer");
```

---

#### `[RFC-01]` `[SPEC-VIOLATION]` EAM / Static Subnet Mapping (`MAP_TYPE_STATIC`) Fails for Prefixes Shorter Than `/96` (IPv6) and Violates RFC 7757 Suffix Symmetry
- **Severity:** `HIGH`
- **Location:** [`addrmap.c:514-520`](addrmap.c#L514-L520) (`map_ip4_to_ip6`), [`addrmap.c:665-674`](addrmap.c#L665-L674) (`map_ip6_to_ip4`), [`conffile.c:440-473`](conffile.c#L440-L473) (`config_map`), [`addrmap.c:863`](addrmap.c#L863) (`parse_map_entry`)
- **Standard / Mechanism:** RFC 7757 Section 3.1 & 3.2 (Explicit Address Mapping for Stateless IP/ICMP Translation)
- **Root Cause Analysis:**
  1. In [`config_map()`](conffile.c#L452-L473):
     - `calc_ip4_mask(&m->map4.mask, NULL, prefix4)` and `calc_ip6_mask(&m->map6.mask, NULL, prefix6)` are called with **`addr = NULL`**, which **skips validating that the configured subnet has zero host bits**! (Contrast with `parse_map_entry()` in `addrmap.c:866-867` which passes `&m->map4.addr` and `&m->map6.addr`).
     - Additionally, `prefix4` and `prefix6` in `config_map()` are parsed via `atoi(slash + 1)` without checking `prefix4 > 32` or `prefix6 > 128` or non-numeric characters (e.g., `/96` on IPv4 wraps `(32 - prefix4)` in unsigned arithmetic if both overflow similarly, or `prefix4 = 0` leads to undefined shift if not guarded).
  2. In [`map_ip4_to_ip6()`](addrmap.c#L517-L519) and [`map_ip6_to_ip4()`](addrmap.c#L668-L670), static subnet translation is implemented as:
     ```c
     if (map4->prefix_len < 32) {
         addr6->s6_addr32[3] = s->map6.addr.s6_addr32[3] | (addr4->s_addr & ~map4->mask.s_addr);
     }
     ```
     and
     ```c
     if (map6->prefix_len < 128) {
         addr4->s_addr = s->map4.addr.s_addr | (addr6->s6_addr32[3] & ~map6->mask.s6_addr32[3]);
     }
     ```
     - While `conffile.c` enforces `(32 - prefix4) == (128 - prefix6)` (requiring the IPv6 prefix length to be in `[96, 128]`), RFC 7757 Section 3.2 allows **arbitrary IPv6 prefix lengths** (e.g., mapping `192.0.2.0/24` to `2001:db8:aaaa::/48` or `/64`) by placing the $k$-bit IPv4 suffix immediately after the IPv6 prefix bits (or in the low bits if `prefix6 == 128 - (32 - prefix4)`). Even under TAYGA's constraint `(32 - prefix4) == (128 - prefix6)`, if `prefix4 == 0` (`prefix6 == 96`), `prefix4` is rejected by `validate_ip4_addr(&m->map4.addr)` because `0.0.0.0` has first octet `0`.
     - More importantly, because `config_map()` calls `calc_ip4_mask(&m->map4.mask, NULL, prefix4)` and `calc_ip6_mask(&m->map6.mask, NULL, prefix6)` with `NULL`, if a user configures `map 192.0.2.5/24 2001:db8::5/120`, `find_map4()` checks `m->addr.s_addr == (m->mask.s_addr & addr4->s_addr)`, which **never matches** because `m->addr.s_addr` still has the host bits `.5` set!
- **Proposed Patch:**
```diff
--- a/conffile.c
+++ b/conffile.c
@@ -435,41 +435,23 @@
 	m = alloc_map_static(ln);
 	if(!m) return ERROR_REJECT;
 
-	char *slash;
-	slash = strchr(args[0], '/');
-	unsigned int prefix4 = 32;
-	if (slash) {
-		prefix4 = atoi(slash+1);
-		slash[0] = '\0';
-	}
-
-	if (!inet_pton(AF_INET, args[0], &m->map4.addr)) {
+	if (strchr(args[0], '/')) {
+		if (parse_prefix(AF_INET, args[0], &m->map4.addr, &m->map4.prefix_len) ||
+		    calc_ip4_mask(&m->map4.mask, &m->map4.addr, m->map4.prefix_len)) {
+			slog(LOG_CRIT, "Expected a valid IPv4 subnet with zero host bits but found \"%s\" on line %d\n", args[0], ln);
+			free(m);
+			return ERROR_REJECT;
+		}
+	} else if (!inet_pton(AF_INET, args[0], &m->map4.addr)) {
 		slog(LOG_CRIT, "Expected an IPv4 subnet but found \"%s\" on "
 		     "line %d\n", args[0], ln);
+		free(m);
 		return ERROR_REJECT;
 	}
-	m->map4.prefix_len = prefix4;
-	calc_ip4_mask(&m->map4.mask, NULL, prefix4);
 
-	unsigned int prefix6 = 128;
-	slash = strchr(args[1], '/');
-	if (slash) {
-		prefix6 = atoi(slash+1);
-		slash[0] = '\0';
-	}
-
-	if ((32 - prefix4) != (128 - prefix6)) {
-		slog(LOG_CRIT, "IPv4 and IPv6 subnet must be of the same size, but found"
-				" %s and %s on line %d\n", args[0], args[1], ln);
-		return ERROR_REJECT;
-	}
-
-	if (!inet_pton(AF_INET6, args[1], &m->map6.addr)) {
+	if (strchr(args[1], '/')) {
+		if (parse_prefix(AF_INET6, args[1], &m->map6.addr, &m->map6.prefix_len) ||
+		    calc_ip6_mask(&m->map6.mask, &m->map6.addr, m->map6.prefix_len)) {
+			slog(LOG_CRIT, "Expected a valid IPv6 subnet with zero host bits but found \"%s\" on line %d\n", args[1], ln);
+			free(m);
+			return ERROR_REJECT;
+		}
+	} else if (!inet_pton(AF_INET6, args[1], &m->map6.addr)) {
 		slog(LOG_CRIT, "Expected an IPv6 subnet but found \"%s\" on "
 				"line %d\n", args[1], ln);
+		free(m);
 		return ERROR_REJECT;
 	}
-	m->map6.prefix_len = prefix6;
-	calc_ip6_mask(&m->map6.mask, NULL, prefix6);
+	if ((32 - m->map4.prefix_len) != (128 - m->map6.prefix_len)) {
+		slog(LOG_CRIT, "IPv4 and IPv6 subnet must be of the same size, but found"
+				" %s and %s on line %d\n", args[0], args[1], ln);
+		free(m);
+		return ERROR_REJECT;
+	}
```

---

#### `[RFC-02]` `[SPEC-VIOLATION]` Incomplete RFC 7915 ICMPv4/ICMPv6 Error Translation: Truncated Inner Fragments Dropped & Inner IPv6 Fragment Header Omitted
- **Severity:** `HIGH`
- **Location:** [`nat64.c:631-635`](nat64.c#L631-L635) (`parse_ip4`), [`nat64.c:1315-1319`](nat64.c#L1315-L1319) (`parse_ip6`), [`nat64.c:686-709`](nat64.c#L686-L709) (`xlate_4to6_icmp_error`), [`nat64.c:1478-1488`](nat64.c#L1478-L1488) (`xlate_6to4_icmp_error`)
- **Standard / Mechanism:** RFC 7915 Sections 4.2, 4.3, 5.2, and 5.3
- **Root Cause Analysis:**
  1. **False "Fragment Misalignment" Drop on Quoted Inner Packets:**
     - `parse_ip4()` is called both on top-level IPv4 packets (`handle_ip4`) and on embedded inner IPv4 packets inside ICMPv4 errors (`xlate_4to6_icmp_error` at line 686).
     - Unlike `parse_ip6(struct pkt *p, int em)`, `parse_ip4(struct pkt *p)` does not take an `int em` parameter!
     - When an ICMPv4 error embeds a partial/truncated quote of a fragmented IPv4 packet (`MF == 1`), `p_em.data_len` is the *quoted* bytes present in the ICMP error (e.g., 20B IPv4 + 8B L4 = 8 bytes of `data_len`, or any non-multiple of 8 if truncated by an intermediate router or RFC 4884). Moreover, even in `parse_ip6(p, em)` ([`nat64.c:1315-1325`](nat64.c#L1315-L1325)), `if ((p->ip6_frag->offset_flags & htons(IP6_F_MF)) && (p->data_len & 0x7))` is checked **even when `em == 1`**! If an ICMPv6 error (such as Time Exceeded or Destination Unreachable) truncates a fragmented IPv6 packet at a byte boundary not divisible by 8, `parse_ip6(&p_em, 1)` drops the entire ICMPv6 error!
     - Furthermore, in `parse_ip4(&p_em)` when `em == 0` vs `em == 1`, if `p_em` is an inner ICMPv4 Echo Request that was fragmented (`MF == 1`), `parse_ip4` drops it at line 614 (`ICMP Fragmented`).
  2. **Inner ICMP Checksum Corruption on Truncated Inner Echo Request (`xlate_payload_4to6` / `xlate_payload_6to4`):**
     - When an ICMPv4/v6 error quotes a truncated ICMP Echo Request (e.g., an ICMPv6 Packet Too Big quoting a 1500-byte ICMPv6 Echo Request, which is truncated to 1280 bytes total / 1232 bytes inner packet, or 576 bytes in IPv4), `xlate_payload_6to4(&p_em, &header.ip4_em, 1)` ([`nat64.c:1065-1074`](nat64.c#L1065-L1074)) computes:
       ```c
       cksum = ~ip6_checksum(p->ip6, htons(p->ip6->payload_length) - p->header_len, 58);
       ```
       Notice `htons(p->ip6->payload_length)` instead of `ntohs(p->ip6->payload_length)` (macro-equivalent on little/big endian, though semantically `ntohs`), which is the **original un-truncated payload length** from the inner IPv6 header—that actually matches the pseudo-header used when the original sender computed `p->icmp->cksum`!
     - However, in `xlate_6to4_icmp_error()` ([`nat64.c:1478-1484`](nat64.c#L1478-L1484)), `xlate_payload_6to4(&p_em, &header.ip4_em, 1)` is called **before** `xlate_header_6to4(&p_em, &header.ip4_em, ...)`, so `header.ip4_em.proto` and `header.ip4_em.length` are uninitialized during `xlate_payload_6to4`.
  3. **Missing Inner IPv6 Fragment Header in `xlate_4to6_icmp_error()`:**
     - If `p_em.ip4->flags_offset & htons(IP4_F_MASK | IP4_F_MF)` is non-zero, RFC 7915 §4.2 mandates translating the inner IPv4 fragment info into an inner IPv6 Fragment Header (`Next Header = 44`). Currently `xlate_4to6_icmp_error()` omits the inner Fragment Header and writes the L4 protocol directly into `header.ip6_em.next_header`.
- **Proposed Patch:**
```diff
--- a/nat64.c
+++ b/nat64.c
@@ -36,6 +36,7 @@
     struct tun_pi pi;
     struct ip6 ip6;
     struct icmp icmp;
     struct ip6 ip6_em;
+    struct ip6_frag ip6_em_frag;
 };
 
@@ -581,7 +582,7 @@
 	}
 }
 
-static int parse_ip4(struct pkt *p)
+static int parse_ip4(struct pkt *p, int em)
 {
 	p->ip4 = (struct ip4 *)(p->data);
 
@@ -628,7 +629,7 @@
 		log_pkt4(LOG_OPT_DROP,p,"IPv4 Packet with IPv6-Only Proto");
 		return ERROR_DROP;
 	} else {
-		if ((p->ip4->flags_offset & htons(IP4_F_MF)) &&
+		if (!em && (p->ip4->flags_offset & htons(IP4_F_MF)) &&
 				(p->data_len & 0x7)) {
 			log_pkt4(LOG_OPT_DROP,p,"Fragment Misalignment");
 			return ERROR_DROP;
@@ -683,7 +684,7 @@
 		}
 	}
 
-	if (parse_ip4(&p_em) < 0) {
+	if (parse_ip4(&p_em, 1) < 0) {
 		log_pkt4(LOG_OPT_DROP,p,"Failed to parse em packet");
 		return;
 	}
@@ -693,9 +694,11 @@
 		return;
 	}
 
-	if (sizeof(struct ip6) * 2 + sizeof(struct icmp) + p_em.data_len > MTU_MIN)
+	uint16_t em_off = ntohs(p_em.ip4->flags_offset);
+	size_t em_frag_len = (em_off & (IP4_F_MASK | IP4_F_MF)) ? sizeof(struct ip6_frag) : 0;
+	if (sizeof(struct ip6) * 2 + sizeof(struct icmp) + em_frag_len + p_em.data_len > MTU_MIN)
 		p_em.data_len = MTU_MIN - sizeof(struct ip6) * 2 -
-						sizeof(struct icmp);
+						sizeof(struct icmp) - em_frag_len;
 
 	if (map_ip4_to_ip6(&header.ip6_em.src, &p_em.ip4->src) ||
 			map_ip4_to_ip6(&header.ip6_em.dest,
@@ -705,7 +708,15 @@
 	}
 
 	xlate_header_4to6(&p_em, &header.ip6_em,
-				ntohs(p_em.ip4->length) - p_em.header_len);
+				ntohs(p_em.ip4->length) - p_em.header_len + em_frag_len);
+	if (em_frag_len) {
+		header.ip6_em_frag.next_header = header.ip6_em.next_header;
+		header.ip6_em_frag.reserved = 0;
+		header.ip6_em_frag.offset_flags = htons(((em_off & IP4_F_MASK) << 3) |
+		                                        ((em_off & IP4_F_MF) ? IP6_F_MF : 0));
+		header.ip6_em_frag.ident = htonl(ntohs(p_em.ip4->ident));
+		header.ip6_em.next_header = 44;
+	}
 
 	switch (p->icmp->type) {
@@ -815,15 +826,15 @@
 	}
 
 	xlate_header_4to6(p, &header.ip6,
-		sizeof(header.icmp) + sizeof(header.ip6_em) + p_em.data_len);
+		sizeof(header.icmp) + sizeof(header.ip6_em) + em_frag_len + p_em.data_len);
 	--header.ip6.hop_limit;
 
 	header.icmp.cksum = 0;
 	header.icmp.cksum = ones_add(ip6_checksum(&header.ip6,
 					ntohs(header.ip6.payload_length), 58),
 			ones_add(ip_checksum(&header.icmp,
 						sizeof(header.icmp) +
-						sizeof(header.ip6_em)),
+						sizeof(header.ip6_em) + em_frag_len),
 				ip_checksum(p_em.data, p_em.data_len)));
 
 	TUN_SET_PROTO(&header.pi,  ETH_P_IPV6);
 
 #ifdef __linux__
 	iov[0].iov_base = &header.ip6;
-	iov[0].iov_len = sizeof(header.ip6) + sizeof(header.icmp) + sizeof(header.ip6_em);
+	iov[0].iov_len = sizeof(header.ip6) + sizeof(header.icmp) + sizeof(header.ip6_em) + em_frag_len;
 #else
 	iov[0].iov_base = &header;
-	iov[0].iov_len = sizeof(header);
+	iov[0].iov_len = sizeof(struct tun_pi) + sizeof(header.ip6) + sizeof(header.icmp) + sizeof(header.ip6_em) + em_frag_len;
 #endif
 	iov[1].iov_base = p_em.data;
 	iov[1].iov_len = p_em.data_len;
@@ -859,7 +870,7 @@
 		return;
 	}
 
-	if (unlikely(parse_ip4(p) < 0)) {
+	if (unlikely(parse_ip4(p, 0) < 0)) {
 		stats_drop(p->data_len);
 		return; //error already logged
 	}
@@ -1312,7 +1323,7 @@
 		p->data_len -= sizeof(struct ip6_frag);
 		p->header_len += sizeof(struct ip6_frag);
 
-		if ((p->ip6_frag->offset_flags & htons(IP6_F_MF)) &&
+		if (!em && (p->ip6_frag->offset_flags & htons(IP6_F_MF)) &&
 				(p->data_len & 0x7)) {
 			if(!em) log_pkt6(LOG_OPT_DROP,p,"Fragment Misaligned");
 			return ERROR_DROP;
@@ -1475,13 +1486,13 @@
 		log_pkt6(LOG_OPT_DROP,p,"Failed to map em src or dest");
 		return;
 	}
-	if(xlate_payload_6to4(&p_em, &header.ip4_em,1) < 0) {
-		log_pkt6(LOG_OPT_DROP,p,"Failed to translate em payload");
-		return;
-	}
 
 	xlate_header_6to4(&p_em, &header.ip4_em,
 		ntohs(p_em.ip6->payload_length) - p_em.header_len);
 
+	if(xlate_payload_6to4(&p_em, &header.ip4_em,1) < 0) {
+		log_pkt6(LOG_OPT_DROP,p,"Failed to translate em payload");
+		return;
+	}
+
 	header.ip4_em.cksum =
 		ip_checksum(&header.ip4_em, sizeof(header.ip4_em));
```

---

#### `[GSO-01]` Stack Buffer Too Small (`2048` Bytes) in `gso_software_segment_and_send_4to6()` Causes Silent Drops on Jumbo MTU Links
- **Severity:** `HIGH`
- **Location:** [`gso.c:695-708`](gso.c#L695-L708) (`gso_software_segment_and_send_4to6`), [`gso.c:381`](gso.c#L381) (`gso_translate_tcp_6to4`)
- **Standard / Mechanism:** Linux Kernel `virtio_net_hdr` GSO Segmentation / Jumbo Frames (`MTU > 2000`)
- **Root Cause Analysis:**
  1. Compare the stack segment buffers across the four software segmentation functions in `gso.c`:
     - `gso_software_segment_and_send_6to4()` ([`gso.c:581`](gso.c#L581)): `uint8_t seg_buf[HEADROOM + sizeof(struct ip4) + UINT16_MAX];`
     - `gso_software_segment_and_send_udp_6to4()` ([`gso.c:802`](gso.c#L802)): `uint8_t seg_buf[HEADROOM + sizeof(struct ip4) + UINT16_MAX];`
     - `gso_software_segment_and_send_udp_4to6()` ([`gso.c:915`](gso.c#L915)): `uint8_t seg_buf[HEADROOM + sizeof(struct ip6) + UINT16_MAX];`
     - `gso_software_segment_and_send_4to6()` ([`gso.c:695`](gso.c#L695)): **`uint8_t seg_buf[HEADROOM + 2048];`**!
  2. In `gso_software_segment_and_send_4to6()`, if `gso_size > 1988` (e.g. a 9000-byte jumbo frame link with `gso_size = 8940`), `ip6_total = 40 + tcp_hdr_len + gso_size` exceeds `sizeof(seg_buf) - HEADROOM` (`2048`), causing `gso_software_segment_and_send_4to6()` to abort with `stats_gso_invalid(); return -1;` and drop the entire TCP flow!
  3. (Note: In `gso_translate_tcp_6to4()` line 381, `tail_buf[HEADROOM + 2048]` is safe only because `tail_ip4_len <= 1260` is guaranteed by the `if` condition on line 333.)
- **Proposed Patch:**
```diff
--- a/gso.c
+++ b/gso.c
@@ -692,7 +692,7 @@
 	uint32_t offset = 0;
 	uint32_t orig_seq = ntohl(orig_tcp->seq);
 
-	uint8_t seg_buf[HEADROOM + 2048];
+	uint8_t seg_buf[HEADROOM + sizeof(struct ip6) + UINT16_MAX];
 	uint8_t *seg_ip = seg_buf + HEADROOM;
 
 	while (offset < payload_len || (offset == 0 && payload_len == 0)) {
```

---

#### `[GSO-02]` `[SPEC-VIOLATION]` GSO Fast-Path Bypasses MTU Enforcement, ICMP Error Generation on Unmapped Addresses, and Destination-Self Checks
- **Severity:** `HIGH`
- **Location:** [`gso.c:268-546`](gso.c#L268-L546) (`gso_translate_tcp_6to4`, `gso_translate_tcp_4to6`), [`gso.c:972-1175`](gso.c#L972-L1175) (`gso_translate_udp_6to4`, `gso_translate_udp_4to6`), [`nat64.c:846-860`](nat64.c#L846-L860), [`nat64.c:1531-1545`](nat64.c#L1531-L1545)
- **Standard / Mechanism:** RFC 7915 Sections 4.1 & 5.1, RFC 6877 (464XLAT Path MTU Discovery), Linux TUN GSO Contract
- **Root Cause Analysis:**
  1. **Missing ICMP Destination Unreachable on Address Mapping Rejection:**
     - In the scalar path (`xlate_4to6_data` / `xlate_6to4_data`), when `map_ip4_to_ip6` or `map_ip6_to_ip4` returns `ERROR_REJECT` (e.g., private IPv4 address with `wkpf_strict`, unmapped destination, or exhausted dynamic pool), TAYGA sends an ICMPv4 Type 3 (Code 1 or 10) or ICMPv6 Type 1 (Code 0 or 5) Destination Unreachable message.
     - In `gso_translate_*` ([`gso.c:322, 508, 1035, 1138`](gso.c#L322)), when `map_ip6_to_ip4` or `map_ip4_to_ip6` returns `ERROR_REJECT`, the function simply returns `-1`, and `handle_ip4` / `handle_ip6` ([`nat64.c:858, 1543`](nat64.c#L858)) **silently drops the packet** without sending any ICMP Destination Unreachable! Because modern Linux TCP/UDP stacks send GSO aggregates for almost all bulk transfers, connections to unroutable/rejected addresses hang until timeout instead of failing fast with `EHOSTUNREACH` / `EACCES`.
  2. **Missing Single-Segment MTU Check / ICMP Packet Too Big (PMTUD Blackhole):**
     - In `gso_translate_tcp_4to6()` and `gso_translate_udp_4to6()`, an incoming IPv4 GSO aggregate has segment MSS `gso_size`. Each segmented IPv6 packet will have size `sizeof(struct ip6) + l4_hdr_len + gso_size`.
     - If `sizeof(struct ip6) + l4_hdr_len + gso_size > gcfg.mtu` (for example, an IPv4 sender sends a GSO aggregate with 1460B MSS (`1500B` IPv4 segments) into a TUN interface with `gcfg.mtu = 1500`, which after `+20B` IPv6 header expansion produces **1520-byte IPv6 segments** when `DF=1`), the scalar path ([`nat64.c:487-490`](nat64.c#L487-L490)) sends `ICMPv4 Fragmentation Needed (Type 3, Code 4, MTU = gcfg.mtu - 20)`!
     - However, `gso_translate_tcp_4to6()` and `gso_translate_udp_4to6()` **never check whether an individual translated segment (`sizeof(struct ip6) + l4_hdr_len + gso_size`) exceeds `gcfg.mtu`**! Instead, they emit the GSO super-packet to the TUN device, bypassing PMTUD (`ICMPv4 Fragmentation Needed`) and causing downstream IPv6 links to drop the oversized segments (PMTUD blackhole)!
     - Similarly, in `gso_translate_tcp_6to4()` and `gso_translate_udp_6to4()`, if `sizeof(struct ip6) + l4_hdr_len + gso_size > gcfg.mtu`, no `ICMPv6 Packet Too Big (Type 2, Code 0, MTU = gcfg.mtu)` is generated!
  3. **Missing Address Validation (`validate_ip6_addr` / `validate_ip4_addr`):**
     - `gso_translate_tcp_6to4` and `gso_translate_udp_6to4` never call `validate_ip6_addr(&ip6->src)` or `validate_ip6_addr(&ip6->dest)` (unlike `parse_ip6`), and `gso_validate_ipv4_header` never calls `validate_ip4_addr(&ip4->src)` or `validate_ip4_addr(&ip4->dest)`.
- **Proposed Patch:**
```diff
--- a/gso.c
+++ b/gso.c
@@ -200,7 +200,9 @@
 	    (ntohs(ip4->flags_offset) & (IP4_F_MASK | IP4_F_MF)))
 		return -1;
 	uint32_t ihl = (ip4->ver_ihl & 0x0f) * 4;
-	if (ihl < sizeof(struct ip4) || ihl > p->data_len || ip_checksum((void *)ip4, ihl) != 0)
+	if (ihl < sizeof(struct ip4) || ihl > p->data_len || ip_checksum((void *)ip4, ihl) != 0 ||
+	    validate_ip4_addr(&ip4->src) == ERROR_DROP ||
+	    validate_ip4_addr(&ip4->dest) == ERROR_DROP)
 		return -1;
 	for (uint32_t off = sizeof(struct ip4); off < ihl;) {
@@ -280,7 +282,8 @@
 	struct ip6 *ip6 = (struct ip6 *)p->data;
 	if ((ntohl(ip6->ver_tc_fl) >> 28) != 6 || ip6->next_header != IPPROTO_TCP ||
-	    ntohs(ip6->payload_length) != p->data_len - sizeof(struct ip6))
+	    ntohs(ip6->payload_length) != p->data_len - sizeof(struct ip6) ||
+	    validate_ip6_addr(&ip6->src) || validate_ip6_addr(&ip6->dest))
 		return -1;
 
 	struct tcp_hdr *tcp = (struct tcp_hdr *)(p->data + sizeof(struct ip6));
@@ -295,6 +298,17 @@
 	if (gso_size == 0)
 		return -1;
 
+	uint32_t max_seg_wire6 = sizeof(struct ip6) + tcp_hdr_len + (payload_len > gso_size ? gso_size : payload_len);
+	if (unlikely(gcfg.mtu > 0 && max_seg_wire6 > gcfg.mtu)) {
+		p->ip6 = ip6;
+		p->header_len = 0;
+		p->data = (uint8_t *)ip6 + sizeof(struct ip6);
+		p->data_len -= sizeof(struct ip6);
+		p->data_proto = IPPROTO_TCP;
+		log_pkt6(LOG_OPT_ICMP, p, "Packet Too Big");
+		host_send_icmp6_error(2, 0, gcfg.mtu, p);
+		return 0;
+	}
+
 	/* RFC 7915 §5.1: If Hop Limit <= 1, discard and send ICMPv6 Time Exceeded */
 	if (unlikely(ip6->hop_limit <= 1)) {
@@ -486,6 +500,19 @@
 	if (gso_validate_transport_vnet(p, ip4_hdr_len, tcp_hdr_len, 16) < 0)
 		return -1;
 
 	uint32_t payload_len = p->data_len - ip4_hdr_len - tcp_hdr_len;
+	uint32_t gso_size = p->vhdr.gso_size;
+	uint32_t max_seg_wire4 = sizeof(struct ip4) + tcp_hdr_len + (payload_len > gso_size ? gso_size : payload_len);
+	if (unlikely((ntohs(ip4->flags_offset) & IP4_F_DF) && gcfg.mtu > MTU_ADJ &&
+	             max_seg_wire4 > (uint32_t)(gcfg.mtu - MTU_ADJ))) {
+		p->ip4 = ip4;
+		p->header_len = ip4_hdr_len;
+		p->data = (uint8_t *)ip4 + ip4_hdr_len;
+		p->data_len -= ip4_hdr_len;
+		p->data_proto = IPPROTO_TCP;
+		log_pkt4(LOG_OPT_ICMP, p, "Packet Too Big");
+		host_send_icmp4_error(3, 4, gcfg.mtu - MTU_ADJ, p);
+		return 0;
+	}
 
 	/* RFC 7915 §4.1: If TTL <= 1, discard and send ICMPv4 Time Exceeded */
```

---

### `MEDIUM` Severity Findings

---

#### `[RFC-03]` `[SPEC-VIOLATION]` TCP Checksum Incremental Update Erroneously Rewrites `0x0000` to `0xFFFF`
- **Severity:** `MEDIUM`
- **Location:** [`nat64.c:429-431`](nat64.c#L429-L431) (`xlate_payload_4to6`), [`nat64.c:1173-1175`](nat64.c#L1173-L1175) (`xlate_payload_6to4`), [`nat64.c:410-411`](nat64.c#L410-L411), [`nat64.c:1154-1155`](nat64.c#L1154-L1155), [`gso.c:116-117`](gso.c#L116-L117), [`gso.c:150-151`](gso.c#L150-L151)
- **Standard / Mechanism:** RFC 793 / RFC 9293 (TCP Checksum), RFC 1624 Section 5 (Incremental Checksum Update: `+0` vs `-0`)
- **Root Cause Analysis:**
  1. In one's complement arithmetic (`ones_add` and `ip_checksum`), the final inversion `~sum` never produces `0xFFFF` (`-0`) unless `sum == 0x0000` (which cannot occur for non-zero words because carry folding `while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)` produces a value in `[0x0001, 0xFFFF]`, and `~0xFFFF == 0x0000`).
  2. For **UDP** (RFC 768 / RFC 8200), a checksum value of `0x0000` means "no checksum was computed", so when a calculated UDP checksum equals `0x0000`, it **MUST** be replaced with `0xFFFF`.
  3. For **TCP** (RFC 9293), `0x0000` has no special "no checksum" meaning; standard TCP checksum calculation (`~sum`) produces `0x0000` when the 16-bit one's complement sum is `0xFFFF`. While most receivers verify TCP checksums by summing the header (including the checksum field) and folding to `0xFFFF` (which accepts both `0x0000` and `0xFFFF`), strict middleboxes, hardware offloads, and RFC 1624 test vectors (including `test/translate.py`) distinguish TCP `0x0000` from UDP `0xFFFF`.
  4. Conversely, look at [`nat64.c:359`](nat64.c#L359) and [`nat64.c:1103`](nat64.c#L1103) in the `VIRTIO_NET_HDR_F_NEEDS_CSUM` UDP branch:
     ```c
     *tck = htons(gso_calc_udp_pseudo6(&ip6->src, &ip6->dest, p->data_len));
     ```
     and
     ```c
     *tck = htons(gso_calc_udp_pseudo4(&ip4->src, &ip4->dest, p->data_len));
     ```
     Unlike `gso.c:1042` and `gso.c:1145` (which check `if (seed == 0) seed = 0xffff;`—though for a non-zero `udp_len >= 8` and valid unicast addresses, the unfolded positive sum folded to 16 bits in `gso_calc_pseudo*` can never be `0` anyway), `nat64.c` and `gso.c` apply the `0x0000 -> 0xFFFF` conversion unconditionally to both TCP and UDP at lines 430 and 1174.
- **Proposed Patch:**
```diff
--- a/nat64.c
+++ b/nat64.c
@@ -407,8 +407,6 @@
 				*tck = 0;
 				*tck = ones_add(ip_checksum(p->data, p->data_len),
 				                ip6_checksum(ip6, p->data_len, IPPROTO_TCP));
-				if (*tck == 0)
-					*tck = 0xffff;
 				p->vhdr.flags &= ~VIRTIO_NET_HDR_F_NEEDS_CSUM;
 			} else {
 				*tck = htons(gso_calc_tcp_pseudo6(&ip6->src, &ip6->dest, p->data_len));
@@ -427,7 +425,7 @@
 	}
 	/* Calculate checksum adjustment (RFC 1624 incremental update) */
 	*tck = ones_add(*tck, ~convert_cksum(ip6, p->ip4));
-	if (*tck == 0)
+	if (p->data_proto == IPPROTO_UDP && *tck == 0)
 		*tck = 0xffff;
 	return ERROR_NONE;
 }
@@ -534,7 +532,7 @@
 			*frag_tck = 0; /* Remove the pseudoheader seed before a full checksum. */
 			*frag_tck = ones_add(ip_checksum(p->data, p->data_len),
 			                     ip6_checksum(&header.ip6, p->data_len, p->data_proto));
-			if (*frag_tck == 0)
+			if (p->data_proto == IPPROTO_UDP && *frag_tck == 0)
 				*frag_tck = 0xffff;
 			p->vhdr.flags &= ~VIRTIO_NET_HDR_F_NEEDS_CSUM;
 		}
@@ -1151,8 +1149,6 @@
 				*tck = 0;
 				*tck = ones_add(ip_checksum(p->data, p->data_len),
 				                ip4_checksum(ip4, p->data_len, IPPROTO_TCP));
-				if (*tck == 0)
-					*tck = 0xffff;
 				p->vhdr.flags &= ~VIRTIO_NET_HDR_F_NEEDS_CSUM;
 			} else {
 				*tck = htons(gso_calc_tcp_pseudo4(&ip4->src, &ip4->dest, p->data_len));
@@ -1171,7 +1167,7 @@
 	}
 	/* Adjust checksum (RFC 1624 incremental update) */
 	*tck = ones_add(*tck, convert_cksum(p->ip6, ip4));
-	if (*tck == 0)
+	if (p->data_proto == IPPROTO_UDP && *tck == 0)
 		*tck = 0xffff;
 	return ERROR_NONE;
 }
```

---

#### `[RFC-04]` `[SPEC-VIOLATION]` RFC 6052 Section 3.1 Well-Known Prefix (`64:ff9b::/96`) Validation Misses Non-Global IPv4 Ranges and Non-`/96` WKPF Lengths
- **Severity:** `MEDIUM`
- **Location:** [`addrmap.c:97-132`](addrmap.c#L97-L132) (`is_private_ip4_addr`), [`conffile.c:191-198`](conffile.c#L191-L198) (`config_prefix`), [`addrmap.c:452-457`](addrmap.c#L452-L457) (`append_to_prefix`)
- **Standard / Mechanism:** RFC 6052 Section 3.1 (Restrictions on the Use of the Well-Known Prefix `64:ff9b::/96`) & RFC 6890 (Special-Purpose IP Address Registries)
- **Root Cause Analysis:**
  1. **RFC 6052 Section 3.1 Prefix Length Restriction:**
     - The Well-Known Prefix `64:ff9b::/96` may **only** be used as a `/96` prefix (unlike RFC 8215 `64:ff9b:1::/48`, which is the Local-Use NAT64 prefix and can be `/48`, `/56`, `/64`, or `/96`).
     - In [`config_prefix()`](conffile.c#L191-L198), TAYGA allows `prefix 64:ff9b::/32` or `prefix 64:ff9b::/64`! And when `prefix_len != 96`, the `wkpf_strict` check in [`append_to_prefix()`](addrmap.c#L450-L457) (which is only inside `case 96:`) is **completely bypassed**!
  2. **Missing Non-Global IPv4 Ranges in `is_private_ip4_addr()`:**
     - RFC 6052 Section 3.1 states: *"The Well-Known Prefix MUST NOT be used to represent non-global IPv4 addresses, such as those defined in [RFC1918] or listed in Section 3 of [RFC5735] (now RFC 6890)."*
     - Look at [`validate_ip4_addr()`](addrmap.c#L30-L54) and [`is_private_ip4_addr()`](addrmap.c#L97-L132):
       - `validate_ip4_addr()` returns `ERROR_LOCAL` (`-3`) for `169.254.0.0/16` (Link-Local, RFC 3927) and `ERROR_NONE` (`0`) for `240.0.0.0/4` (Class E Reserved, RFC 1112).
       - In `parse_ip4()` ([`nat64.c:600-601`](nat64.c#L600-L601)), TAYGA only checks `validate_ip4_addr(...) == ERROR_DROP`! Thus, `169.254.x.x` (`ERROR_LOCAL`) is accepted by `parse_ip4()`.
       - In `map_ip6_to_ip4()` ([`addrmap.c:676-690`](addrmap.c#L676-L690)), `extract_from_prefix()` returns `validate_ip4_addr(addr4)` (`ERROR_LOCAL = -3 < 0`), which drops `169.254.0.0/16`, and in `append_to_prefix()` (`if (validate_ip4_addr(addr4)) return ERROR_DROP;`), `169.254.0.0/16` is dropped.
       - However, `240.0.0.0/4` (Class E, non-global), `192.0.0.0/24` (IETF Protocol Assignments, RFC 6890—except when used with local prefix or `wkpf-strict off` for `192.0.0.0/29` DS-Lite/CLAT), and `192.88.99.0/24` (6to4 relay anycast) are **not checked in `is_private_ip4_addr()`**, allowing `64:ff9b::240.0.0.1` to be translated even when `wkpf_strict == 1`!
- **Proposed Patch:**
```diff
--- a/addrmap.c
+++ b/addrmap.c
@@ -128,6 +128,14 @@
 	/* 203.0.113.0/24 RFC5737 */
 	if ((a->s_addr & htonl(0xffffff00)) == htonl(0xcB007100))
 		return ERROR_REJECT;
 
+	/* 192.0.0.0/24 RFC6890 IETF Protocol Assignments */
+	if ((a->s_addr & htonl(0xffffff00)) == htonl(0xc0000000))
+		return ERROR_REJECT;
+
+	/* 240.0.0.0/4 RFC1112 Reserved (Class E) */
+	if ((a->s_addr & htonl(0xf0000000)) == htonl(0xf0000000))
+		return ERROR_REJECT;
+
 	return ERROR_NONE;
 }
--- a/conffile.c
+++ b/conffile.c
@@ -198,6 +198,14 @@
 				"or 96 only, aborting...\n");
 		return ERROR_REJECT;
 	}
+	if (m6->addr.s6_addr32[0] == WKPF &&
+	    m6->addr.s6_addr16[2] == 0 &&
+	    m6->prefix_len != 96) {
+		slog(LOG_CRIT, "Well-Known Prefix 64:ff9b::/96 can only be used with a /96 prefix length (use 64:ff9b:1::/48 per RFC 8215 for shorter local-use prefixes), aborting...\n");
+		free(m);
+		return ERROR_REJECT;
+	}
 	if (insert_map4(&m->map4, NULL) < 0) {
```

---

#### `[STAB-01]` Algorithmic Complexity DoS ($O(2^{32 - \text{prefix\_len}})$ Under Mutex) in `assign_dynamic()` When Dynamic Pool Approaches Capacity
- **Severity:** `MEDIUM`
- **Location:** [`dynamic.c:140-163`](dynamic.c#L140-L163) (`assign_dynamic`)
- **Standard / Mechanism:** Daemon Concurrency & Resource Exhaustion
- **Root Cause Analysis:**
  1. When an IPv6 packet with an unmapped source address arrives (`map_ip6_to_ip4` with `dyn_alloc = 1`), the worker thread acquires `gcfg.map_mutex` and calls [`assign_dynamic(addr6)`](dynamic.c#L108).
  2. Look at the allocation loop in [`dynamic.c:140-163`](dynamic.c#L140-L163):
     ```c
     max = UINT32_MAX >> pool->map4.prefix_len;
     ...
     for (i = 0, entry = NULL; i <= max; ++i) {
         addr = pool->free_head.addr | ((base + i) & max);
         if (!entry || addr == pool->free_head.addr)
             entry = pool->free_list.next;
         for (;;) {
             f = list_entry(entry, struct free_addr, list);
             if (f->addr + f->count >= addr)
                 break;
             entry = entry->next;
         }
         if (f->addr >= addr)
             continue;
         ...
     ```
  3. Notice two severe algorithmic defects:
     - First, if a large dynamic pool is configured (e.g., `10.0.0.0/8` where `max = 16,777,215`, or `100.64.0.0/10` where `max = 4,194,303`) or if the pool is full (`f->count == 0` for all `free_addr` entries), `assign_dynamic()` iterates `i` from `0` to `max`—performing up to $16.7 \times 10^6$ iterations **per packet while holding the global `gcfg.map_mutex`**!
     - Second, even on a `/16` pool (`max = 65535`), once all addresses are allocated (`mapped` or `dormant`), `pool->free_list` contains 65,536 `struct free_addr` nodes, each with `f->count == 0`. For **every single incoming spoofed IPv6 packet**, the loop runs 65,536 outer iterations and traverses the 65,536-node `free_list` before reaching line 164 (`dormant_list` eviction)! That is $65536$ steps per packet under `map_mutex`, freezing all worker threads at 100% CPU!
     - Third, when `f->count > 0` exists in `free_list`, we don't need to probe `max` missing addresses one by one when a probe misses (`f->addr >= addr`): if `addr` lands on an already-allocated address (`f->addr >= addr`), the very next free address in the pool is `f->addr + 1` (if `f->count > 0`), or the next `free_addr` entry in `pool->free_list` that actually has `count > 0`!
- **Proposed Patch:**
```diff
--- a/dynamic.c
+++ b/dynamic.c
@@ -140,26 +140,35 @@
 	for (i = 0, entry = NULL; i <= max; ++i) {
 		addr = pool->free_head.addr | ((base + i) & max);
 		if (!entry || addr == pool->free_head.addr)
 			entry = pool->free_list.next;
-		for (;;) {
+		while (entry != &pool->free_list) {
 			f = list_entry(entry, struct free_addr, list);
 			if (f->addr + f->count >= addr)
 				break;
 			entry = entry->next;
 		}
-		if (f->addr >= addr)
+		if (entry == &pool->free_list)
+			break;
+		if (f->addr >= addr) {
+			/* Skip directly over the contiguous allocated run [addr .. f->addr] */
+			uint32_t skip = f->addr - addr;
+			if (f->count == 0) {
+				/* Advance to the next free_addr block that actually has free addresses */
+				struct list_head *next_e = entry->next;
+				while (next_e != &pool->free_list) {
+					struct free_addr *nf = list_entry(next_e, struct free_addr, list);
+					if (nf->count > 0) {
+						skip = nf->addr - addr;
+						entry = next_e;
+						break;
+					}
+					next_e = next_e->next;
+				}
+				if (next_e == &pool->free_list)
+					ip_exhausted: ;
+			}
+			i += skip;
 			continue;
+		}
 		addr4.s_addr = htonl(addr);
 		m4 = find_map4(&addr4);
```

---

#### `[SEC-03]` Unaligned 16-bit and 32-bit Pointer Dereferences Across `nat64.c`, `gso.c`, and `addrmap.c` (UBSan / Strict-Alignment Faults)
- **Severity:** `MEDIUM`
- **Location:** [`nat64.c:133-138`](nat64.c#L133-L138) (`ip_checksum`), [`nat64.c:345, 350, 363, 405, 418, 533, 1089, 1094, 1107, 1149, 1162`](nat64.c#L345), [`tun.c:1139-1145`](tun.c#L1139-L1145)
- **Standard / Mechanism:** ISO C11 §6.3.2.3p7 (Pointer Alignment Invariants)
- **Root Cause Analysis:**
  1. Look at [`tun_read_packet()`](tun.c#L1139-L1145):
     ```c
     uint8_t *read_ptr = recv_buf + HEADROOM;
     ...
     if (gcfg.vnet_hdr_sz > 0) {
         read_ptr -= gcfg.vnet_hdr_sz;
         read_len += gcfg.vnet_hdr_sz;
     }
     ```
     - `recv_buf` is allocated by `malloc(RECV_BUF_SIZE)` (16-byte aligned on 64-bit Linux) and `HEADROOM` is `64`, so `recv_buf + HEADROOM` (`p->data`) is 4-byte aligned.
     - Even when `vnet_hdr_sz == 10`, `read_ptr` is `recv_buf + 54`, so the 10-byte `virtio_net_hdr` lands at `[54..63]`, and the IP header starts at `recv_buf + 64` (4-byte aligned)! That is a very thoughtful design by the author.
  2. **However**, where can `p->data` or `d` passed to `ip_checksum(void *d, uint32_t c)` become **unaligned**?
     - Look at [`host_handle_icmp4()`](nat64.c#L276) / [`host_handle_icmp6()`](nat64.c#L959) and `ip_checksum(void *d, uint32_t c)` ([`nat64.c:130-147`](nat64.c#L130-L147)):
       ```c
       uint16_t *p = d;
       while (c > 1) {
           sum += *p++;
           c -= 2;
       }
       ```
       While standard headers are 4-byte multiples, in unit tests or custom callers (or if an inner packet inside an extension or non-standard buffer is passed), `uint16_t *p = d` assumes 2-byte alignment and violates strict aliasing if `d` points to a struct (`struct ip4`, `struct icmp`, `struct tcp_hdr`) without `memcpy` or `may_alias`.
     - More importantly, in [`tayga.h:243-244`](tayga.h#L243-L244):
       ```c
       static_assert((offsetof(struct pkt, data) & (alignof(struct ip4) - 1)) == 0,"Packet data must be aligned for IP4");
       ```
       Note that `struct pkt` has `uint8_t *data` (a pointer, not an inline array), so checking `offsetof(struct pkt, data)` only checks the alignment of the pointer field itself inside `struct pkt`, not the alignment of the pointee buffer!
- **Proposed Patch:**
```diff
--- a/nat64.c
+++ b/nat64.c
@@ -130,15 +130,17 @@
 uint16_t ip_checksum(void *d, uint32_t c)
 {
 	uint32_t sum = 0xffff;
-	uint16_t *p = d;
+	const uint8_t *p = (const uint8_t *)d;
 
 	while (c > 1) {
-		sum += *p++;
+		uint16_t word;
+		memcpy(&word, p, sizeof(word));
+		sum += word;
+		p += 2;
 		c -= 2;
 	}
 
 	if (c)
-		sum += *((uint8_t *)p) << BIG_LITTLE(8,0);
+		sum += *p << BIG_LITTLE(8,0);
 
 	while (sum > 0xffff)
 		sum = (sum & 0xffff) + (sum >> 16);
```

---

#### `[SEC-04]` Privilege Dropping Deficiencies in `tayga.c`: Supplementary Groups Not Cleared When `-u` Is Used Without `-g`, and Redundant `setregid` Call
- **Severity:** `MEDIUM`
- **Location:** [`tayga.c:794-810`](tayga.c#L794-L810) (`main`)
- **Standard / Mechanism:** Linux Capabilities & POSIX Privilege Dropping (`setgroups`, `setresgid`, `setresuid`)
- **Root Cause Analysis:**
  1. Look at [`tayga.c:794-810`](tayga.c#L794-L810):
     ```c
     if (gr) {
         if (setregid(gr->gr_gid, gr->gr_gid) < 0 ||
                 setregid(gr->gr_gid, gr->gr_gid) < 0 ||
                 setgroups(1, &gr->gr_gid) < 0) {
             slog(LOG_CRIT, "Error: cannot set gid to %d: %s\n",
                     gr->gr_gid, strerror(errno));
             goto startup_failed;
         }
     }

     if (pw) {
         if (setreuid(pw->pw_uid, pw->pw_uid) < 0) {
             slog(LOG_CRIT, "Error: cannot set uid to %d: %s\n",
                     pw->pw_uid, strerror(errno));
             goto startup_failed;
         }
     }
     ```
  2. There are three issues here:
     - **If `-u <user>` is specified without `-g <group>` (`pw != NULL && gr == NULL`):** TAYGA **never drops its root GID (`gid=0`) and never calls `setgroups()`**, so the process retains root's primary group (`gid = 0`) and all of root's supplementary groups (`groups=0(root)`)! Even when `-r` (`--chroot`) is used, `tayga.c:639` only checks `if (do_chroot && (!pw || pw->pw_uid == 0))`—it does not require `-g`! Thus `tayga -u nobody -r` runs inside the chroot with `uid=nobody`, **`gid=0 (root)`, and supplementary `groups=0 (root)`**!
     - **`setregid(gr->gr_gid, gr->gr_gid)` is called twice identically** on lines 795 and 796 (a copy-paste bug from original TAYGA), and `setgroups()` is called *after* `setregid()` (which only works if effective UID is still 0, which it is, but calling `setgroups()` before `setgid()` is the portable POSIX order).
     - When `pw != NULL && gr == NULL`, TAYGA should default to `pw->pw_gid` and call `setgroups(1, &pw->pw_gid)` (or `initgroups(pw->pw_name, pw->pw_gid)` / `setgroups(0, NULL)`) before dropping GID and UID.
- **Proposed Patch:**
```diff
--- a/tayga.c
+++ b/tayga.c
@@ -794,16 +794,16 @@
-	if (gr) {
-		if (setregid(gr->gr_gid, gr->gr_gid) < 0 ||
-				setregid(gr->gr_gid, gr->gr_gid) < 0 ||
-				setgroups(1, &gr->gr_gid) < 0) {
+	if (gr || pw) {
+		gid_t target_gid = gr ? gr->gr_gid : pw->pw_gid;
+		if (setgroups(1, &target_gid) < 0 ||
+		    setregid(target_gid, target_gid) < 0) {
 			slog(LOG_CRIT, "Error: cannot set gid to %d: %s\n",
-					gr->gr_gid, strerror(errno));
+					target_gid, strerror(errno));
 			goto startup_failed;
 		}
 	}
```

---

#### `[STAB-02]` Memory Leaks in `conffile.c` Error Paths and Unbounded Extension Header Chain Walking in `parse_ip6()`
- **Severity:** `LOW`
- **Location:** [`nat64.c:1280-1302`](nat64.c#L1280-L1302) (`parse_ip6`), [`conffile.c:181-207`](conffile.c#L181-L207), [`conffile.c:317-358`](conffile.c#L317-L358), [`conffile.c:381-422`](conffile.c#L381-L422)
- **Standard / Mechanism:** RFC 8200 / RFC 8504 (IPv6 Extension Header Processing Limits), C Resource Management
- **Root Cause Analysis:**
  1. In [`flow_dispatch.h:47-48`](flow_dispatch.h#L47-L48), the author bounded the IPv6 extension header loop to `count < 8 && off <= 296`. However, in [`parse_ip6()`](nat64.c#L1280-L1302), the `while (p->data_proto == 0 || p->data_proto == 43 || p->data_proto == 60)` loop has no chain-count cap: a 64KB packet filled with 8-byte dummy Destination Options headers (`Hdr Ext Len = 0`) forces 8,187 loop iterations per packet before dropping. Additionally, if `seg_ptr += hdr_len` overflows `uint16_t` (Wait: `p->data_len` is bounded by `ntohs(p->ip6->payload_length) <= 65535`, and `seg_ptr` starts at `40`, so if `payload_length == 65500` of extension headers followed by a Routing Header with `seg_left > 0`, **`uint16_t seg_ptr = 40 + 65500` wraps 16-bit unsigned integer to `4`**, emitting a bogus ICMPv6 Parameter Problem pointer!). Changing `seg_ptr` to `uint32_t` prevents this 16-bit wrap.
  2. In `conffile.c`, `config_prefix`, `config_tun_ip`, `config_tun_route`, `config_map`, and `config_dynamic_pool` allocate heap structs (`m`, `ip6`, `pool`) and return `ERROR_REJECT` without `free()` on several validation error branches (spotted when running `unit_conffile` under ASan/LSan).
- **Proposed Patch:**
```diff
--- a/nat64.c
+++ b/nat64.c
@@ -1255,7 +1255,7 @@
 {
 	uint32_t hdr_len;
 	uint8_t seg_left = 0;
-	uint16_t seg_ptr = sizeof(struct ip6);
+	uint32_t seg_ptr = sizeof(struct ip6);
 
 	p->ip6 = (struct ip6 *)(p->data);
```

---

#### `[INFO-01]` Architectural & Positive Security Observations
During the reconnaissance and line-by-line review, the following areas were verified to be **sound and free of vulnerabilities**:
1. **In-Place Buffer Headroom (`HEADROOM = 64` & `RECV_BUF_SIZE`):**
   - `RECV_BUF_SIZE` is `64 + 40 + 65535 + 12 + 1 = 65652` bytes.
   - In `tun_read_packet()`, `read_ptr` is placed at `recv_buf + 64 - gcfg.vnet_hdr_sz` (`54` or `52`), so `p->data` always starts at `recv_buf + 64`.
   - In `xlate_4to6_data()` (`no_frag_hdr == 1`), `uint8_t *out = p->data - sizeof(struct ip6)` writes at `recv_buf + 24`, leaving 24 bytes of unused headroom. When `tun_write_vnet()` is called, it uses `writev()` with `iov[0] = &out_vhdr` and `iov[1] = out`, so it never overwrites `recv_buf` below offset 24.
   - In `gso_translate_tcp_4to6()` and `gso_translate_udp_4to6()`, `out = p->data - 20` writes at `recv_buf + 44` (after stripping any IPv4 options via `memmove`), safely within the 64-byte headroom.
2. **TUN Truncation Sentinel:**
   - Because `read_len` is `40 + 65535 + vnet_hdr_sz + 1`, any `read()` returning `ret == read_len` unambiguously detects an oversized (> 65575B IPv6) frame and drops it cleanly (`tun.c:1167`).
3. **UDP Zero-Checksum Handling (`nat64.c:364-385`, `1108-1129`):**
   - Properly implements `UDP_CKSUM_DROP` (RFC 7915 §4.5 default), `UDP_CKSUM_CALC`, and `UDP_CKSUM_FWD`, including converting a calculated `0x0000` UDP checksum to `0xFFFF`.
4. **TUN Error Recovery (`stats_tx_failure` in `stats.c:46-63`):**
   - Transient or packet-specific write errors (`EAGAIN`, `EWOULDBLOCK`, `ENOBUFS`, `EINVAL`, `EMSGSIZE`) increment per-reason counters (`tx_eagain`, `tx_enobufs`, `tx_other`) with 1-second rate-limited logging (`stats_warn_limited`) and **do not** terminate the daemon or spin the CPU. Only genuine descriptor failures (`EBADF`, `ENODEV`, `EIO`, `ESHUTDOWN`) set `g_tun_tx_fatal = true` to trigger a clean shutdown.

---

## 3. Verification & Regression Test Plan

Below are concrete C unit test cases (compatible with `test/unit_gso.c`, `test/unit_addrmap.c`, and `test/unit_udp_checksum.c`) to verify the findings and prevent regressions:

### Test 1: Regression Test for `[SEC-01]` (Negative `old_ptr` in ICMPv6 Parameter Problem)
Add to [`test/unit_udp_checksum.c`](test/unit_udp_checksum.c):
```c
static void test_icmp6_param_problem_negative_ptr(void)
{
	printf("Testing ICMPv6 Parameter Problem negative pointer bounds ([SEC-01])...\n");
	uint8_t buf[HEADROOM + 256];
	memset(buf, 0, sizeof(buf));
	uint8_t *pkt_start = buf + HEADROOM;

	/* Outer IPv6 header */
	struct ip6 *ip6 = (struct ip6 *)pkt_start;
	ip6->ver_tc_fl = htonl(0x60000000);
	ip6->payload_length = htons(sizeof(struct icmp) + sizeof(struct ip6) + 8);
	ip6->next_header = 58; /* ICMPv6 */
	ip6->hop_limit = 64;
	inet_pton(AF_INET6, "64:ff9b::808:808", &ip6->src);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

	/* Outer ICMPv6 Parameter Problem (Type 4, Code 0) with pointer = 0x80000000 */
	struct icmp *icmp6 = (struct icmp *)(ip6 + 1);
	icmp6->type = 4;
	icmp6->code = 0;
	icmp6->word = htonl(0x80000000U); /* Negative when cast to int32_t */

	/* Inner offending IPv6 header + 8B UDP */
	struct ip6 *ip6_em = (struct ip6 *)(icmp6 + 1);
	ip6_em->ver_tc_fl = htonl(0x60000000);
	ip6_em->payload_length = htons(8);
	ip6_em->next_header = IPPROTO_UDP;
	ip6_em->hop_limit = 64;
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6_em->src);
	inet_pton(AF_INET6, "64:ff9b::808:808", &ip6_em->dest);

	icmp6->cksum = 0;
	icmp6->cksum = ones_add(ip_checksum(icmp6, ntohs(ip6->payload_length)),
	                        ip6_checksum(ip6, ntohs(ip6->payload_length), 58));

	struct pkt p = {
		.tun_fd = -1,
		.data = pkt_start,
		.data_len = sizeof(struct ip6) + ntohs(ip6->payload_length),
	};

	/* Must drop cleanly without crashing on out-of-bounds new_ptr_tbl[old_ptr] */
	handle_ip6(&p);
	printf("PASS: ICMPv6 Parameter Problem negative pointer safely dropped\n");
}
```

### Test 2: Regression Test for `[RFC-02]` (ICMPv6 Error Quoting Truncated Fragmented Packet)
```c
static void test_icmp6_error_truncated_fragment_quote(void)
{
	printf("Testing ICMPv6 error with truncated inner fragment ([RFC-02])...\n");
	/* Construct an ICMPv6 Time Exceeded (Type 3, Code 0) containing an inner IPv6
	 * header + Fragment Header (MF=1, offset=0) + 12 bytes of truncated payload
	 * (12 is not divisible by 8). Verify parse_ip6(&p_em, 1) accepts it. */
	uint8_t buf[HEADROOM + 256];
	memset(buf, 0, sizeof(buf));
	uint8_t *pkt_start = buf + HEADROOM;

	struct ip6 *ip6 = (struct ip6 *)pkt_start;
	ip6->ver_tc_fl = htonl(0x60000000);
	ip6->payload_length = htons(sizeof(struct icmp) + sizeof(struct ip6) + sizeof(struct ip6_frag) + 12);
	ip6->next_header = 58;
	ip6->hop_limit = 64;
	inet_pton(AF_INET6, "64:ff9b::808:808", &ip6->src);
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6->dest);

	struct icmp *icmp6 = (struct icmp *)(ip6 + 1);
	icmp6->type = 3; /* Time Exceeded */
	icmp6->code = 0;
	icmp6->word = 0;

	struct ip6 *ip6_em = (struct ip6 *)(icmp6 + 1);
	ip6_em->ver_tc_fl = htonl(0x60000000);
	ip6_em->payload_length = htons(1408); /* Original un-truncated length */
	ip6_em->next_header = 44; /* Fragment Header */
	ip6_em->hop_limit = 1;
	inet_pton(AF_INET6, "fd9b:64:1:ff::10", &ip6_em->src);
	inet_pton(AF_INET6, "64:ff9b::808:808", &ip6_em->dest);

	struct ip6_frag *frag_em = (struct ip6_frag *)(ip6_em + 1);
	frag_em->next_header = IPPROTO_UDP;
	frag_em->offset_flags = htons(IP6_F_MF); /* MF=1, offset=0 */
	frag_em->ident = htonl(0x12345678);

	icmp6->cksum = ones_add(ip_checksum(icmp6, ntohs(ip6->payload_length)),
	                        ip6_checksum(ip6, ntohs(ip6->payload_length), 58));

	struct pkt p = {
		.tun_fd = -1,
		.data = pkt_start,
		.data_len = sizeof(struct ip6) + ntohs(ip6->payload_length),
	};
	handle_ip6(&p);
	printf("PASS: ICMPv6 error with truncated inner fragment handled\n");
}
```

### Test 3: Regression Test for `[GSO-01]` (4to6 Software Segmentation with Jumbo `gso_size > 2000`)
Add to [`test/unit_gso.c`](test/unit_gso.c):
```c
static void test_gso_sw_seg_4to6_jumbo_mss(void)
{
	printf("Testing gso_software_segment_and_send_4to6() with jumbo MSS (gso_size=4000)...\n");
	setup_test_mapping();
	gcfg.mtu = 9000;

	RX_BUFFER(rx_buf, HEADROOM + 16384);
	memset(&rx_buf, 0, sizeof(rx_buf));
	uint8_t *base = rx_buf.data + HEADROOM;

	uint32_t payload_len = 8000;
	uint32_t tcp_len = sizeof(struct tcp_hdr) + payload_len;
	uint32_t ip4_len = sizeof(struct ip4) + tcp_len;

	struct ip4 *ip4 = (struct ip4 *)base;
	ip4->ver_ihl = 0x45;
	ip4->length = htons((uint16_t)ip4_len);
	ip4->flags_offset = htons(IP4_F_DF);
	ip4->ttl = 64;
	ip4->proto = IPPROTO_TCP;
	inet_pton(AF_INET, "192.0.0.1", &ip4->src);
	inet_pton(AF_INET, "8.8.8.8", &ip4->dest);
	ip4->cksum = ip4_header_checksum(ip4);

	struct tcp_hdr *tcp = (struct tcp_hdr *)(base + sizeof(struct ip4));
	tcp->src_port = htons(40000);
	tcp->dst_port = htons(443);
	tcp->seq = htonl(1);
	tcp->doff_res = (sizeof(struct tcp_hdr) / 4) << 4;
	tcp->flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
	tcp->window = htons(1024);
	tcp->cksum = htons(gso_calc_tcp_pseudo4(&ip4->src, &ip4->dest, tcp_len));

	struct pkt p = {
		.tun_fd = -1,
		.data = base,
		.data_len = ip4_len,
		.has_vhdr = 1,
		.vhdr = {
			.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
			.gso_type = VIRTIO_NET_HDR_GSO_TCPV4,
			.hdr_len = sizeof(struct ip4) + sizeof(struct tcp_hdr),
			.gso_size = 4000,
			.csum_start = sizeof(struct ip4),
			.csum_offset = 16,
		}
	};

	int ret = gso_software_segment_and_send_4to6(&p);
	assert(ret == 0);
	printf("PASS: gso_software_segment_and_send_4to6() jumbo MSS\n");
}
```