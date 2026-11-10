# Architecture

`src/tayga.c` owns startup, privilege changes, workers and shutdown. Configuration
and immutable or reloadable address mappings live in `conffile.c`, `addrmap.c` and
`dynamic.c`. Reload stages a complete replacement and publishes it under map then
cache locks. Static IPv4 entries use longest-prefix matching; narrower mappings
may override broader ones. Overlaps can make reverse translation asymmetric and
must be chosen deliberately.

The scalar translator in `nat64.c` handles packet validation, ICMP and IP header
translation, checksums and fragmentation. `gso.c` handles validated VirtIO
aggregates, hardware-offload output and software segmentation. Both paths must
preserve address rejection, self-destination and path-MTU behavior.

Linux TUN queues and transactional interface setup are in `tun.c` and
`netlink_io.h`. Synchronous kernel queue steering remains the production default.
Flow dispatch, group steering and asynchronous io_uring are experimental opt-ins;
see the configuration/help output for restrictions. Batched thread-local counters
are published through `stats.c` and the exporter.

RFC 7757 mappings replace the IPv4 prefix with the IPv6 prefix, copy the remaining
IPv4 bits immediately after it and pad trailing IPv6 bits with zeros. Reverse
translation copies that same suffix and discards trailing padding. Equal suffix
width mappings retain the former low-bit representation. Config files and map
files use identical suffix-capacity validation.

Dynamic allocation scans free runs in hash order, then wraps before declaring
exhaustion. Static overrides are skipped by subnet. Existing minimum lease aging
protects active assignments; optional allocation-rate limiting is not implemented.


## Telemetry snapshot publication

JSON export serializes counter collection and rendering to an in-memory stream.
Metadata file reads and temporary-file writes happen outside that shared lock.
A separate lock per destination covers the final rename and sequence check;
an older slow writer discards its temporary file if a newer snapshot has already
been published. Publication records live only while writers for that path are
in flight and are then freed. Different output paths do not share a filesystem
publication lock. The cached PREF64 source refreshes on monotonic time and
accepts regular files only. Telemetry export does not change mapping/cache
ownership or add synchronization to the packet translation path.
