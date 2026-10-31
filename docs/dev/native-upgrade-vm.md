# Native package upgrade VM gate

`test/system/run-native-upgrade-vm.py` exercises DEB/APK/RPM upgrade and early boot
recovery with real dpkg/systemd, apk/OpenRC, or RPM/systemd in an existing dedicated Lima Linux VM.
The VM name must start with `tayga-installer-`. The runner forcibly powers it
off, removes the installed test profile/package on success, and stops it on exit.
Use a disposable Debian, Alpine, or Fedora VM with no existing managed profiles or SFX installation.
Install the native package dependencies before running the gate.

Build two matching DEB, APK or RPM revisions from the current installer sources with
`scripts/build-native-packages.py`, using verified static binaries for the VM's
architecture. APK fixtures are explicitly installed with `--allow-untrusted`. Both revisions must contain the current upgrade and boot recovery
helpers. These are local test fixtures, not release versions.

```sh
python3 test/system/run-native-upgrade-vm.py \
  --vm tayga-installer-debian \
  --baseline build/native-vm/packages/tayga-managed-0.9.14-21-arm64.deb \
  --target build/native-vm/packages/tayga-managed-0.9.14-22-arm64.deb \
  --output build/native-vm/debian-gate
```

The gate installs the baseline, activates a SIIT profile, upgrades the running
service, checks PID replacement and readiness, and verifies retained data.
For the power-cut case it starts a coordinated downgrade back to the baseline.
A test-only PATH interposer runs the real package manager, then pauses after the staged package
has been installed. It changes test data, writes a readiness marker, and syncs
the VM filesystem. The host kills the VM driver without a guest shutdown.

After boot, the test requires automatic restoration of the accepted higher
package revision in the package database, the original data, removal of target-only
data, an active service with successful readiness, and retirement of the journal.
The runner stores command logs, package/fixture SHA256 hashes and `report.json`.
A failed gate retains guest state for diagnosis; inspect its journal before
starting another run. A clean successful run can be repeated with a new output
directory.

This gate checks one interruption boundary on Debian/systemd, Alpine/OpenRC,
or Fedora/systemd, with SIIT route readiness. It does not certify packet translation, arbitrary storage corruption,
or all transaction boundaries.

Early boot recovery must not synchronously start a systemd unit that declares
`Requires=tayga-recovery.service` and `After=tayga-recovery.service`: doing so
deadlocks recovery until its timeout. The boot helper marks its recovery context;
the package coordinator queues the restored service with `--no-block`, and the
managed unit performs readiness in `ExecStartPost` after recovery completes.
Interactive recovery still waits for the service and checks readiness directly.

For Alpine/OpenRC, select `--vm tayga-installer-alpine` and supply matching
`.apk` baseline/target files. Recovery defers the managed service to its enabled
OpenRC runlevel; `start_post` performs readiness after the recovery dependency
returns. The native APK recovery version check uses the installed package list,
because a named `apk info -v PACKAGE` query returns descriptive output.

For Fedora/systemd, select `--vm tayga-installer-fedora` and matching `.rpm`
packages. Install the declared RPM dependencies before starting. The coordinated
power-cut fixture explicitly permits a downgrade; RPM compares the versions and
the coordinator selects `dnf downgrade` only for an actual downward transition.

Native DEB/RPM packages also install `tayga-package-recovery.service`. The early
profile recovery unit defers a native package journal to this unit, which runs
after `basic.target` and before the managed service. Distribution RPM file
triggers may synchronously call `systemd-run`; executing them before sysinit can
block boot even when the coordinator itself queues service startup correctly.
The late unit executes the persistent journal worker and fails closed when it
is missing or recovery fails. The managed unit requires both recovery units.

The RPM fixture supplies a dedicated dummy interface and native IPv6 route for
the SIIT endpoint because Fedora Cloud may have no IPv6 default route. Its owned
systemd fixture unit restores that route after the power cut and is removed on
successful cleanup. This is a route readiness fixture, not a translated traffic
endpoint.

## Profiles that must remain inactive

For DEB/RPM systemd gates, `--profile-state unconfigured` skips profile activation;
`--profile-state stopped` activates the fixture then disables and stops its unit.
Both variants require recovery to restore package/data state without starting
TAYGA. This tests an explicitly disabled profile, not overriding the normal boot
policy of an enabled unit that was merely stopped before reboot.

The package installs a vendor `multi-user.target.wants` link for package recovery,
so interrupted upgrades recover even when no profile service was ever registered.
This recovery unit does not require the profile recovery unit to exist; ordering
is respected when the profile recovery unit is present. Installing the package
still does not enable a managed translation profile.

See [test image cache](test-images.md) for reuse of existing OS downloads.

## Forwarded traffic

Add `--traffic` for an active-profile gate. The runner copies
`installer-native-wire-smoke.sh` and runs it before upgrade, after upgrade and
following boot recovery. Separate IPv4 client and IPv6 server namespaces exchange
ICMP and TCP/HTTP through the SIIT daemon. The IPv6 HTTP log must contain the
translated client address, and the response body must match the fixture proof.
Each probe removes its namespaces, veth interfaces and HTTP server. Python 3,
`ping`, `curl` and iproute2 are required in the guest. UDP and PMTU edge cases
remain separate checks; this flag does not test CLAT/NAT64 or FreeBSD PF.
