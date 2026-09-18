# ==============================================================================
# RouterOS 7 Preflight Check for TAYGA Unified Container (CLAT / NAT64)
# ==============================================================================
# Performs a non-destructive audit of the router environment before deploying TAYGA.
# Verifies CPU architecture, RouterOS version, container device-mode,
# ext4 USB storage (slot/mount/free), free RAM, IPv6 default route, and detects
# unowned object collisions.
#
# If any checks FAIL, this script aborts with :error to prevent broken deployments.
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-preflight.rsc
# ==============================================================================

:local passCount 0
:local failCount 0
:local warnCount 0

:put "============================================================"
:put " Starting TAYGA Unified Preflight Audit..."
:put "============================================================"

# --- 1. Architecture & OS Version Check ---
:local osVer [/system/resource/get version]
:local cpuArch [/system/resource/get architecture-name]
:local freeMem ([/system/resource/get free-memory] / 1048576)

:put ("--> RouterOS Version: " . $osVer . " (Arch: " . $cpuArch . ")")
:if ($cpuArch = "arm64" or $cpuArch = "aarch64") do={
    :put " [PASS] CPU Architecture is ARM64 (compatible with Chateau 5G ax)"
    :set passCount ($passCount + 1)
} else={
    :put (" [FAIL] CPU Architecture is '" . $cpuArch . "'. ARM64 container image is strictly required.")
    :set failCount ($failCount + 1)
}

:if ($freeMem > 64) do={
    :put (" [PASS] Free RAM: " . $freeMem . " MB (sufficient for TAYGA + Unbound)")
    :set passCount ($passCount + 1)
} else={
    :put (" [FAIL] Free RAM is low: " . $freeMem . " MB. At least 64 MB free RAM required.")
    :set failCount ($failCount + 1)
}

# --- 2. Container Feature Support & Device Mode ---
:local contSubsystemOk false
:do {
    :local contCount [:len [/container/find]]
    :set contSubsystemOk true
    :put " [PASS] Container subsystem is present in RouterOS."
    :set passCount ($passCount + 1)
} on-error={
    :put " [FAIL] Container subsystem not available. The 'container' package must be installed."
    :set failCount ($failCount + 1)
}

:do {
    :local dmCont [/system/device-mode/get container]
    :if ($dmCont = true) do={
        :put " [PASS] Device-mode container=yes is enabled."
        :set passCount ($passCount + 1)
    } else={
        :put " [FAIL] Device-mode container feature is disabled. Run: /system/device-mode update container=yes (requires physical confirmation button/reboot)."
        :set failCount ($failCount + 1)
    }
} on-error={
    :put " [WARN] Device-mode container property could not be checked directly."
    :set warnCount ($warnCount + 1)
}

# --- 3. Storage Mount, ext4 Filesystem & Free Disk Space Check ---
:local extSlot "usb1"
:local diskId [/disk/find where slot="usb1" or name="usb1"]
:if ([:len $diskId] = 0) do={
    :set diskId [/disk/find where slot="pcie1" or name="pcie1"]
    :if ([:len $diskId] > 0) do={ :set extSlot "pcie1" } else={
        :foreach d in=[/disk/find where fs="ext4"] do={
            :if ($extSlot = "usb1") do={
                :do { :set extSlot [/disk/get $d slot] } on-error={
                    :do { :set extSlot [/disk/get $d name] } on-error={}
                }
                :set diskId $d
            }
        }
    }
}

:if ([:len $diskId] > 0) do={
    :local diskFs [/disk/get $diskId fs]
    :local diskFreeBytes 0
    :do { :set diskFreeBytes [/disk/get $diskId free] } on-error={
        :do { :set diskFreeBytes [/disk/get $diskId free-space] } on-error={}
    }
    :local diskFreeMB ($diskFreeBytes / 1048576)
    :put (" [INFO] Storage detected: slot=" . $extSlot . ", fs=" . $diskFs . ", free=" . $diskFreeMB . " MB")
    
    :if ($diskFs = "ext4") do={
        :put " [PASS] Storage filesystem is ext4 (required for container rootfs)."
        :set passCount ($passCount + 1)
    } else={
        :put (" [FAIL] Storage filesystem is '" . $diskFs . "'. RouterOS containers require ext4 formatted storage.")
        :set failCount ($failCount + 1)
    }
    
    :if ($diskFreeMB > 100) do={
        :put (" [PASS] Free disk space: " . $diskFreeMB . " MB (sufficient for TAR & rootfs).")
        :set passCount ($passCount + 1)
    } else={
        :put (" [FAIL] Free disk space is low: " . $diskFreeMB . " MB. At least 100 MB required.")
        :set failCount ($failCount + 1)
    }
} else={
    :put (" [FAIL] No ext4 storage disk (usb1 / pcie1) found in /disk. External ext4 storage is required.")
    :set failCount ($failCount + 1)
}

# --- 4. IPv6 Upstream & Default Route Check (Strict for CLAT, Warn for NAT64) ---
:local targetMode "clat"
:do { :if ([:len $AUDITMODE] > 0) do={ :set targetMode $AUDITMODE } } on-error={}

:local v6DefaultCount [:len [/ipv6/route/find where dst-address="::/0" and active=yes]]
:if ($v6DefaultCount > 0) do={
    :put " [PASS] Active IPv6 default route (::/0) exists on router."
    :set passCount ($passCount + 1)
} else={
    :if ($targetMode = "clat") do={
        :put " [FAIL] No active IPv6 default route (::/0) found. Telekom IPv6 WAN connectivity is strictly required for CLAT."
        :set failCount ($failCount + 1)
    } else={
        :put " [WARN] No active IPv6 default route (::/0) found. Telekom IPv6 WAN connectivity recommended for NAT64."
        :set warnCount ($warnCount + 1)
    }
}

# --- 5. Collision & Foreign Object Ownership Check ---
:local existingBridge [/interface/bridge/find where name="bridge-clat"]
:if ([:len $existingBridge] > 0) do={
    :local bComm [/interface/bridge/get $existingBridge comment]
    :if (!($bComm ~ "^\\[tayga-unified")) do={
        :put " [FAIL] Conflict: 'bridge-clat' exists but is not owned by tayga-unified project."
        :set failCount ($failCount + 1)
    }
}

:local existingVeth [/interface/veth/find where name="veth-clat"]
:if ([:len $existingVeth] > 0) do={
    :local vComm [/interface/veth/get $existingVeth comment]
    :if (!($vComm ~ "^\\[tayga-unified")) do={
        :put " [FAIL] Conflict: 'veth-clat' exists but is not owned by tayga-unified project."
        :set failCount ($failCount + 1)
    }
}

# --- Summary & Enforcement ---
:put "============================================================"
:put (" Preflight Audit Summary: PASS=" . $passCount . " | WARN=" . $warnCount . " | FAIL=" . $failCount)
:if ($failCount = 0) do={
    :put " Status: READY FOR INSTALLATION"
    :put "============================================================"
} else={
    :put " Status: BLOCKED - Fix the FAIL items above before proceeding."
    :put "============================================================"
    :error ("Preflight audit failed with " . $failCount . " errors. Aborting.")
}
