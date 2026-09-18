# ==============================================================================
# RouterOS 7 Upgrade Script: State-Driven Dual-Slot (A/B) Upgrade & Instant Auto-Rollback
# ==============================================================================
# Upgrades container image with zero traffic blackholing and verified recovery:
# 1. Verifies prerequisites: veth-clat, active CLAT container, new image TAR
# 2. Reads persistent state (ACTIVE_SLOT, LAST_GOOD_SLOT)
# 3. Targets alternate slot (clat-a <-> clat-b)
# 4. Withdraws default route
# 5. Cleanly stops active container (retained in stopped state for instant fallback)
# 6. Deploys candidate container into target slot
# 7. Starts candidate container and verifies end-to-end probe ping (/32)
# 8. If probe succeeds: marks candidate verified, promotes slot, enables default route
# 9. If probe fails: INSTANTLY restarts preserved previous container (< 1s, zero extraction)!
#
# Supports continuous sequential upgrades: A -> B -> A (C) -> B (D) -> ...
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-upgrade.rsc
# ==============================================================================

# --- 0. Acquire Unified Lock (owner=upgrade) ---
:global TAYGA_LOCK_OWNER
:global TAYGA_LOCK_TIME

:local waitCtrl 0
:while ([:len $TAYGA_LOCK_OWNER] > 0 and $TAYGA_LOCK_OWNER != "none" and $TAYGA_LOCK_OWNER != "upgrade" and $waitCtrl < 20) do={
    :put ("--> System locked by " . $TAYGA_LOCK_OWNER . "; waiting for lock release (" . $waitCtrl . "/20s)...")
    :delay 1s
    :set waitCtrl ($waitCtrl + 1)
}
:if ([:len $TAYGA_LOCK_OWNER] > 0 and $TAYGA_LOCK_OWNER != "none" and $TAYGA_LOCK_OWNER != "upgrade") do={
    :put " [FAIL] Lock could not be acquired within 20s timeout. Aborting upgrade."
    :error "Aborted: lock busy"
}
:set TAYGA_LOCK_OWNER "upgrade"
:set TAYGA_LOCK_TIME [/system/resource/get uptime]

:do {
    :put "============================================================"
    :put " Starting State-Driven Dual-Slot (A/B) TAYGA Upgrade..."
    :put "============================================================"

    # Migration cleanup: Remove any legacy /32 probe route from main table
    :do { /ip/route/remove [find where dst-address="1.1.1.1/32" and comment~"^\\[tayga-unified"] } on-error={}

    # --- 1. Detect Storage Slot & Image Paths ---
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
    :local basePath ($extSlot . "/telekom-xlat")

    # CPU architecture-aware local image filename
    :local cpuArch [/system/resource/get architecture-name]
    :local localTarName "tayga-arm64.tar"
    :if ($cpuArch = "x86_64" or $cpuArch = "amd64") do={ :set localTarName "tayga-amd64.tar" }
    :if ($cpuArch = "arm") do={ :set localTarName "tayga-armv7.tar" }
    :local imagePath ($basePath . "/images/" . $localTarName)

    # --- Remote Image & Registry Configuration (Overridable via global variables) ---
    :global USE_REGISTRY
    :global REMOTE_IMAGE
    :global REGISTRY_URL

    :local useRegistry false
    :if ($USE_REGISTRY = true) do={ :set useRegistry true }

    :local remoteImage "ghcr.io/antongrizli/tayga-clat:latest"
    :if ([:len $REMOTE_IMAGE] > 0) do={ :set remoteImage $REMOTE_IMAGE }

    :local registryUrl "https://ghcr.io"
    :if ([:len $REGISTRY_URL] > 0) do={ :set registryUrl $REGISTRY_URL }

    # Auto-detect: if local TAR is not present on storage, automatically switch to GHCR pull
    :local hasLocalTar ([:len [/file/find where name=$imagePath]] > 0)
    :if ($useRegistry = false and $hasLocalTar = false) do={
        :put ("--> Local image " . $imagePath . " not found; switching to GHCR registry pull (" . $remoteImage . ")...")
        :set useRegistry true
    }

    # --- 2. Check Prerequisites Before Modifying Services ---
    :if ($useRegistry = false and $hasLocalTar = false) do={
        :put (" [FAIL] Upgrade image archive '" . $imagePath . "' not found and USE_REGISTRY is false.")
        :error "Aborted: missing container image archive"
    }

    :if ([:len [/interface/veth/find where name="veth-clat"]] = 0) do={
        :put " [FAIL] Required interface 'veth-clat' not found. Run routeros-install-clat.rsc first."
        :error "Aborted: veth-clat interface missing"
    }

    :local oldConts [/container/find where comment~"^\\[tayga-unified:clat\\]" and interface="veth-clat"]
    :if ([:len $oldConts] = 0) do={
        :put " [FAIL] No active CLAT container found to upgrade. Run routeros-install-clat.rsc first."
        :error "Aborted: no active CLAT container"
    }
    :local oldCont ($oldConts->0)

    # --- 3. Determine Active Slot & Target Inactive Slot (A/B Rotation) ---
    :local curRootDir [/container/get $oldCont root-dir]
    :local targetSlot "clat-b"
    :local prevSlot "clat-a"

    :if ($curRootDir ~ "clat-b") do={
        :set targetSlot "clat-a"
        :set prevSlot "clat-b"
    } else={
        :set targetSlot "clat-b"
        :set prevSlot "clat-a"
    }
    :local targetRootfs ($basePath . "/rootfs/" . $targetSlot)

    :put ("--> Active Slot : " . $prevSlot . " (" . $curRootDir . ")")
    :put ("--> Target Slot : " . $targetSlot . " (" . $targetRootfs . ")")

    # Ensure isolated CLAT probe table exists
    :if ([:len [/routing/table/find where name="tayga-probe-clat"]] = 0) do={
        /routing/table/add name=tayga-probe-clat fib comment="[tayga-unified:clat] Isolated CLAT Probe Table"
    }
    :if ([:len [/ip/route/find where routing-table="tayga-probe-clat" and dst-address="0.0.0.0/0"]] = 0) do={
        /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 routing-table=tayga-probe-clat comment="[tayga-unified:clat:probe] CLAT Probe Route"
    }

    # --- 4. Withdraw Default Route during Upgrade Window ---
    :put "--> Withdrawing default route..."
    /ip/route/disable [find where comment~"^\\[tayga-unified:clat:default\\]"]

    # --- 5. Cleanly STOP Active Container (Preserved definition for instant fallback) ---
    :put "--> Stopping running container (retaining definition for instant rollback)..."
    /container/stop $oldCont
    :local stopWait 0
    :while (([/container/get $oldCont stopped] != true) && ($stopWait < 30)) do={
        :delay 1s
        :set stopWait ($stopWait + 1)
    }
    :if ([/container/get $oldCont stopped] != true) do={
        :put " [FAIL] Active container did not stop cleanly within 30s timeout."
        :error "Aborted: container stop timed out"
    }

    # Clean up any leftover candidate container from previous failed attempts
    :local staleCand [/container/find where comment~"^\\[tayga-unified:clat:candidate\\]"]
    :if ([:len $staleCand] > 0) do={
        :do { /container/remove ($staleCand->0) } on-error={}
    }

    # Clean up target rootfs directory
    :do {
        /file/remove [find where name=$targetRootfs]
    } on-error={}

    # --- 6. Deploy Candidate Container into Target Slot ---
    :if ($useRegistry = true) do={
        :put ("--> Setting container registry URL: " . $registryUrl . "...")
        :do { /container/config/set registry-url=$registryUrl } on-error={}
        :put ("--> Pulling remote candidate image '" . $remoteImage . "' into " . $targetRootfs . "...")
        /container/add remote-image=$remoteImage \
            root-dir=$targetRootfs \
            interface=veth-clat \
            envlist=tayga-clat-envs \
            memory-high=128M \
            memory-max=192M \
            start-on-boot=no \
            restart-policy=on-failure \
            restart-interval=10s \
            logging=yes \
            comment="[tayga-unified:clat:candidate] Candidate Upgrade Container"

        :put "--> Downloading and extracting candidate layers from GHCR (may take 10-60s)..."
        :local candCont [/container/find where comment~"^\\[tayga-unified:clat:candidate\\]"]
        :if ([:len $candCont] > 0) do={
            :local cId ($candCont->0)
            :local extWait 0
            :local isExtracted false
            :while (($isExtracted = false) && ($extWait < 180)) do={
                :local isStopped [/container/get $cId stopped]
                :if ($isStopped = true) do={
                    :set isExtracted true
                } else={
                    :delay 2s
                    :set extWait ($extWait + 2)
                }
            }
            :if ($isExtracted = false) do={
                :error "Aborted: remote image extraction timed out (180s)"
            }
        }
    } else={
        :put ("--> Extracting candidate image into " . $targetRootfs . "...")
        /container/add file=$imagePath \
            root-dir=$targetRootfs \
            interface=veth-clat \
            envlist=tayga-clat-envs \
            memory-high=128M \
            memory-max=192M \
            start-on-boot=no \
            restart-policy=on-failure \
            restart-interval=10s \
            logging=yes \
            comment="[tayga-unified:clat:candidate] Candidate Upgrade Container"
        :delay 3s
    }

    # --- 7. Start Candidate Container and Verify End-to-End Probe ---
    :put "--> Starting candidate container..."
    :local upgradeOk true
    :local newCont [/container/find where comment~"^\\[tayga-unified:clat:candidate\\]"]
    :if ([:len $newCont] > 0) do={
        :local newId ($newCont->0)
        /container/start $newId

        :local isRunning false
        :for i from=1 to=30 do={
            :if ($isRunning = false) do={
                :local r [/container/get $newId running]
                :if ($r = true) do={
                    :set isRunning true
                } else={
                    :delay 1s
                }
            }
        }
        :if ($isRunning = false) do={
            :set upgradeOk false
            :put " [FAIL] Candidate container failed to reach running state."
        }
    } else={
        :set upgradeOk false
    }

    # Warm-up delay for RFC 7050 discovery / translation initialization
    :if ($upgradeOk = true) do={
        :delay 5s
        :put "--> Testing end-to-end probe ping via tayga-probe-clat..."
        :local pingRx [/ping 1.1.1.1 src-address=172.31.64.1 routing-table=tayga-probe-clat count=3]
        :if ($pingRx > 0) do={
            :put (" [PASS] Probe test successful (" . $pingRx . "/3 received)!")
        } else={
            :set upgradeOk false
            :put " [FAIL] Candidate probe ping returned 0 packets."
        }
    }

    # --- 8. Promote Candidate OR Execute INSTANT ZERO-EXTRACTION ROLLBACK ---
    :if ($upgradeOk = true) do={
        :put "--> Promoting candidate to active production container..."
        :local candId [/container/find where comment~"^\\[tayga-unified:clat:candidate\\]"]
        :if ([:len $candId] > 0) do={
            /container/set ($candId->0) comment=("[tayga-unified:clat] TAYGA CLAT Container (Slot " . $targetSlot . ")")
        }

        # Remove old stopped container now that new candidate is confirmed working
        :put ("--> Removing superseded container from previous slot " . $prevSlot . "...")
        :do { /container/remove $oldCont } on-error={}

        # Update state environment variables
        :local envAct [/container/envs/find where list="tayga-clat-envs" and key="ACTIVE_SLOT"]
        :if ([:len $envAct] > 0) do={ /container/envs/set ($envAct->0) value=$targetSlot }
        :local envGood [/container/envs/find where list="tayga-clat-envs" and key="LAST_GOOD_SLOT"]
        :if ([:len $envGood] > 0) do={ /container/envs/set ($envGood->0) value=$targetSlot }

        :put "--> Re-enabling default route..."
        /ip/route/enable [find where comment~"^\\[tayga-unified:clat:default\\]"]
        :put "============================================================"
        :put (" Upgrade Successful! Active & Confirmed Slot: " . $targetSlot)
        :put "============================================================"
    } else={
        :put "============================================================"
        :put " [ALERT] Upgrade failed! Initiating INSTANT AUTOMATIC ROLLBACK..."
        :put "============================================================"

        # 1. Stop and remove failing candidate container
        :local failedCont [/container/find where comment~"^\\[tayga-unified:clat:candidate\\]"]
        :if ([:len $failedCont] > 0) do={
            :local fc ($failedCont->0)
            :do {
                /container/stop $fc
                :local w 0
                :while (([/container/get $fc stopped] != true) && ($w < 15)) do={
                    :delay 1s
                    :set w ($w + 1)
                }
            } on-error={}
            /container/remove $fc
        }

        # 2. INSTANTLY Restart preserved old container (< 1s, zero file extraction)
        :put ("--> Instantly restarting preserved working container from slot " . $prevSlot . "...")
        /container/start $oldCont
        :local restoredRunning false
        :for i from=1 to=15 do={
            :if ($restoredRunning = false) do={
                :local r [/container/get $oldCont running]
                :if ($r = true) do={ :set restoredRunning true } else={ :delay 1s }
            }
        }

        # Update state
        :local envAct [/container/envs/find where list="tayga-clat-envs" and key="ACTIVE_SLOT"]
        :if ([:len $envAct] > 0) do={ /container/envs/set ($envAct->0) value=$prevSlot }

        # Verify probe on restored container before re-enabling default route
        :delay 3s
        :local restorePingRx [/ping 1.1.1.1 src-address=172.31.64.1 routing-table=tayga-probe-clat count=3]
        :if ($restorePingRx > 0) do={
            :put "--> Restored container probe OK. Re-enabling default route..."
            /ip/route/enable [find where comment~"^\\[tayga-unified:clat:default\\]"]
            :put "============================================================"
            :put (" Automatic Rollback Complete! Restored Active Slot: " . $prevSlot)
            :put "============================================================"
        } else={
            :put "============================================================"
            :put " WARNING: Restored container probe ping did not respond."
            :put " Default route left disabled to prevent traffic disruption."
            :put " Inspect logs: /log print where topics~'container'"
            :put "============================================================"
        }
    }
} on-error={
    :put " [ERROR] Unhandled error occurred during upgrade."
}

# Release Unified Lock strictly by owner
:if ($TAYGA_LOCK_OWNER = "upgrade") do={
    :set TAYGA_LOCK_OWNER "none"
}
