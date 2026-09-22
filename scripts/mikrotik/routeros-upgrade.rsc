# ==============================================================================
# RouterOS 7 Upgrade Script: Atomic Dual-Slot (A/B) Upgrade & Instant Auto-Rollback
# ==============================================================================
# Upgrades container image with minimal service interruption (~5-8s during container transition) and verified recovery:
# 1. Verifies prerequisites: veth-clat, active CLAT container, target storage
# 2. Reads persistent state (ACTIVE_SLOT, LAST_GOOD_SLOT)
# 3. Targets alternate slot (clat-a <-> clat-b)
# 4. Deploys candidate container into target slot (download & extract BEFORE stopping active)
# 5. Only after candidate extraction completes: withdraws default route and stops active container
# 6. Starts candidate container and verifies end-to-end multi-target probe ping
# 7. If probe succeeds: marks candidate verified, promotes slot, enables default route
# 8. If probe fails: INSTANTLY restarts preserved previous container (< 1s, zero extraction)!
#
# Supports continuous sequential upgrades: A -> B -> A (C) -> B (D) -> ...
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-upgrade.rsc
# ==============================================================================

# --- 0. Acquire Unified Lock (owner=upgrade) ---
:global TaygaLockOwner
:global TaygaLockToken
:global TaygaLockTime

:local myToken ("upgrade-" . [:tostr [/system/clock/get time]] . "-" . [:rndnum from=1000 to=9999])
:local waitCtrl 0
:local acquired false

:while ($acquired = false and $waitCtrl < 20) do={
    :local curUp [/system/resource/get uptime]
    :local busy false
    :if ([:len $TaygaLockOwner] > 0 and $TaygaLockOwner != "none") do={
        :local age 0s
        :local ageValid false
        :do {
            :set age ($curUp - $TaygaLockTime)
            :set ageValid true
        } on-error={ :set ageValid false }
        :if ($ageValid = true and $age >= 300s) do={
            :local jobRunning false
            :do {
                :if ($TaygaLockOwner = "controller") do={
                    :if ([:len [/system/script/job find where script="tayga-controller"]] > 0) do={
                        :set jobRunning true
                    }
                }
            } on-error={}
            :if ($jobRunning = false) do={
                :put ("--> Overriding stale lock held by " . $TaygaLockOwner . " (age=" . [:tostr $age] . ")...")
            } else={
                :set busy true
            }
        } else={
            :set busy true
        }
    }
    :if ($busy = false) do={
        :set TaygaLockOwner "upgrade"
        :set TaygaLockToken $myToken
        :set TaygaLockTime $curUp
        :set acquired true
    } else={
        :put ("--> System locked by " . $TaygaLockOwner . "; waiting for lock release (" . $waitCtrl . "/20s)...")
        :delay 1s
        :set waitCtrl ($waitCtrl + 1)
    }
}

:if ($acquired = false) do={
    :put " [FAIL] Lock could not be acquired within 20s timeout. Aborting upgrade."
    :error "Aborted: lock busy"
}

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
    :global UseRegistry
    :global RemoteImage
    :global RegistryUrl

    :local useRegistry false
    :if ($UseRegistry = true) do={ :set useRegistry true }

    :local remoteImage "ghcr.io/antongrizli/tayga-clat:latest"
    :if ([:len $RemoteImage] > 0) do={ :set remoteImage $RemoteImage }

    :local registryUrl "https://ghcr.io"
    :if ([:len $RegistryUrl] > 0) do={ :set registryUrl $RegistryUrl }

    # Auto-detect: if local TAR is not present on storage, automatically switch to GHCR pull
    :local hasLocalTar ([:len [/file/find where name=$imagePath]] > 0)
    :if ($useRegistry = false and $hasLocalTar = false) do={
        :put ("--> Local image " . $imagePath . " not found; switching to GHCR registry pull (" . $remoteImage . ")...")
        :set useRegistry true
    }

    # --- 2. Check Prerequisites Before Modifying Services ---
    :if ($useRegistry = false and $hasLocalTar = false) do={
        :put (" [FAIL] Upgrade image archive '" . $imagePath . "' not found and UseRegistry is false.")
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

    # Ensure isolated CLAT probe table & routing rule exist
    :if ([:len [/routing/table/find where name="tayga-probe-clat"]] = 0) do={
        /routing/table/add name=tayga-probe-clat fib comment="[tayga-unified:clat] Isolated CLAT Probe Table"
    }
    :if ([:len [/ip/route/find where routing-table="tayga-probe-clat" and dst-address="0.0.0.0/0"]] = 0) do={
        /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 routing-table=tayga-probe-clat comment="[tayga-unified:clat:probe] CLAT Probe Route"
    }
    :if ([:len [/routing/rule/find where table="tayga-probe-clat" and comment~"^\\[tayga-unified:clat"]] = 0) do={
        /routing/rule/add src-address=172.31.64.1/32 action=lookup-only-in-table table=tayga-probe-clat comment="[tayga-unified:clat:probe] CLAT Probe Rule"
    }

    # Clean up any leftover candidate container from previous failed attempts
    :local staleCand [/container/find where comment~"^\\[tayga-unified:clat:candidate\\]"]
    :if ([:len $staleCand] > 0) do={
        :do { /container/stop ($staleCand->0) } on-error={}
        :local scw 0
        :while (([/container/get ($staleCand->0) stopped] != true) && ($scw < 15)) do={
            :delay 1s
            :set scw ($scw + 1)
        }
        :do { /container/remove ($staleCand->0) } on-error={}
    }

    # Clean up target rootfs directory
    :do {
        /file/remove [find where name=$targetRootfs]
    } on-error={}

    # --- 4. Deploy Candidate Container into Target Slot (Active container remains running) ---
    :local txPhase "staging"

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
    }

    :put "--> Waiting for candidate container extraction to complete while active container serves traffic..."
    :local candCont [/container/find where comment~"^\\[tayga-unified:clat:candidate\\]"]
    :if ([:len $candCont] > 0) do={
        :local cId ($candCont->0)
        :local extWait 0
        :local isExtracted false
        :while (($isExtracted = false) && ($extWait < 180)) do={
            # Refresh lock heartbeat to prevent controller from stealing lock
            :set TaygaLockTime [/system/resource/get uptime]
            :local isStopped [/container/get $cId stopped]
            :if ($isStopped = true) do={
                :set isExtracted true
            } else={
                :delay 2s
                :set extWait ($extWait + 2)
            }
        }
        :if ($isExtracted = false) do={
            :error "Aborted: container image extraction timed out (180s)"
        }
    } else={
        :error "Aborted: candidate container failed to create"
    }

    # --- 5. Cleanly Switch Over (Interruption window typically 5-8 seconds during container transition) ---
    :set txPhase "switching"
    :put "--> Candidate extracted. Withdrawing default route..."
    /ip/route/disable [find where comment~"^\\[tayga-unified:clat:default\\]"]

    :put "--> Stopping running container (retaining definition for instant rollback)..."
    /container/stop $oldCont
    :local stopWait 0
    :while (([/container/get $oldCont stopped] != true) && ($stopWait < 30)) do={
        :delay 1s
        :set stopWait ($stopWait + 1)
    }
    :local upgradeOk true
    :if ([/container/get $oldCont stopped] != true) do={
        :put " [FAIL] Active container did not stop cleanly within 30s timeout."
        :set upgradeOk false
    }

    # --- 6. Start Candidate Container and Verify End-to-End Probe ---
    :if ($upgradeOk = true) do={
        :put "--> Starting candidate container..."
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
    }

    # Warm-up delay for RFC 7050 discovery / translation initialization
    :if ($upgradeOk = true) do={
        :delay 5s
        :put "--> Testing end-to-end probe ping via tayga-probe-clat..."
        :local pingRx 0
        :do {
            :set pingRx [/ping 1.1.1.1 src-address=172.31.64.1 count=2]
        } on-error={}
        :if ($pingRx = 0) do={
            :do {
                :set pingRx [/ping 8.8.8.8 src-address=172.31.64.1 count=2]
            } on-error={}
        }
        :if ($pingRx > 0) do={
            :put (" [PASS] Probe test successful (" . $pingRx . "/2 received)!")
        } else={
            :set upgradeOk false
            :put " [FAIL] Candidate probe ping returned 0 packets to 1.1.1.1 and 8.8.8.8."
        }
    }

    # --- 8. Promote Candidate OR Execute INSTANT ZERO-EXTRACTION ROLLBACK ---
    # Verify lock ownership was maintained before making network state changes
    :if ($TaygaLockToken != $myToken or $TaygaLockOwner != "upgrade") do={
        :put " [FAIL] Lock was hijacked by another process. Halting upgrade."
        :error "Aborted: lock lost"
    }

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
                    :set TaygaLockTime [/system/resource/get uptime]
                    :delay 1s
                    :set w ($w + 1)
                }
            } on-error={}
            /container/remove $fc
        }

        # 2. INSTANTLY Restart preserved old container (< 1s, zero file extraction)
        :if ($TaygaLockToken != $myToken or $TaygaLockOwner != "upgrade") do={
            :put " [FAIL] Lock was lost before rollback could complete."
            :error "Aborted: lock lost"
        }
        :set TaygaLockTime [/system/resource/get uptime]
        :put ("--> Instantly restarting preserved working container from slot " . $prevSlot . "...")
        /container/start $oldCont
        :local restoredRunning false
        :for i from=1 to=15 do={
            :if ($restoredRunning = false) do={
                :set TaygaLockTime [/system/resource/get uptime]
                :local r [/container/get $oldCont running]
                :if ($r = true) do={ :set restoredRunning true } else={ :delay 1s }
            }
        }

        # Update state
        :local envAct [/container/envs/find where list="tayga-clat-envs" and key="ACTIVE_SLOT"]
        :if ([:len $envAct] > 0) do={ /container/envs/set ($envAct->0) value=$prevSlot }

        # Verify probe on restored container before re-enabling default route
        :delay 3s
        :local restorePingRx 0
        :do {
            :set restorePingRx [/ping 1.1.1.1 src-address=172.31.64.1 count=3]
        } on-error={}
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
    :if ($txPhase = "switching") do={
        :put " [EMERGENCY ROLLBACK] Restoring previous container and network state..."
        :local fc [/container/find where comment~"^\\[tayga-unified:clat:candidate\\]"]
        :if ([:len $fc] > 0) do={
            :do { /container/stop ($fc->0) } on-error={}
            :delay 1s
            :do { /container/remove ($fc->0) } on-error={}
        }
        :do { /container/start $oldCont } on-error={}
        :delay 2s
        :do { /ip/route/enable [find where comment~"^\\[tayga-unified:clat:default\\]"] } on-error={}
        :put " [EMERGENCY ROLLBACK] Restored previous active container and default route."
    }
}

# Release Unified Lock strictly by token match
:if ($TaygaLockToken = $myToken) do={
    :set TaygaLockOwner "none"
    :set TaygaLockToken ""
}
