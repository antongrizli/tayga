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

:global TAYGA_MAINTENANCE_LOCK true

:put "============================================================"
:put " Starting State-Driven Dual-Slot (A/B) TAYGA Upgrade..."
:put "============================================================"

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
:local prevRootfs ($basePath . "/rootfs/" . $prevSlot)
:put ("--> Active Slot : " . $prevSlot . " (" . $curRootDir . ")")
:put ("--> Target Slot : " . $targetSlot . " (" . $targetRootfs . ")")

# --- 4. Clean Stale Candidate Container (Strict Ownership Verification) ---
:local staleCandidate [/container/find where root-dir=$targetRootfs]
:if ([:len $staleCandidate] > 0) do={
    :foreach sc in=$staleCandidate do={
        :local scComm [/container/get $sc comment]
        :local scIf [/container/get $sc interface]
        :if ($scComm ~ "^\\[tayga-unified:clat" and $scIf = "veth-clat") do={
            :put ("--> Cleaning stale candidate container registration on " . $targetRootfs . "...")
            :do { /container/stop $sc } on-error={}
            :local sw 0
            :while (([/container/get $sc stopped] != true) && ($sw < 15)) do={
                :delay 1s
                :set sw ($sw + 1)
            }
            :if ([/container/get $sc stopped] != true) do={
                :error "Aborted: stale candidate container did not stop. Aborting to protect system state."
            }
            /container/remove $sc
        } else={
            :put (" [FAIL] Target slot " . $targetRootfs . " is occupied by unowned container. Aborting.")
            :error "Aborted: target slot occupied by unowned container"
        }
    }
}

# --- 5. Temporarily withdraw default route to prevent blackholing ---
:put "--> Withdrawing default route..."
/ip/route/disable [find where comment~"^\\[tayga-unified:clat:default\\]"]

# Ensure service probe and IPv6 return routes are active
/ip/route/enable [find where comment~"^\\[tayga-unified:clat:probe\\]"]
/ipv6/route/enable [find where comment~"^\\[tayga-unified:clat\\]"]

# --- 6. Stop running container (KEEP DEFINITION FOR FAST ZERO-EXTRACTION ROLLBACK) ---
:put "--> Stopping running container (retaining definition for instant rollback)..."
/container/stop $oldCont
:local waits 0
:while (([/container/get $oldCont stopped] != true) && ($waits < 30)) do={
    :delay 1s
    :set waits ($waits + 1)
}

:if ([/container/get $oldCont stopped] != true) do={
    :put " [FAIL] Active container did not stop within 30s timeout. Restoring default route and aborting."
    /ip/route/enable [find where comment~"^\\[tayga-unified:clat:default\\]"]
    :error "Aborted: container stop timed out"
}

# --- 7. Deploy upgraded candidate container into target slot ---
:local upgradeOk true
:do {
    :if ($useRegistry = true) do={
        :put ("--> Setting container registry URL: " . $registryUrl . "...")
        :do { /container/config/set registry-url=$registryUrl } on-error={}
        
        :put ("--> Pulling candidate remote image '" . $remoteImage . "' into " . $targetRootfs . "...")
        /container/add remote-image=$remoteImage \
            root-dir=$targetRootfs \
            interface=veth-clat \
            envlist=tayga-clat-envs \
            memory-high=128M \
            memory-max=192M \
            start-on-boot=yes \
            restart-policy=on-failure \
            restart-interval=10s \
            logging=yes \
            comment=("[tayga-unified:clat:candidate] TAYGA CLAT Container (Slot " . $targetSlot . ")")
        
        # RouterOS pulls and extracts remote image in background: wait until extraction completes (status stopped)
        :put "--> Downloading and extracting layers from GHCR (may take 10-60s)..."
        :local candCont [/container/find where comment~"^\\[tayga-unified:clat:candidate\\]"]
        :if ([:len $candCont] > 0) do={
            :local candId ($candCont->0)
            :local extWait 0
            :local isExtracted false
            :while (($isExtracted = false) && ($extWait < 180)) do={
                :local isStopped [/container/get $candId stopped]
                :if ($isStopped = true) do={
                    :set isExtracted true
                } else={
                    :delay 2s
                    :set extWait ($extWait + 2)
                }
            }
            :if ($isExtracted = false) do={
                :put " [FAIL] Remote image download/extraction timed out (180s)."
                :set upgradeOk false
            } else={
                :put " [PASS] Container image layers downloaded and extracted successfully."
            }
        } else={
            :set upgradeOk false
            :put " [FAIL] Candidate container entry was not created."
        }
    } else={
        :put ("--> Extracting local candidate image " . $imagePath . " into " . $targetRootfs . "...")
        /container/add file=$imagePath \
            root-dir=$targetRootfs \
            interface=veth-clat \
            envlist=tayga-clat-envs \
            memory-high=128M \
            memory-max=192M \
            start-on-boot=yes \
            restart-policy=on-failure \
            restart-interval=10s \
            logging=yes \
            comment=("[tayga-unified:clat:candidate] TAYGA CLAT Container (Slot " . $targetSlot . ")")
        :delay 3s
    }
} on-error={
    :set upgradeOk false
    :put " [FAIL] Failed to extract/add candidate container."
}

:local candidateCont [/container/find where comment~"^\\[tayga-unified:clat:candidate\\]"]
:if ($upgradeOk = true and [:len $candidateCont] > 0) do={
    :local candId ($candidateCont->0)
    :put "--> Starting candidate container..."
    :do {
        /container/start $candId
    } on-error={
        :set upgradeOk false
    }
    
    # Poll for running state (up to 30s)
    :local isRunning false
    :for i from=1 to=30 do={
        :if ($isRunning = false) do={
            :local r [/container/get $candId running]
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
    :put "--> Testing end-to-end probe ping (1.1.1.1)..."
    :local pingRx [/ping 1.1.1.1 src-address=172.31.64.1 count=3]
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
    :local restorePingRx [/ping 1.1.1.1 src-address=172.31.64.1 count=3]
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

:set TAYGA_MAINTENANCE_LOCK false

