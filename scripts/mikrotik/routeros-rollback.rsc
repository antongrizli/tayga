# ==============================================================================
# RouterOS 7 Rollback Script: Emergency Revert to Previous Working State
# ==============================================================================
# 1. Verifies CLAT prerequisites (veth-clat, CLAT configuration)
# 2. Withdraws default route ONLY (keeps service probe and return routes active)
# 3. Stops and removes failing CLAT container instance (strictly ignores NAT64)
# 4. Restores container definition pointing to previous working rootfs slot
# 5. Starts restored container and polls for running state
# 6. Tests probe ping (1.1.1.1) via active probe route
# 7. Re-enables default route only when probe succeeds
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-rollback.rsc
# ==============================================================================

# --- 0. Acquire Unified Lock (owner=rollback) ---
:global TAYGA_LOCK_OWNER
:global TAYGA_LOCK_TIME

:local waitCtrl 0
:while ([:len $TAYGA_LOCK_OWNER] > 0 and $TAYGA_LOCK_OWNER != "none" and $TAYGA_LOCK_OWNER != "rollback" and $waitCtrl < 20) do={
    :put ("--> System locked by " . $TAYGA_LOCK_OWNER . "; waiting for lock release (" . $waitCtrl . "/20s)...")
    :delay 1s
    :set waitCtrl ($waitCtrl + 1)
}
:if ([:len $TAYGA_LOCK_OWNER] > 0 and $TAYGA_LOCK_OWNER != "none" and $TAYGA_LOCK_OWNER != "rollback") do={
    :put " [FAIL] Lock could not be acquired within 20s timeout. Aborting rollback."
    :error "Aborted: lock busy"
}
:set TAYGA_LOCK_OWNER "rollback"
:set TAYGA_LOCK_TIME [/system/resource/get uptime]

:do {
    :put "============================================================"
    :put " Starting Emergency CLAT Rollback..."
    :put "============================================================"

    # Migration cleanup: Remove any legacy /32 probe route from main table
    :do { /ip/route/remove [find where dst-address="1.1.1.1/32" and comment~"^\\[tayga-unified"] } on-error={}

    # --- 1. Verify Prerequisites Before Making Any Changes ---
    :if ([:len [/interface/veth/find where name="veth-clat"]] = 0) do={
        :put " [FAIL] Required interface 'veth-clat' not found. Rollback is only valid for CLAT installations."
        :error "Aborted: veth-clat interface missing"
    }

    # Ensure isolated CLAT probe table exists
    :if ([:len [/routing/table/find where name="tayga-probe-clat"]] = 0) do={
        /routing/table/add name=tayga-probe-clat fib comment="[tayga-unified:clat] Isolated CLAT Probe Table"
    }
    :if ([:len [/ip/route/find where routing-table="tayga-probe-clat" and dst-address="0.0.0.0/0"]] = 0) do={
        /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 routing-table=tayga-probe-clat comment="[tayga-unified:clat:probe] CLAT Probe Route"
    }

    # --- 2. Withdraw default route ONLY (service routes must remain active for probe) ---
    :put "--> Disabling default route (preserving service probe and mapped IPv6 routes)..."
    /ip/route/disable [find where comment~"^\\[tayga-unified:clat:default\\]"]

    # Ensure service IPv6 return routes are active
    /ipv6/route/enable [find where comment~"^\\[tayga-unified:clat\\]"]

    # --- 3. Detect Storage Slot & Paths ---
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
    :local prevImagePath ($basePath . "/images/tayga-arm64-prev.tar")

    # --- 4. Determine Target Rollback Slot from Confirmed LAST_GOOD_SLOT ---
    :local restoreSlot "clat-a"
    :local envGood [/container/envs/find where list="tayga-clat-envs" and key="LAST_GOOD_SLOT"]
    :if ([:len $envGood] > 0) do={
        :set restoreSlot [/container/envs/get ($envGood->0) value]
    }
    :local baseRootfs ($basePath . "/rootfs/" . $restoreSlot)
    :put ("--> Target Rollback Slot: " . $restoreSlot . " (" . $baseRootfs . ")")

    # --- 5. Stop and Remove Any Failing / Candidate CLAT Containers ---
    :local clatConts [/container/find where comment~"^\\[tayga-unified:clat" and interface="veth-clat"]
    :foreach c in=$clatConts do={
        :local cRoot [/container/get $c root-dir]
        :if (!($cRoot ~ $restoreSlot)) do={
            :put ("--> Stopping unconfirmed / candidate container on " . $cRoot . "...")
            /container/stop $c
            :local waits 0
            :while (([/container/get $c stopped] != true) && ($waits < 30)) do={
                :delay 1s
                :set waits ($waits + 1)
            }
            :if ([/container/get $c stopped] != true) do={
                :put " [FAIL] Container did not stop within 30s timeout. Aborting rollback."
                :error "Aborted: container stop timed out"
            }
            /container/remove $c
        }
    }

    # --- 6. Start or Re-create Confirmed Container for LAST_GOOD_SLOT ---
    :local goodCont [/container/find where root-dir~$restoreSlot and comment~"^\\[tayga-unified:clat" and interface="veth-clat"]
    :if ([:len $goodCont] = 0) do={
        :local targetImg $prevImagePath
        :if ([:len [/file/find where name=$prevImagePath]] = 0) do={
            :if ([:len [/file/find where name=$imagePath]] > 0) do={
                :put "--> Previous image archive not found; using verified base image archive..."
                :set targetImg $imagePath
            } else={
                :put " [FAIL] No container definition or valid image archive found for rollback."
                :error "Aborted: missing rollback container and image archive"
            }
        }

        :put ("--> Re-creating container from " . $targetImg . " into slot " . $restoreSlot . "...")
        /container/add file=$targetImg \
            root-dir=$baseRootfs \
            interface=veth-clat \
            envlist=tayga-clat-envs \
            memory-high=128M \
            memory-max=192M \
            start-on-boot=no \
            restart-policy=on-failure \
            restart-interval=10s \
            logging=yes \
            comment=("[tayga-unified:clat] TAYGA CLAT Container (Slot " . $restoreSlot . ")")
        :delay 3s
        :set goodCont [/container/find where root-dir~$restoreSlot and comment~"^\\[tayga-unified:clat" and interface="veth-clat"]
    }

    :if ([:len $goodCont] > 0) do={
        :local cid ($goodCont->0)
        :local isRun [/container/get $cid running]
        :if ($isRun != true) do={
            :put "--> Starting restored container..."
            /container/start $cid
        }

        # Poll for running state (up to 30s)
        :local isRunning false
        :for i from=1 to=30 do={
            :if ($isRunning = false) do={
                :local r [/container/get $cid running]
                :if ($r = true) do={
                    :set isRunning true
                } else={
                    :delay 1s
                }
            }
        }
    }

    :put "--> Waiting 5s for translation warm-up..."
    :delay 5s

    # --- 7. Probe Verification via Isolated Probe Table ---
    :put "--> Testing end-to-end probe ping via tayga-probe-clat..."
    :local probeOk false
    :local pingRx [/ping 1.1.1.1 src-address=172.31.64.1 routing-table=tayga-probe-clat count=3]
    :if ($pingRx > 0) do={
        :set probeOk true
        :put (" [PASS] Probe test successful (" . $pingRx . "/3 received) after rollback!")
    }

    # --- 8. Re-enable Default Route ONLY if Probe Succeeded ---
    :if ($probeOk = true) do={
        :local envAct [/container/envs/find where list="tayga-clat-envs" and key="ACTIVE_SLOT"]
        :if ([:len $envAct] > 0) do={ /container/envs/set ($envAct->0) value=$restoreSlot }

        :put "--> Restoring default route..."
        /ip/route/enable [find where comment~"^\\[tayga-unified:clat:default\\]"]
        :put "============================================================"
        :put (" Rollback Completed Successfully. Active Slot: " . $restoreSlot)
        :put "============================================================"
    } else={
        :put "============================================================"
        :put " WARNING: Container restored but probe ping did not respond."
        :put " Default route left disabled to prevent traffic blackholing."
        :put " Inspect logs: /log print where topics~'container'"
        :put "============================================================"
    }
} on-error={
    :put " [ERROR] Unhandled error during rollback."
}

# Release Unified Lock strictly by owner
:if ($TAYGA_LOCK_OWNER = "rollback") do={
    :set TAYGA_LOCK_OWNER "none"
}
