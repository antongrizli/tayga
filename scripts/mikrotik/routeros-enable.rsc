# ==============================================================================
# RouterOS 7 Script: Safely Enable TAYGA Service & Controller
# ==============================================================================
# 1. Resets persistent state to DISCOVERING
# 2. Enables Network State Controller scheduler
# 3. Runs an immediate controller evaluation cycle
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-enable.rsc
# ==============================================================================

:global TAYGA_STATE "DISCOVERING"
:global TAYGA_DIRECT_FAIL_COUNT 0
:global TAYGA_DIRECT_PASS_COUNT 0
:global TAYGA_CLAT_FAIL_COUNT 0

:put "============================================================"
:put " Enabling TAYGA Service & Network State Controller..."
:put "============================================================"

# 1. Detect External Storage Slot & Paths
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
:local controllerScript ($basePath . "/scripts/routeros-controller.rsc")

# 2. Enable Controller Scheduler
:put "--> Enabling /system/scheduler tayga-controller..."
/system/scheduler/enable [find where name="tayga-controller"]

# 3. Trigger immediate evaluation cycle
:put "--> Running initial controller cycle..."
:do {
    /import file-name=$controllerScript
} on-error={
    :put " [WARN] Initial controller run failed; scheduler will retry."
}

:put "============================================================"
:put " TAYGA service enabled and automated controller active!"
:put "============================================================"
