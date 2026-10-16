# ==============================================================================
# RouterOS 7 Script: Safely Disable TAYGA Service & Controller
# ==============================================================================
# 1. Acquires Unified Lock (owner=disable) and disables scheduler
# 2. Waits for any active controller run to finish (with strict 20s timeout)
# 3. Sets persistent TaygaState to DISABLED
# 4. Disables CLAT default route and re-enables parked direct WAN default routes
# 5. Cleanly stops running TAYGA CLAT and NAT64 containers
# 6. Releases Unified Lock
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-disable.rsc
# ==============================================================================

:global TaygaLockOwner
:global TaygaLockToken
:global TaygaLockTime
:global TaygaState
:global TaygaParkedRouteIds

:put "============================================================"
:put " Disabling TAYGA Service & Network State Controller..."
:put "============================================================"

# 1. Acquire Unified Lock with 20s wait
:local myToken ("disable-" . [:tostr [/system/clock/get time]] . "-" . [:rndnum from=1000 to=9999])
:local waitCount 0
:local acquired false

:while ($acquired = false and $waitCount < 20) do={
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
        :set TaygaLockOwner "disable"
        :set TaygaLockToken $myToken
        :set TaygaLockTime $curUp
        :set acquired true
    } else={
        :put ("--> System locked by " . $TaygaLockOwner . "; waiting for lock release (" . $waitCount . "/20s)...")
        :delay 1s
        :set waitCount ($waitCount + 1)
    }
}

:if ($acquired = false) do={
    :put " [FAIL] Lock could not be acquired within 20s timeout. Aborting disable."
    :error "Aborted: lock busy"
}

:do {
    # Verify lock ownership was maintained before making network state changes
    :if ($TaygaLockToken != $myToken or $TaygaLockOwner != "disable") do={
        :put " [FAIL] Lock was lost before disable operations could start."
        :error "Aborted: lock lost"
    }
    # 2. Disable Controller Scheduler
    :put "--> Disabling /system/scheduler tayga-controller..."
    /system/scheduler/disable [find where name="tayga-controller"]

    # 3. Set persistent state to DISABLED
    :set TaygaState "DISABLED"

    # 4. Disable CLAT default route in main table
    :put "--> Withdrawing CLAT default route..."
    /ip/route/disable [find where comment~"^\\[tayga-unified:clat:default\\]"]

    # 5. Disable NAT64 prefix route if active
    :put "--> Withdrawing NAT64 prefix route..."
    /ipv6/route/disable [find where comment~"^\\[tayga-unified:nat64(:prefix)?\\]"]

    # 6. Restore specifically parked direct WAN default routes
    :put "--> Restoring parked direct WAN default routes..."
    :if ([:len $TaygaParkedRouteIds] > 0) do={
        :local remainingParked [:toarray ""]
        :foreach pid in=$TaygaParkedRouteIds do={
            :local restored false
            :do {
                :if ([:len [/ip/route/find where .id=$pid]] > 0) do={
                    :put ("--> Re-enabling route: " . $pid)
                    /ip/route/enable $pid
                    :if ([/ip/route/get $pid disabled] = false) do={
                        :set restored true
                        :local c [/ip/route/get $pid comment]
                        :if ($c ~ "\\[tayga-parked:wan-direct\\]") do={
                            :local tagPos [:find $c " [tayga-parked:wan-direct]"]
                            :if ([:len $tagPos] > 0) do={
                                /ip/route/set $pid comment=[:pick $c 0 $tagPos]
                            } else={
                                :set tagPos [:find $c "[tayga-parked:wan-direct]"]
                                :if ([:len $tagPos] > 0) do={
                                    /ip/route/set $pid comment=[:pick $c 0 $tagPos]
                                }
                            }
                        }
                    }
                } else={
                    :set restored true
                }
            } on-error={}
            :if ($restored = false) do={
                :set remainingParked ($remainingParked, $pid)
            }
        }
        :set TaygaParkedRouteIds $remainingParked
    }

    # Sweep any persistent tagged routes not captured in tracking
    :local leftoverParked [/ip/route/find where comment~"\\[tayga-parked:wan-direct\\]"]
    :foreach lp in=$leftoverParked do={
        :do {
            /ip/route/enable $lp
            :if ([/ip/route/get $lp disabled] = false) do={
                :local c [/ip/route/get $lp comment]
                :local tagPos [:find $c " [tayga-parked:wan-direct]"]
                :if ([:len $tagPos] > 0) do={
                    /ip/route/set $lp comment=[:pick $c 0 $tagPos]
                } else={
                    :set tagPos [:find $c "[tayga-parked:wan-direct]"]
                    :if ([:len $tagPos] > 0) do={
                        /ip/route/set $lp comment=[:pick $c 0 $tagPos]
                    }
                }
            }
        } on-error={}
    }

    # 7. Stop running containers cleanly
    :put "--> Stopping TAYGA containers..."
    :local conts [/container/find where comment~"^\\[tayga-unified"]
    :foreach c in=$conts do={
        :do {
            /container/stop $c
        } on-error={}
    }

    :put "============================================================"
    :put " TAYGA service disabled safely. Direct WAN routes restored."
    :put " To re-enable, run routeros-enable.rsc."
    :put "============================================================"
} on-error={
    :put " [ERROR] An unexpected error occurred while disabling service."
}

# Release Unified Lock strictly by token match
:if ($TaygaLockToken = $myToken) do={
    :set TaygaLockOwner "none"
    :set TaygaLockToken ""
}
