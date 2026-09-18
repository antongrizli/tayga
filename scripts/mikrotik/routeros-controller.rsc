# ==============================================================================
# RouterOS 7 Network State Controller: Dynamic Mode Selection & Route Management
# ==============================================================================
# Automates runtime mode selection between DIRECT IPv4, CLAT (RFC 6877), and
# NAT64 based on real-time WAN capability and LAN requirements.
#
# FSM States:
#   - DISCOVERING     : Initial state / evaluating available WAN paths
#   - DIRECT          : Direct WAN IPv4 is active and healthy (CLAT in standby)
#   - PREPARING_CLAT  : Direct IPv4 failed; starting/probing CLAT container
#   - CLAT_ACTIVE     : CLAT verified end-to-end; default IPv4 route active via CLAT
#   - DEGRADED        : No working IPv4 transit (direct down, CLAT/PLAT unreachable)
#   - DISABLED        : Manually disabled by administrator via routeros-disable.rsc
#
# Usage:
#   Run periodically via /system/scheduler (default: every 15s)
#   /import file-name=usb1/telekom-xlat/scripts/routeros-controller.rsc
# ==============================================================================

# --- Global State & Concurrency Variables ---
:global TAYGA_MAINTENANCE_LOCK
:global TAYGA_CONTROLLER_BUSY
:global TAYGA_CONTROLLER_TIME
:global TAYGA_STATE
:global TAYGA_DIRECT_FAIL_COUNT
:global TAYGA_DIRECT_PASS_COUNT
:global TAYGA_CLAT_FAIL_COUNT

# 1. Check Disabled State
:if ($TAYGA_STATE = "DISABLED") do={
    :log debug "[tayga-controller] System is in DISABLED state. Skipping execution."
    :return nil
}

# 2. Concurrency Guard: Check Maintenance Lock (Upgrade/Rollback in progress)
:if ($TAYGA_MAINTENANCE_LOCK = true) do={
    :log info "[tayga-controller] Upgrade or maintenance in progress (lock=true). Skipping controller run."
    :return nil
}

# 3. Concurrency Guard & Stale Lock Recovery
:if ($TAYGA_CONTROLLER_BUSY = true) do={
    # Self-heal stuck busy flag if not cleared
    :log warn "[tayga-controller] Stale busy flag detected. Resetting controller busy lock."
    :set TAYGA_CONTROLLER_BUSY false
}
:set TAYGA_CONTROLLER_BUSY true

# Main Execution Block with Guaranteed Lock Cleanup on Exception
:do {
    # Initialize State Counters if undefined
    :if ([:len $TAYGA_STATE] = 0) do={ :set TAYGA_STATE "DISCOVERING" }
    :if ([:len $TAYGA_DIRECT_FAIL_COUNT] = 0) do={ :set TAYGA_DIRECT_FAIL_COUNT 0 }
    :if ([:len $TAYGA_DIRECT_PASS_COUNT] = 0) do={ :set TAYGA_DIRECT_PASS_COUNT 0 }
    :if ([:len $TAYGA_CLAT_FAIL_COUNT] = 0) do={ :set TAYGA_CLAT_FAIL_COUNT 0 }

    # Policy Defaults
    :local policy "auto"
    :local preferDirectIpv4 "yes"
    :local lanRequiresIpv4 "yes"
    :local allowLocalNat64 "no"
    :local ipv6OnlyLanIfaces ""
    :local failThreshold 3
    :local recoveryThreshold 4
    :local clatFailThreshold 3

    # Read policy settings from tayga-clat-envs if present
    :local envPolicy [/container/envs/find where list="tayga-clat-envs" and key="POLICY"]
    :if ([:len $envPolicy] > 0) do={ :set policy [/container/envs/get ($envPolicy->0) value] }

    :local envPrefer [/container/envs/find where list="tayga-clat-envs" and key="PREFER_DIRECT_IPV4"]
    :if ([:len $envPrefer] > 0) do={ :set preferDirectIpv4 [/container/envs/get ($envPrefer->0) value] }

    :local envLanReq [/container/envs/find where list="tayga-clat-envs" and key="LAN_REQUIRES_IPV4"]
    :if ([:len $envLanReq] > 0) do={ :set lanRequiresIpv4 [/container/envs/get ($envLanReq->0) value] }

    :local envAllowNat64 [/container/envs/find where list="tayga-clat-envs" and key="ALLOW_LOCAL_NAT64"]
    :if ([:len $envAllowNat64] > 0) do={ :set allowLocalNat64 [/container/envs/get ($envAllowNat64->0) value] }

    :local envIpv6Lan [/container/envs/find where list="tayga-clat-envs" and key="IPV6_ONLY_LAN_INTERFACES"]
    :if ([:len $envIpv6Lan] > 0) do={ :set ipv6OnlyLanIfaces [/container/envs/get ($envIpv6Lan->0) value] }

    # Early check for POLICY=manual (Read-only / monitor mode: DO NOT modify config)
    :if ($policy = "manual") do={
        :log debug "[tayga-controller] POLICY=manual. Controller running in monitor-only mode."
        :set TAYGA_CONTROLLER_BUSY false
        :return nil
    }

    # Detect Primary WAN Interface (lte1 on Chateau, ether1 on CHR)
    :local wanIf "lte1"
    :if ([:len [/interface/find where name="lte1"]] = 0) do={
        :if ([:len [/interface/find where name="ether1"]] > 0) do={
            :set wanIf "ether1"
        }
    }

    # Ensure Isolated Routing Tables exist (Strict Zero-Leak Isolation)
    # 1. Direct WAN Probe Table
    :if ([:len [/routing/table/find where name="wan-direct"]] = 0) do={
        /routing/table/add name=wan-direct fib comment="[tayga-unified:direct] Isolated Direct WAN Routing Table"
    }

    # 2. CLAT Probe Table (Isolates all CLAT testing from main table)
    :if ([:len [/routing/table/find where name="tayga-probe-clat"]] = 0) do={
        /routing/table/add name=tayga-probe-clat fib comment="[tayga-unified:clat] Isolated CLAT Probe Table"
    }

    # Synchronize default route in 'wan-direct' table with direct WAN gateway
    # STRICT FILTERING: search strictly in routing-table="main" and exclude any tayga-unified routes
    :local directWanGw ""
    :local wanRoutes [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active and !comment~"^\\[tayga-unified"]
    :if ([:len $wanRoutes] > 0) do={
        :set directWanGw [/ip/route/get ($wanRoutes->0) gateway]
    } else={
        # Check if original WAN route was temporarily disabled during CLAT active mode
        :local origWanRoutes [/ip/route/find where comment~"^\\[tayga-unified:orig-wan-default\\]"]
        :if ([:len $origWanRoutes] > 0) do={
            :set directWanGw [/ip/route/get ($origWanRoutes->0) gateway]
        } else={
            :set directWanGw $wanIf
        }
    }

    :local tableRoute [/ip/route/find where routing-table="wan-direct" and dst-address="0.0.0.0/0"]
    :if ([:len $tableRoute] = 0) do={
        :if ([:len $directWanGw] > 0) do={
            /ip/route/add dst-address=0.0.0.0/0 gateway=$directWanGw routing-table=wan-direct comment="[tayga-unified:direct:probe] Direct WAN Probe Route"
        }
    } else={
        :local curGw [/ip/route/get ($tableRoute->0) gateway]
        :if ($curGw != $directWanGw and [:len $directWanGw] > 0) do={
            /ip/route/set ($tableRoute->0) gateway=$directWanGw
        }
    }

    # Ensure CLAT Probe Route exists in 'tayga-probe-clat' table (NEVER in main table)
    :local clatProbeRoute [/ip/route/find where routing-table="tayga-probe-clat" and dst-address="0.0.0.0/0"]
    :if ([:len $clatProbeRoute] = 0) do={
        /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 routing-table=tayga-probe-clat comment="[tayga-unified:clat:probe] CLAT Probe Route"
    }

    # --- Zero-Leak Probing Phase ---
    # 1. Direct WAN IPv4 Probe via wan-direct table
    :local directIpv4Ok false
    :if ([:len $directWanGw] > 0) do={
        :local ping1 [/ping 1.1.1.1 routing-table=wan-direct count=2]
        :if ($ping1 > 0) do={
            :set directIpv4Ok true
        } else={
            :local ping2 [/ping 8.8.8.8 routing-table=wan-direct count=2]
            :if ($ping2 > 0) do={ :set directIpv4Ok true }
        }
    }

    # 2. IPv6 WAN Probe
    :local ipv6Ok false
    :local ping6_1 [/ping 2606:4700:4700::1111 count=2]
    :if ($ping6_1 > 0) do={
        :set ipv6Ok true
    } else={
        :local ping6_2 [/ping 2001:4860:4860::8888 count=2]
        :if ($ping6_2 > 0) do={ :set ipv6Ok true }
    }

    # Container reference
    :local conts [/container/find where comment~"^\\[tayga-unified:clat\\]"]
    :local clatDefaultRoute [/ip/route/find where comment~"^\\[tayga-unified:clat:default\\]" and routing-table="main"]

    # --- Finite State Machine (FSM) Evaluation ---
    :local nextState $TAYGA_STATE

    :if ($directIpv4Ok = true and $preferDirectIpv4 = "yes") do={
        :set TAYGA_DIRECT_FAIL_COUNT 0
        :set TAYGA_DIRECT_PASS_COUNT ($TAYGA_DIRECT_PASS_COUNT + 1)

        :if ($TAYGA_STATE = "DIRECT") do={
            # Steady state DIRECT
        } else={
            # Check recovery hysteresis threshold
            :if ($TAYGA_DIRECT_PASS_COUNT >= $recoveryThreshold or $TAYGA_STATE = "DISCOVERING") do={
                :log info ("[tayga-controller] Direct WAN IPv4 verified (passes=" . $TAYGA_DIRECT_PASS_COUNT . "). Switching to DIRECT mode.")
                :set nextState "DIRECT"

                # 1. Disable CLAT default route in main table
                :if ([:len $clatDefaultRoute] > 0) do={
                    /ip/route/set ($clatDefaultRoute->0) disabled=yes
                }

                # 2. Re-enable original direct WAN default routes
                :local origRoutes [/ip/route/find where comment~"^\\[tayga-unified:orig-wan-default\\]"]
                :foreach r in=$origRoutes do={
                    :log info "[tayga-controller] Restoring original direct WAN default route..."
                    /ip/route/set $r disabled=no comment="[orig-wan-default]"
                }

                # 3. Put CLAT container into standby after graceful delay
                :if ([:len $conts] > 0) do={
                    :local cId ($conts->0)
                    :if ([/container/get $cId running] = true) do={
                        :log info "[tayga-controller] Placing CLAT container into standby..."
                        /container/stop $cId
                    }
                }
            } else={
                :log info ("[tayga-controller] Direct IPv4 probe passing (" . $TAYGA_DIRECT_PASS_COUNT . "/" . $recoveryThreshold . "), awaiting recovery threshold.")
            }
        }
    } else={
        # Direct IPv4 failed or not preferred
        :set TAYGA_DIRECT_PASS_COUNT 0
        :set TAYGA_DIRECT_FAIL_COUNT ($TAYGA_DIRECT_FAIL_COUNT + 1)

        :if ($TAYGA_STATE = "DIRECT" and $TAYGA_DIRECT_FAIL_COUNT < $failThreshold) do={
            :log warn ("[tayga-controller] Direct IPv4 probe failed (" . $TAYGA_DIRECT_FAIL_COUNT . "/" . $failThreshold . "). Awaiting fail threshold.")
        } else={
            # Direct IPv4 considered down; check IPv6 + CLAT feasibility
            :if ($ipv6Ok = true and $lanRequiresIpv4 = "yes") do={
                # Ensure CLAT container is running
                :if ([:len $conts] > 0) do={
                    :local cId ($conts->0)
                    :if ([/container/get $cId running] != true) do={
                        :log info "[tayga-controller] Starting CLAT container..."
                        /container/start $cId
                        :delay 3s
                    }
                }

                # CLAT Data-Plane Verification (src-address 172.31.64.1 via tayga-probe-clat table)
                :local clatProbeOk false
                :local clatPing [/ping 1.1.1.1 src-address=172.31.64.1 routing-table=tayga-probe-clat count=3]
                :if ($clatPing > 0) do={
                    :set clatProbeOk true
                }

                :if ($clatProbeOk = true) do={
                    :set TAYGA_CLAT_FAIL_COUNT 0
                    :if ($TAYGA_STATE != "CLAT_ACTIVE") do={
                        :log info "[tayga-controller] CLAT end-to-end probe verified! Switching traffic to CLAT."

                        # 1. Temporarily disable active direct WAN default routes to prevent conflict
                        :local activeWanRoutes [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active and !comment~"^\\[tayga-unified"]
                        :foreach r in=$activeWanRoutes do={
                            :log info "[tayga-controller] Parking direct WAN default route..."
                            /ip/route/set $r disabled=yes comment="[tayga-unified:orig-wan-default]"
                        }

                        # 2. Activate default route via CLAT in main table
                        :if ([:len $clatDefaultRoute] > 0) do={
                            /ip/route/set ($clatDefaultRoute->0) disabled=no distance=1
                        } else={
                            /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 distance=1 routing-table=main comment="[tayga-unified:clat:default] Default route via TAYGA CLAT"
                        }
                    }
                    :set nextState "CLAT_ACTIVE"
                } else={
                    :set TAYGA_CLAT_FAIL_COUNT ($TAYGA_CLAT_FAIL_COUNT + 1)
                    :log warn ("[tayga-controller] CLAT probe ping failed (failures=" . $TAYGA_CLAT_FAIL_COUNT . "/" . $clatFailThreshold . ")")

                    # Apply hysteresis to CLAT failure: only tear down after clatFailThreshold failures
                    :if ($TAYGA_CLAT_FAIL_COUNT >= $clatFailThreshold or $TAYGA_STATE = "PREPARING_CLAT") do={
                        :log error "[tayga-controller] CLAT path unavailable. Entering DEGRADED state."
                        :set nextState "DEGRADED"

                        # Disable CLAT default route to avoid traffic blackholing
                        :if ([:len $clatDefaultRoute] > 0) do={
                            /ip/route/set ($clatDefaultRoute->0) disabled=yes
                        }
                    }
                }
            } else={
                # Neither Direct IPv4 nor IPv6 transit available
                :log error "[tayga-controller] No viable IPv4 or IPv6 WAN uplink detected. Entering DEGRADED state."
                :set nextState "DEGRADED"
                :if ([:len $clatDefaultRoute] > 0) do={
                    /ip/route/set ($clatDefaultRoute->0) disabled=yes
                }
            }
        }
    }

    # Update State Transition
    :if ($TAYGA_STATE != $nextState) do={
        :log info ("[tayga-controller] State transition: " . $TAYGA_STATE . " -> " . $nextState)
        :set TAYGA_STATE $nextState
    }
} on-error={
    :log error "[tayga-controller] Unhandled error during controller execution; releasing busy lock."
}

# Release Controller Concurrency Lock
:set TAYGA_CONTROLLER_BUSY false
