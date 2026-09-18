# ==============================================================================
# RouterOS 7 Network State Controller: Dynamic Mode Selection & Route Management
# ==============================================================================
# Automates runtime mode selection between DIRECT IPv4 and CLAT (RFC 6877)
# based on real-time WAN capability and LAN requirements.
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

# --- Global State & Concurrency Mutex Variables ---
:global TAYGA_MAINTENANCE_LOCK
:global TAYGA_CONTROLLER_BUSY
:global TAYGA_BUSY_TICKS
:global TAYGA_STATE
:global TAYGA_PARKED_ROUTE_IDS
:global TAYGA_DIRECT_FAIL_COUNT
:global TAYGA_DIRECT_PASS_COUNT
:global TAYGA_CLAT_FAIL_COUNT

# 1. Check Disabled State
:if ($TAYGA_STATE = "DISABLED") do={
    :log debug "[tayga-controller] System is in DISABLED state. Skipping execution."
    :return nil
}

# 2. Concurrency Guard: Check Maintenance Lock (Upgrade/Rollback/Disable in progress)
:if ($TAYGA_MAINTENANCE_LOCK = true) do={
    :log info "[tayga-controller] Maintenance or upgrade in progress (lock=true). Skipping controller run."
    :return nil
}

# 3. Concurrency Mutex Guard with Stale Lock Recovery
:if ($TAYGA_CONTROLLER_BUSY = true) do={
    :if ([:len $TAYGA_BUSY_TICKS] = 0) do={ :set TAYGA_BUSY_TICKS 0 }
    :set TAYGA_BUSY_TICKS ($TAYGA_BUSY_TICKS + 1)
    :if ($TAYGA_BUSY_TICKS < 4) do={
        :log debug ("[tayga-controller] Another controller run is in progress (ticks=" . $TAYGA_BUSY_TICKS . "). Skipping.")
        :return nil
    }
    :log warn "[tayga-controller] Stale busy lock detected (>=4 ticks / 60s). Self-healing lock."
}
:set TAYGA_CONTROLLER_BUSY true
:set TAYGA_BUSY_TICKS 0

# Main Protected Execution Block
:do {
    # Initialize State Counters & Arrays
    :if ([:len $TAYGA_STATE] = 0) do={ :set TAYGA_STATE "DISCOVERING" }
    :if ([:len $TAYGA_DIRECT_FAIL_COUNT] = 0) do={ :set TAYGA_DIRECT_FAIL_COUNT 0 }
    :if ([:len $TAYGA_DIRECT_PASS_COUNT] = 0) do={ :set TAYGA_DIRECT_PASS_COUNT 0 }
    :if ([:len $TAYGA_CLAT_FAIL_COUNT] = 0) do={ :set TAYGA_CLAT_FAIL_COUNT 0 }
    :if ([:len $TAYGA_PARKED_ROUTE_IDS] = 0) do={ :set TAYGA_PARKED_ROUTE_IDS [:toarray ""] }

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

    # Informative log if unsupported or unconfigured NAT64 is requested
    :if ($allowLocalNat64 = "yes") do={
        :if ([:len $ipv6OnlyLanIfaces] = 0) do={
            :log warn "[tayga-controller] ALLOW_LOCAL_NAT64=yes ignored: IPV6_ONLY_LAN_INTERFACES is empty. Auto-NAT64 requires explicit interface list."
        }
    }

    # Early check for POLICY=manual (Read-only monitor mode)
    :if ($policy = "manual") do={
        :log debug "[tayga-controller] POLICY=manual. Running in monitor-only mode."
        :set TAYGA_CONTROLLER_BUSY false
        :return nil
    }

    # Migration cleanup: Remove any legacy /32 probe route from main table
    :local legacyProbes [/ip/route/find where dst-address="1.1.1.1/32" and comment~"^\\[tayga-unified"]
    :if ([:len $legacyProbes] > 0) do={
        :log info "[tayga-controller] Migrating legacy /32 probe route from main table..."
        :do { /ip/route/remove $legacyProbes } on-error={}
    }

    # Detect Primary WAN Interface (lte1 on Chateau, ether1 on CHR)
    :local wanIf "lte1"
    :if ([:len [/interface/find where name="lte1"]] = 0) do={
        :if ([:len [/interface/find where name="ether1"]] > 0) do={
            :set wanIf "ether1"
        }
    }

    # Ensure Isolated Routing Tables exist with strict ownership verification
    :local wanTable [/routing/table/find where name="wan-direct"]
    :if ([:len $wanTable] = 0) do={
        /routing/table/add name=wan-direct fib comment="[tayga-unified:direct] Isolated Direct WAN Routing Table"
    } else={
        :local tComm [/routing/table/get ($wanTable->0) comment]
        :if (!($tComm ~ "^\\[tayga-unified")) do={
            :log warn "[tayga-controller] Existing routing table 'wan-direct' is not owned by this project. Using with caution."
        }
    }

    :local clatTable [/routing/table/find where name="tayga-probe-clat"]
    :if ([:len $clatTable] = 0) do={
        /routing/table/add name=tayga-probe-clat fib comment="[tayga-unified:clat] Isolated CLAT Probe Table"
    } else={
        :local cComm [/routing/table/get ($clatTable->0) comment]
        :if (!($cComm ~ "^\\[tayga-unified")) do={
            :log warn "[tayga-controller] Existing routing table 'tayga-probe-clat' is not owned by this project. Using with caution."
        }
    }

    # Strictly detect direct WAN gateway on $wanIf
    :local directWanGw ""
    :local wanRoutes [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active and !comment~"^\\[tayga-unified"]
    :foreach wr in=$wanRoutes do={
        :local gw [/ip/route/get $wr gateway]
        :if ($gw = $wanIf or $gw ~ "^[0-9]" or $gw ~ "^[a-fA-F0-9]") do={
            :if ([:len $directWanGw] = 0) do={ :set directWanGw $gw }
        }
    }

    # If active route not found, check previously parked routes
    :if ([:len $directWanGw] = 0 and [:len $TAYGA_PARKED_ROUTE_IDS] > 0) do={
        :foreach pid in=$TAYGA_PARKED_ROUTE_IDS do={
            :do {
                :local pgw [/ip/route/get $pid gateway]
                :if ([:len $directWanGw] = 0 and [:len $pgw] > 0) do={ :set directWanGw $pgw }
            } on-error={}
        }
    }
    :if ([:len $directWanGw] = 0) do={ :set directWanGw $wanIf }

    # Sync probe route in 'wan-direct'
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

    # Ensure isolated CLAT probe route exists in 'tayga-probe-clat'
    :local clatProbeRoute [/ip/route/find where routing-table="tayga-probe-clat" and dst-address="0.0.0.0/0"]
    :if ([:len $clatProbeRoute] = 0) do={
        /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 routing-table=tayga-probe-clat comment="[tayga-unified:clat:probe] CLAT Probe Route"
    }

    # --- Zero-Leak Probing Phase ---
    # 1. Direct WAN IPv4 Probe
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

    # Containers and Route references
    :local conts [/container/find where comment~"^\\[tayga-unified:clat\\]"]
    :local clatDefaultRoute [/ip/route/find where comment~"^\\[tayga-unified:clat:default\\]" and routing-table="main"]

    # --- Finite State Machine (FSM) Evaluation ---
    :local nextState $TAYGA_STATE

    :if ($directIpv4Ok = true and $preferDirectIpv4 = "yes") do={
        :set TAYGA_DIRECT_FAIL_COUNT 0
        :set TAYGA_DIRECT_PASS_COUNT ($TAYGA_DIRECT_PASS_COUNT + 1)

        :if ($TAYGA_STATE = "DIRECT") do={
            # Steady state DIRECT: ensure CLAT default route is disabled
            :if ([:len $clatDefaultRoute] > 0) do={
                :if ([/ip/route/get ($clatDefaultRoute->0) disabled] = false) do={
                    /ip/route/set ($clatDefaultRoute->0) disabled=yes
                }
            }
        } else={
            # Check recovery hysteresis threshold
            :if ($TAYGA_DIRECT_PASS_COUNT >= $recoveryThreshold or $TAYGA_STATE = "DISCOVERING") do={
                :log info ("[tayga-controller] Direct WAN IPv4 verified (passes=" . $TAYGA_DIRECT_PASS_COUNT . "). Switching to DIRECT mode.")
                :set nextState "DIRECT"

                # 1. Disable CLAT default route
                :if ([:len $clatDefaultRoute] > 0) do={
                    /ip/route/set ($clatDefaultRoute->0) disabled=yes
                }

                # 2. Re-enable specifically parked WAN default routes
                :if ([:len $TAYGA_PARKED_ROUTE_IDS] > 0) do={
                    :foreach pid in=$TAYGA_PARKED_ROUTE_IDS do={
                        :do {
                            :log info ("[tayga-controller] Re-enabling parked WAN route: " . $pid)
                            /ip/route/enable $pid
                        } on-error={}
                    }
                    :set TAYGA_PARKED_ROUTE_IDS [:toarray ""]
                }

                # 3. Put CLAT container into standby
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
            # Direct IPv4 down; prepare and verify CLAT path
            :if ($lanRequiresIpv4 = "yes") do={
                # Start container if stopped
                :if ([:len $conts] > 0) do={
                    :local cId ($conts->0)
                    :if ([/container/get $cId running] != true) do={
                        :log info "[tayga-controller] Starting CLAT container..."
                        /container/start $cId
                        :delay 3s
                    }
                }

                # Data-plane verification via isolated probe table
                :local clatProbeOk false
                :local clatPing [/ping 1.1.1.1 src-address=172.31.64.1 routing-table=tayga-probe-clat count=3]
                :if ($clatPing > 0) do={
                    :set clatProbeOk true
                }

                :if ($clatProbeOk = true) do={
                    :set TAYGA_CLAT_FAIL_COUNT 0
                    :set nextState "CLAT_ACTIVE"

                    # Transactional Route Switching: Scoped to specific WAN routes
                    :local activeScopedWan [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active and (gateway=$wanIf or gateway=$directWanGw) and !comment~"^\\[tayga-unified"]
                    :if ([:len $activeScopedWan] > 0) do={
                        :log info "[tayga-controller] Parking active direct WAN default routes..."
                        :local newParked [:toarray ""]
                        :foreach r in=$activeScopedWan do={
                            :do {
                                /ip/route/disable $r
                                :set newParked ($newParked, $r)
                            } on-error={
                                :log error "[tayga-controller] Failed to park route. Aborting route switch."
                            }
                        }
                        :set TAYGA_PARKED_ROUTE_IDS $newParked
                    }

                    # Enable CLAT default route in main table
                    :if ([:len $clatDefaultRoute] > 0) do={
                        /ip/route/set ($clatDefaultRoute->0) disabled=no distance=1
                    } else={
                        /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 distance=1 routing-table=main comment="[tayga-unified:clat:default] Default route via TAYGA CLAT"
                    }

                    # Continuous Active Route Verification: Verify 0.0.0.0/0 in main wins
                    :local winningDef [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active=yes]
                    :if ([:len $winningDef] > 0) do={
                        :local winGw [/ip/route/get ($winningDef->0) gateway]
                        :if ($winGw != "172.31.64.2") do={
                            :log warn ("[tayga-controller] Routing drift detected! Active default gateway is " . $winGw . " instead of CLAT. Re-asserting CLAT priority.")
                            :local compRoute ($winningDef->0)
                            :if (!([/ip/route/get $compRoute comment] ~ "^\\[tayga-unified")) do={
                                :do {
                                    /ip/route/disable $compRoute
                                    :set TAYGA_PARKED_ROUTE_IDS ($TAYGA_PARKED_ROUTE_IDS, $compRoute)
                                } on-error={}
                            }
                        }
                    }
                } else={
                    # CLAT probe failed
                    :set TAYGA_CLAT_FAIL_COUNT ($TAYGA_CLAT_FAIL_COUNT + 1)
                    :log warn ("[tayga-controller] CLAT probe failed (failures=" . $TAYGA_CLAT_FAIL_COUNT . "/" . $clatFailThreshold . ")")

                    # Apply symmetric hysteresis threshold before tearing down CLAT
                    :if ($TAYGA_CLAT_FAIL_COUNT >= $clatFailThreshold or $TAYGA_STATE = "PREPARING_CLAT") do={
                        :log error "[tayga-controller] CLAT transit unavailable. Entering DEGRADED state."
                        :set nextState "DEGRADED"

                        # Disable CLAT default route to avoid traffic blackholing
                        :if ([:len $clatDefaultRoute] > 0) do={
                            /ip/route/set ($clatDefaultRoute->0) disabled=yes
                        }
                    }
                }
            } else={
                :log error "[tayga-controller] No viable uplink detected. Entering DEGRADED state."
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
    :log error "[tayga-controller] Unhandled exception during controller execution; releasing lock."
}

# Release Controller Concurrency Lock
:set TAYGA_CONTROLLER_BUSY false
:set TAYGA_BUSY_TICKS 0
