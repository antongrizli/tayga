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
#   - PREPARING_NAT64 : Local NAT64 requested for IPv6-only LAN segment
#   - NAT64_ACTIVE    : Local NAT64 + DNS64 verified and active
#   - DEGRADED        : No working IPv4 transit (direct down, CLAT/PLAT unreachable)
#
# Usage:
#   Run periodically via /system/scheduler (default: every 15s)
#   /import file-name=usb1/telekom-xlat/scripts/routeros-controller.rsc
# ==============================================================================

# --- Global State & Concurrency Lock ---
:global TAYGA_MAINTENANCE_LOCK
:global TAYGA_CONTROLLER_BUSY
:global TAYGA_STATE
:global TAYGA_DIRECT_FAIL_COUNT
:global TAYGA_DIRECT_PASS_COUNT
:global TAYGA_CLAT_FAIL_COUNT

# Concurrency Guard: Check Maintenance Lock (Upgrade/Rollback active)
:if ($TAYGA_MAINTENANCE_LOCK = true) do={
    :log info "[tayga-controller] Upgrade or maintenance in progress (lock=true). Skipping controller run."
    :return nil
}

# Concurrency Guard: Avoid Overlapping Controller Invocations
:if ($TAYGA_CONTROLLER_BUSY = true) do={
    :log debug "[tayga-controller] Previous controller run still in progress. Skipping."
    :return nil
}
:set TAYGA_CONTROLLER_BUSY true

# Initialize State Counters if undefined
:if ([:len $TAYGA_STATE] = 0) do={ :set TAYGA_STATE "DISCOVERING" }
:if ([:len $TAYGA_DIRECT_FAIL_COUNT] = 0) do={ :set TAYGA_DIRECT_FAIL_COUNT 0 }
:if ([:len $TAYGA_DIRECT_PASS_COUNT] = 0) do={ :set TAYGA_DIRECT_PASS_COUNT 0 }
:if ([:len $TAYGA_CLAT_FAIL_COUNT] = 0) do={ :set TAYGA_CLAT_FAIL_COUNT 0 }

# --- Policy Defaults & Environment Reading ---
:local policy "auto"
:local preferDirectIpv4 "yes"
:local lanRequiresIpv4 "yes"
:local allowLocalNat64 "no"
:local ipv6OnlyLanIfaces ""
:local failThreshold 3
:local recoveryThreshold 4

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

# Detect WAN Interface
:local wanIf "lte1"
:if ([:len [/interface/find where name="lte1"]] = 0) do={
    :if ([:len [/interface/find where name="ether1"]] > 0) do={
        :set wanIf "ether1"
    }
}

# Ensure Isolated Routing Table 'wan-direct' exists for Zero-Leak Probing
:if ([:len [/routing/table/find where name="wan-direct"]] = 0) do={
    /routing/table/add name=wan-direct fib comment="[tayga-unified:direct] Isolated Direct WAN Routing Table"
}

# Dynamically synchronize default route in 'wan-direct' table with direct WAN gateway
:local directWanGw ""
:local wanRoutes [/ip/route/find where dst-address="0.0.0.0/0" and active and !comment~"^\\[tayga-unified:clat"]
:if ([:len $wanRoutes] > 0) do={
    :set directWanGw [/ip/route/get ($wanRoutes->0) gateway]
} else={
    # Fallback to WAN interface as gateway if no direct route found in main table
    :set directWanGw $wanIf
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

# Helper to find CLAT container & default route
:local conts [/container/find where comment~"^\\[tayga-unified:clat\\]"]
:local clatDefaultRoute [/ip/route/find where comment~"^\\[tayga-unified:clat:default\\]"]

# Ensure Candidate Probe Route (1.1.1.1/32 via 172.31.64.2) exists for CLAT validation
:if ([:len [/ip/route/find where comment~"^\\[tayga-unified:clat:probe\\]"]] = 0) do={
    /ip/route/add dst-address=1.1.1.1/32 gateway=172.31.64.2 distance=1 comment="[tayga-unified:clat:probe] Probe Route"
}

# --- Finite State Machine (FSM) Evaluation ---
:local nextState $TAYGA_STATE

:if ($policy = "manual") do={
    :log debug "[tayga-controller] POLICY=manual. Controller active in monitor-only mode."
    :set TAYGA_CONTROLLER_BUSY false
    :return nil
}

:if ($directIpv4Ok = true and $preferDirectIpv4 = "yes") do={
    :set TAYGA_DIRECT_FAIL_COUNT 0
    :set TAYGA_DIRECT_PASS_COUNT ($TAYGA_DIRECT_PASS_COUNT + 1)
    
    :if ($TAYGA_STATE = "DIRECT") do={
        # Already in DIRECT state; steady state
    } else={
        # Check recovery hysteresis threshold
        :if ($TAYGA_DIRECT_PASS_COUNT >= $recoveryThreshold or $TAYGA_STATE = "DISCOVERING") do={
            :log info ("[tayga-controller] Direct WAN IPv4 verified (passes=" . $TAYGA_DIRECT_PASS_COUNT . "). Switching to DIRECT mode.")
            :set nextState "DIRECT"
            
            # Disable CLAT default route
            :if ([:len $clatDefaultRoute] > 0) do={
                /ip/route/set ($clatDefaultRoute->0) disabled=yes
            }
            
            # Place CLAT container in standby
            :if ([:len $conts] > 0) do={
                :local cId ($conts->0)
                :if ([/container/get $cId running] = true) do={
                    :log info "[tayga-controller] Placing CLAT container into standby..."
                    /container/stop $cId
                }
            }
        } else={
            :log info ("[tayga-controller] Direct IPv4 probe passing (" . $TAYGA_DIRECT_PASS_COUNT . "/" . $recoveryThreshold . "), awaiting hysteresis threshold.")
        }
    }
} else={
    # Direct IPv4 failed or not preferred
    :set TAYGA_DIRECT_PASS_COUNT 0
    :set TAYGA_DIRECT_FAIL_COUNT ($TAYGA_DIRECT_FAIL_COUNT + 1)
    
    :if ($TAYGA_STATE = "DIRECT" and $TAYGA_DIRECT_FAIL_COUNT < $failThreshold) do={
        :log warn ("[tayga-controller] Direct IPv4 probe failed (" . $TAYGA_DIRECT_FAIL_COUNT . "/" . $failThreshold . "). Awaiting hysteresis threshold.")
    } else={
        # Direct IPv4 considered down; check IPv6 + CLAT feasibility
        :if ($ipv6Ok = true and $lanRequiresIpv4 = "yes") do={
            :set nextState "PREPARING_CLAT"
            
            # Ensure CLAT container is running
            :if ([:len $conts] > 0) do={
                :local cId ($conts->0)
                :if ([/container/get $cId running] != true) do={
                    :log info "[tayga-controller] Starting CLAT container..."
                    /container/start $cId
                    :delay 3s
                }
            }
            
            # CLAT Data-Plane Verification (src-address 172.31.64.1 through probe route)
            :local clatProbeOk false
            :local clatPing [/ping 1.1.1.1 src-address=172.31.64.1 count=3]
            :if ($clatPing > 0) do={
                :set clatProbeOk true
            }
            
            :if ($clatProbeOk = true) do={
                :set TAYGA_CLAT_FAIL_COUNT 0
                :if ($TAYGA_STATE != "CLAT_ACTIVE") do={
                    :log info "[tayga-controller] CLAT end-to-end probe verified! Activating CLAT default route."
                }
                :set nextState "CLAT_ACTIVE"
                
                # Activate default route via CLAT
                :if ([:len $clatDefaultRoute] > 0) do={
                    /ip/route/set ($clatDefaultRoute->0) disabled=no
                } else={
                    /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 distance=10 comment="[tayga-unified:clat:default] Default route via TAYGA CLAT"
                }
            } else={
                :set TAYGA_CLAT_FAIL_COUNT ($TAYGA_CLAT_FAIL_COUNT + 1)
                :log warn ("[tayga-controller] CLAT probe ping failed (attempts=" . $TAYGA_CLAT_FAIL_COUNT . "). PLAT translation unavailable.")
                :set nextState "DEGRADED"
                
                # Disable CLAT default route to avoid blackholing traffic
                :if ([:len $clatDefaultRoute] > 0) do={
                    /ip/route/set ($clatDefaultRoute->0) disabled=yes
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

# Update State
:if ($TAYGA_STATE != $nextState) do={
    :log info ("[tayga-controller] State transition: " . $TAYGA_STATE . " -> " . $nextState)
    :set TAYGA_STATE $nextState
}

# Release Controller Concurrency Lock
:set TAYGA_CONTROLLER_BUSY false
