# ==============================================================================
# RouterOS 7 Network State Controller: Dynamic Mode Selection & Route Management
# ==============================================================================
# Automates runtime mode selection between DIRECT IPv4, CLAT (RFC 6877), and
# NAT64 (RFC 6146/6147) based on real-time WAN capability and LAN requirements.
#
# FSM States:
#   - DISCOVERING     : Initial state / evaluating available WAN paths
#   - DIRECT          : Direct WAN IPv4 is active and healthy (CLAT in standby)
#   - NAT64_ACTIVE    : Direct WAN IPv4 + Local NAT64/DNS64 active for IPv6 LAN
#   - PREPARING_CLAT  : Direct IPv4 failed; starting/probing CLAT container
#   - CLAT_ACTIVE     : CLAT verified end-to-end; default IPv4 route active via CLAT
#   - DEGRADED        : No working IPv4 transit (direct down, CLAT/PLAT unreachable)
#   - DISABLED        : Manually disabled by administrator via routeros-disable.rsc
#   - CONFIG_ERROR    : Invalid policy configuration (e.g. missing LAN interfaces)
#
# Usage:
#   Run periodically via /system/scheduler (default: every 15s)
#   /import file-name=usb1/telekom-xlat/scripts/routeros-controller.rsc
# ==============================================================================

# --- Global State & Unified Lock Variables ---
:global TAYGA_LOCK_OWNER
:global TAYGA_LOCK_TOKEN
:global TAYGA_LOCK_TIME
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

# 2. Unified Lock Manager: Check Ownership, Expiration, and Mutual Exclusion
:local curUptime [/system/resource/get uptime]
:local isLocked false
:if ([:len $TAYGA_LOCK_OWNER] > 0 and $TAYGA_LOCK_OWNER != "none") do={
    :local lockAge 0s
    :do {
        :set lockAge ($curUptime - $TAYGA_LOCK_TIME)
    } on-error={ :set lockAge 999s }
    :if ($lockAge < 120s) do={
        :set isLocked true
    } else={
        :log warn ("[tayga-controller] Stale lock detected (owner=" . $TAYGA_LOCK_OWNER . ", age=" . [:tostr $lockAge] . "). Overriding lock.")
    }
}

:if ($isLocked = true) do={
    :log info ("[tayga-controller] System locked by owner: " . $TAYGA_LOCK_OWNER . ". Skipping controller cycle.")
    :return nil
}

:local myToken ("ctrl-" . [:tostr [/system/clock/get time]] . "-" . [:rndnum from=1000 to=9999])
:set TAYGA_LOCK_OWNER "controller"
:set TAYGA_LOCK_TOKEN $myToken
:set TAYGA_LOCK_TIME $curUptime

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

    # Read policy settings from shared tayga-policy-envs or fallback to tayga-clat-envs / tayga-nat64-envs
    :local findEnv do={
        :local varName $1
        :local envId [/container/envs/find where list="tayga-policy-envs" and key=$varName]
        :if ([:len $envId] > 0) do={ :return [/container/envs/get ($envId->0) value] }
        :set envId [/container/envs/find where list="tayga-clat-envs" and key=$varName]
        :if ([:len $envId] > 0) do={ :return [/container/envs/get ($envId->0) value] }
        :set envId [/container/envs/find where list="tayga-nat64-envs" and key=$varName]
        :if ([:len $envId] > 0) do={ :return [/container/envs/get ($envId->0) value] }
        :return ""
    }

    :local val [$findEnv "POLICY"]
    :if ([:len $val] > 0) do={ :set policy $val }
    :set val [$findEnv "PREFER_DIRECT_IPV4"]
    :if ([:len $val] > 0) do={ :set preferDirectIpv4 $val }
    :set val [$findEnv "LAN_REQUIRES_IPV4"]
    :if ([:len $val] > 0) do={ :set lanRequiresIpv4 $val }
    :set val [$findEnv "ALLOW_LOCAL_NAT64"]
    :if ([:len $val] > 0) do={ :set allowLocalNat64 $val }
    :set val [$findEnv "IPV6_ONLY_LAN_INTERFACES"]
    :if ([:len $val] > 0) do={ :set ipv6OnlyLanIfaces $val }

    # Early check for POLICY=manual (Read-only monitor mode)
    :if ($policy = "manual") do={
        :log debug "[tayga-controller] POLICY=manual. Running in monitor-only mode."
        :if ($TAYGA_LOCK_TOKEN = $myToken) do={
            :set TAYGA_LOCK_OWNER "none"
            :set TAYGA_LOCK_TOKEN ""
        }
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

    # Strict Table Ownership Verification: refuse to touch unowned tables
    :local wanTable [/routing/table/find where name="wan-direct"]
    :if ([:len $wanTable] = 0) do={
        /routing/table/add name=wan-direct fib comment="[tayga-unified:direct] Isolated Direct WAN Routing Table"
    } else={
        :local tComm [/routing/table/get ($wanTable->0) comment]
        :if (!($tComm ~ "^\\[tayga-unified:direct\\]")) do={
            :log error "[tayga-controller] ABORT: Table 'wan-direct' exists and is NOT owned by tayga-unified project. Refusing to modify."
            :if ($TAYGA_LOCK_TOKEN = $myToken) do={
                :set TAYGA_LOCK_OWNER "none"
                :set TAYGA_LOCK_TOKEN ""
            }
            :return nil
        }
    }

    :local clatTable [/routing/table/find where name="tayga-probe-clat"]
    :if ([:len $clatTable] = 0) do={
        /routing/table/add name=tayga-probe-clat fib comment="[tayga-unified:clat] Isolated CLAT Probe Table"
    } else={
        :local cComm [/routing/table/get ($clatTable->0) comment]
        :if (!($cComm ~ "^\\[tayga-unified:clat\\]")) do={
            :log error "[tayga-controller] ABORT: Table 'tayga-probe-clat' exists and is NOT owned by tayga-unified project. Refusing to modify."
            :if ($TAYGA_LOCK_TOKEN = $myToken) do={
                :set TAYGA_LOCK_OWNER "none"
                :set TAYGA_LOCK_TOKEN ""
            }
            :return nil
        }
    }

    # Strictly detect direct WAN gateway belonging specifically to $wanIf
    :local directWanGw ""
    :local wanRoutes [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active and !comment~"^\\[tayga-unified"]
    :foreach wr in=$wanRoutes do={
        :local isMyWan false
        :local gw [/ip/route/get $wr gateway]
        :if ($gw = $wanIf) do={ :set isMyWan true }
        :do {
            :local immGw [/ip/route/get $wr immediate-gw]
            :if ($immGw ~ $wanIf) do={ :set isMyWan true }
        } on-error={}
        :if ($isMyWan = true and [:len $directWanGw] = 0) do={
            :set directWanGw $gw
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

    # Sync probe route in 'wan-direct' (strictly owned route)
    :local tableRoute [/ip/route/find where routing-table="wan-direct" and dst-address="0.0.0.0/0" and comment~"^\\[tayga-unified:direct"]
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
    :local clatProbeRoute [/ip/route/find where routing-table="tayga-probe-clat" and dst-address="0.0.0.0/0" and comment~"^\\[tayga-unified:clat"]
    :if ([:len $clatProbeRoute] = 0) do={
        /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 routing-table=tayga-probe-clat comment="[tayga-unified:clat:probe] CLAT Probe Route"
    }

    # --- Zero-Leak Probing Phase ---
    # 1. Direct WAN IPv4 Probe via wan-direct
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
    :local clatConts [/container/find where comment~"^\\[tayga-unified:clat\\]"]
    :local nat64Conts [/container/find where comment~"^\\[tayga-unified:nat64\\]"]
    :local clatDefaultRoute [/ip/route/find where comment~"^\\[tayga-unified:clat:default\\]" and routing-table="main"]
    :local nat64Route [/ipv6/route/find where comment~"^\\[tayga-unified:nat64(:prefix)?\\]"]

    # Normalize NAT64 prefix route comment if legacy syntax found
    :if ([:len $nat64Route] > 0) do={
        :local curNComm [/ipv6/route/get ($nat64Route->0) comment]
        :if ($curNComm != "[tayga-unified:nat64:prefix] NAT64 prefix route") do={
            /ipv6/route/set ($nat64Route->0) comment="[tayga-unified:nat64:prefix] NAT64 prefix route"
        }
    }

    # --- Finite State Machine (FSM) Evaluation ---
    :local nextState $TAYGA_STATE

    # Check NAT64 prerequisites if requested
    :local nat64ConfigValid false
    :if ($allowLocalNat64 = "yes") do={
        :local hasCont ([:len $nat64Conts] > 0)
        :local hasRoute ([:len $nat64Route] > 0)
        :if ($hasCont = true and $hasRoute = true) do={
            :if ([:len $ipv6OnlyLanIfaces] > 0) do={
                :local ifaceList [:toarray $ipv6OnlyLanIfaces]
                :local allExist true
                :foreach ifName in=$ifaceList do={
                    :if ([:len [/interface/find where name=$ifName]] = 0) do={
                        :set allExist false
                        :log error ("[tayga-controller] Configured IPV6_ONLY_LAN_INTERFACE '" . $ifName . "' does NOT exist!")
                    }
                }
                :if ($allExist = true) do={ :set nat64ConfigValid true }
            } else={
                :set nat64ConfigValid true
            }
        } else={
            :log warn "[tayga-controller] ALLOW_LOCAL_NAT64=yes requested, but NAT64 container or prefix route is missing."
        }
    }

    :if ($directIpv4Ok = true and $preferDirectIpv4 = "yes") do={
        :set TAYGA_DIRECT_FAIL_COUNT 0
        :set TAYGA_DIRECT_PASS_COUNT ($TAYGA_DIRECT_PASS_COUNT + 1)

        :if ($TAYGA_DIRECT_PASS_COUNT >= $recoveryThreshold or $TAYGA_STATE = "DISCOVERING" or $TAYGA_STATE = "DIRECT" or $TAYGA_STATE = "NAT64_ACTIVE" or $TAYGA_STATE = "PREPARING_NAT64") do={
            # Direct IPv4 is healthy
            # 1. Verified Unparking of WAN routes from TAYGA_PARKED_ROUTE_IDS
            :if ([:len $TAYGA_PARKED_ROUTE_IDS] > 0) do={
                :local remainingParked [:toarray ""]
                :foreach pid in=$TAYGA_PARKED_ROUTE_IDS do={
                    :local restored false
                    :do {
                        :if ([:len [/ip/route/find where .id=$pid]] > 0) do={
                            /ip/route/enable $pid
                            :if ([/ip/route/get $pid disabled] = false) do={
                                :set restored true
                                :log info ("[tayga-controller] Successfully re-enabled parked WAN route: " . $pid)
                            }
                        } else={
                            # Route was deleted externally; do not retain
                            :set restored true
                        }
                    } on-error={}
                    :if ($restored = false) do={
                        :set remainingParked ($remainingParked, $pid)
                    }
                }
                :set TAYGA_PARKED_ROUTE_IDS $remainingParked
            }

            # 2. Safety Gate: Verify at least one direct WAN default route is active in main BEFORE withdrawing CLAT!
            :local activeWanDef [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active=yes and !comment~"^\\[tayga-unified"]
            :if ([:len $activeWanDef] > 0) do={
                # Direct WAN default route is active; safe to disable CLAT default route and put container in standby
                :if ([:len $clatDefaultRoute] > 0) do={
                    /ip/route/set ($clatDefaultRoute->0) disabled=yes
                }
                :if ([:len $clatConts] > 0) do={
                    :local cId ($clatConts->0)
                    :if ([/container/get $cId running] = true) do={
                        :log info "[tayga-controller] Placing CLAT container into standby..."
                        /container/stop $cId
                    }
                }
            } else={
                :log error "[tayga-controller] No direct WAN default route is active in main! Retaining CLAT default route to avoid traffic loss."
            }

            # 3. Handle NAT64 activation if requested and valid
            :if ($allowLocalNat64 = "yes") do={
                :if ($nat64ConfigValid = true) do={
                    :local nId ($nat64Conts->0)
                    :if ([/container/get $nId running] != true) do={
                        :log info "[tayga-controller] Starting NAT64 container..."
                        /container/start $nId
                        :delay 3s
                    }
                    :if ([:len $nat64Route] > 0) do={
                        /ipv6/route/set ($nat64Route->0) disabled=no
                    }

                    # Verify NAT64 readiness (container running, DNS64 resolve, translation ping)
                    :local nRunning [/container/get $nId running]
                    :local dns64Ok false
                    :local nat64PingOk false

                    :if ($nRunning = true) do={
                        :do {
                            :local res [:resolve "ipv4only.arpa" server=fc68::2]
                            :if ([:tostr $res] ~ "^64:ff9b::") do={ :set dns64Ok true }
                        } on-error={
                            :log warn "[tayga-controller] DNS64 resolution probe to fc68::2 failed."
                        }

                        :local pCount [/ping 64:ff9b::1.1.1.1 src-address=fc68::1 count=2]
                        :if ($pCount > 0) do={
                            :set nat64PingOk true
                        } else={
                            :log warn "[tayga-controller] NAT64 data-plane translation ping failed."
                        }
                    }

                    :if ($nRunning = true and $dns64Ok = true and $nat64PingOk = true) do={
                        :set nextState "NAT64_ACTIVE"
                    } else={
                        :log warn ("[tayga-controller] NAT64 verifying: running=" . [:tostr $nRunning] . ", dns64=" . [:tostr $dns64Ok] . ", ping=" . [:tostr $nat64PingOk] . ". State: PREPARING_NAT64")
                        :set nextState "PREPARING_NAT64"
                    }
                } else={
                    :set nextState "CONFIG_ERROR"
                    # Teardown invalid NAT64
                    :if ([:len $nat64Conts] > 0) do={
                        :local nId ($nat64Conts->0)
                        :if ([/container/get $nId running] = true) do={ /container/stop $nId }
                    }
                    :if ([:len $nat64Route] > 0) do={ /ipv6/route/set ($nat64Route->0) disabled=yes }
                }
            } else={
                :set nextState "DIRECT"
                # Stop NAT64 container if running
                :if ([:len $nat64Conts] > 0) do={
                    :local nId ($nat64Conts->0)
                    :if ([/container/get $nId running] = true) do={
                        :log info "[tayga-controller] Placing NAT64 container into standby..."
                        /container/stop $nId
                    }
                }
                :if ([:len $nat64Route] > 0) do={
                    /ipv6/route/set ($nat64Route->0) disabled=yes
                }
            }
        } else={
            :log info ("[tayga-controller] Direct IPv4 probe passing (" . $TAYGA_DIRECT_PASS_COUNT . "/" . $recoveryThreshold . "), awaiting recovery threshold.")
        }
    } else={
        # Direct IPv4 failed or not preferred
        :set TAYGA_DIRECT_PASS_COUNT 0
        :set TAYGA_DIRECT_FAIL_COUNT ($TAYGA_DIRECT_FAIL_COUNT + 1)

        :if (($TAYGA_STATE = "DIRECT" or $TAYGA_STATE = "NAT64_ACTIVE" or $TAYGA_STATE = "PREPARING_NAT64") and $TAYGA_DIRECT_FAIL_COUNT < $failThreshold) do={
            :log warn ("[tayga-controller] Direct IPv4 probe failed (" . $TAYGA_DIRECT_FAIL_COUNT . "/" . $failThreshold . "). Awaiting fail threshold.")
        } else={
            # Direct IPv4 confirmed down (failures >= failThreshold); teardown NAT64 and prepare CLAT path!
            :if ([:len $nat64Route] > 0) do={ /ipv6/route/set ($nat64Route->0) disabled=yes }
            :if ([:len $nat64Conts] > 0) do={
                :local nId ($nat64Conts->0)
                :if ([/container/get $nId running] = true) do={
                    :log info "[tayga-controller] Direct IPv4 down: stopping NAT64 container..."
                    /container/stop $nId
                }
            }

            # Direct IPv4 confirmed down; prepare CLAT path
            :if ($lanRequiresIpv4 = "yes") do={
                # Start CLAT container if stopped
                :if ([:len $clatConts] > 0) do={
                    :local cId ($clatConts->0)
                    :if ([/container/get $cId running] != true) do={
                        :log info "[tayga-controller] Starting CLAT container..."
                        /container/start $cId
                        :delay 3s
                    }
                }

                # CLAT Data-Plane Verification via isolated probe table
                :local clatProbeOk false
                :local clatPing [/ping 1.1.1.1 src-address=172.31.64.1 routing-table=tayga-probe-clat count=3]
                :if ($clatPing > 0) do={
                    :set clatProbeOk true
                }

                :if ($clatProbeOk = true) do={
                    :set TAYGA_CLAT_FAIL_COUNT 0

                    # Transactional Route Switching: strictly matching managed $wanIf
                    :local switchSuccess true
                    :local newlyParked [:toarray ""]
                    :local activeScopedWan [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active and (gateway=$wanIf or gateway=$directWanGw or immediate-gw~$wanIf) and !comment~"^\\[tayga-unified"]

                    :foreach r in=$activeScopedWan do={
                        :do {
                            /ip/route/disable $r
                            :set newlyParked ($newlyParked, $r)
                        } on-error={
                            :set switchSuccess false
                            :log error "[tayga-controller] Failed to disable WAN route. Initiating transaction rollback."
                        }
                    }

                    :if ($switchSuccess = true) do={
                        :do {
                            # Enable/Add CLAT default route in main table
                            :if ([:len $clatDefaultRoute] > 0) do={
                                /ip/route/set ($clatDefaultRoute->0) disabled=no distance=1
                            } else={
                                /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 distance=1 routing-table=main comment="[tayga-unified:clat:default] Default route via TAYGA CLAT"
                            }

                            # Verify active default route in main points strictly to CLAT with NO foreign conflicts
                            :local winDef [/ip/route/find where routing-table="main" and dst-address="0.0.0.0/0" and active=yes]
                            :local clatWon false
                            :local hasConflict false
                            :foreach wd in=$winDef do={
                                :local gw [/ip/route/get $wd gateway]
                                :if ($gw = "172.31.64.2") do={
                                    :set clatWon true
                                } else={
                                    :set hasConflict true
                                    :log error ("[tayga-controller] Route conflict: foreign active default route detected with gateway=" . $gw)
                                }
                            }
                            :if ($clatWon = false or $hasConflict = true) do={
                                :set switchSuccess false
                                :log error "[tayga-controller] CLAT route validation failed: no winning path or conflict present."
                            }
                        } on-error={
                            :set switchSuccess false
                        }
                    }

                    :if ($switchSuccess = false) do={
                        # Transaction Rollback: Re-enable newly parked routes and disable CLAT route
                        :log warn "[tayga-controller] Rolling back route switch transaction..."
                        :local clatRoutesToDisable [/ip/route/find where comment~"^\\[tayga-unified:clat:default\\]"]
                        :foreach cr in=$clatRoutesToDisable do={
                            :do { /ip/route/set $cr disabled=yes } on-error={}
                        }
                        :foreach r in=$newlyParked do={
                            :local restored false
                            :do {
                                /ip/route/enable $r
                                :if ([/ip/route/get $r disabled] = false) do={ :set restored true }
                            } on-error={}
                            :if ($restored = false) do={
                                # Save un-restored route for retry by future cycles
                                :set TAYGA_PARKED_ROUTE_IDS ($TAYGA_PARKED_ROUTE_IDS, $r)
                            }
                        }
                        :set nextState "DEGRADED"
                    } else={
                        # Success: Accumulate newly parked routes into TAYGA_PARKED_ROUTE_IDS with deduplication
                        :foreach r in=$newlyParked do={
                            :local isDupl false
                            :foreach ex in=$TAYGA_PARKED_ROUTE_IDS do={ :if ($ex = $r) do={ :set isDupl true } }
                            :if ($isDupl = false) do={ :set TAYGA_PARKED_ROUTE_IDS ($TAYGA_PARKED_ROUTE_IDS, $r) }
                        }
                        :set nextState "CLAT_ACTIVE"
                    }
                } else={
                    # CLAT probe ping failed
                    :set TAYGA_CLAT_FAIL_COUNT ($TAYGA_CLAT_FAIL_COUNT + 1)
                    :log warn ("[tayga-controller] CLAT probe failed (failures=" . $TAYGA_CLAT_FAIL_COUNT . "/" . $clatFailThreshold . ")")

                    # Apply symmetric hysteresis threshold
                    :if ($TAYGA_CLAT_FAIL_COUNT >= $clatFailThreshold or $TAYGA_STATE = "PREPARING_CLAT") do={
                        :log error "[tayga-controller] CLAT path unavailable. Entering DEGRADED state."
                        :set nextState "DEGRADED"

                        # Disable CLAT default route to avoid traffic blackholing
                        :local clatRoutesToDisable [/ip/route/find where comment~"^\\[tayga-unified:clat:default\\]"]
                        :foreach cr in=$clatRoutesToDisable do={
                            /ip/route/set $cr disabled=yes
                        }
                    }
                }
            } else={
                :log error "[tayga-controller] No viable uplink detected. Entering DEGRADED state."
                :set nextState "DEGRADED"
                :local clatRoutesToDisable [/ip/route/find where comment~"^\\[tayga-unified:clat:default\\]"]
                :foreach cr in=$clatRoutesToDisable do={
                    /ip/route/set $cr disabled=yes
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
    :log error "[tayga-controller] Unhandled exception during controller execution."
}

# Release Controller Lock strictly by token match
:if ($TAYGA_LOCK_TOKEN = $myToken) do={
    :set TAYGA_LOCK_OWNER "none"
    :set TAYGA_LOCK_TOKEN ""
}
