# ==============================================================================
# RouterOS 7 Installation Script: TAYGA CLAT (Customer-Side Translator RFC 6877)
# ==============================================================================
# Deploys TAYGA unified container in CLAT mode on MikroTik Chateau 5G ax.
# Uses tagged configuration [tayga-unified:clat] for safe idempotency & rollback.
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-install-clat.rsc
# ==============================================================================

:put "============================================================"
:put " Deploying TAYGA Unified CLAT Container..."
:put "============================================================"

# --- 1. Detect External Storage Slot & Paths ---
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
:local preflightScript ($basePath . "/scripts/routeros-preflight.rsc")
:local imagePath ($basePath . "/images/tayga-arm64.tar")
:local rootfsPath ($basePath . "/rootfs/clat-a")

# --- 2. Run Preflight Audit First (Strict CLAT Mode) ---
:global AUDITMODE "clat"
:do {
    /import file-name=$preflightScript
} on-error={
    :error "Installation aborted: preflight audit failed."
}

# --- 3. Check Required Image Archive on Storage ---
:local imageFound [:len [/file/find where name=$imagePath]]
:if ($imageFound = 0) do={
    :put (" [FAIL] Required image archive '" . $imagePath . "' not found on storage drive.")
    :put (" Upload the image first: scp dist/tayga-arm64.tar admin@<router-ip>:" . $imagePath)
    :error "Aborted: missing container image archive"
}

# --- 4. Collision Check: Ensure Interface Names are not Claimed by Other Projects ---
:local existingBridge [/interface/bridge/find where name="bridge-clat"]
:if ([:len $existingBridge] > 0) do={
    :local bComm [/interface/bridge/get $existingBridge comment]
    :if (!($bComm ~ "^\\[tayga-unified:clat\\]")) do={
        :put " [FAIL] Conflict: 'bridge-clat' already exists and is NOT owned by this project. Aborting."
        :error "Aborted: bridge-clat collision"
    }
}

:local existingVeth [/interface/veth/find where name="veth-clat"]
:if ([:len $existingVeth] > 0) do={
    :local vComm [/interface/veth/get $existingVeth comment]
    :if (!($vComm ~ "^\\[tayga-unified:clat\\]")) do={
        :put " [FAIL] Conflict: 'veth-clat' already exists and is NOT owned by this project. Aborting."
        :error "Aborted: veth-clat collision"
    }
}

# --- 5. Detect WAN Interface (lte1 on Chateau, ether1 on CHR) ---
:local wanIf "lte1"
:if ([:len [/interface/find where name="lte1"]] = 0) do={
    :if ([:len [/interface/find where name="ether1"]] > 0) do={
        :set wanIf "ether1"
    }
}
:put ("--> WAN interface detected: " . $wanIf)

# --- 6. Create Dedicated Bridge for Container Transport ---
:if ([:len [/interface/bridge/find where name="bridge-clat"]] = 0) do={
    :put "--> Creating bridge-clat..."
    /interface/bridge/add name=bridge-clat comment="[tayga-unified:clat] Transport Bridge"
} else={
    :put "--> bridge-clat already exists with project ownership (reusing)"
}

# --- 7. Configure RouterOS Gateway IP Addresses on Bridge ---
:if ([:len [/ip/address/find where comment="[tayga-unified:clat] RouterOS IPv4 gateway"]] = 0) do={
    :put "--> Assigning IPv4 gateway 172.31.64.1/24 to bridge-clat..."
    /ip/address/add address=172.31.64.1/24 interface=bridge-clat comment="[tayga-unified:clat] RouterOS IPv4 gateway"
}

:if ([:len [/ipv6/address/find where comment="[tayga-unified:clat] RouterOS IPv6 gateway"]] = 0) do={
    :put "--> Assigning IPv6 gateway fd9b:64:1:fe::1/64 to bridge-clat..."
    /ipv6/address/add address=fd9b:64:1:fe::1/64 interface=bridge-clat advertise=no comment="[tayga-unified:clat] RouterOS IPv6 gateway"
}

# --- 8. Create VETH Interface for Container ---
:if ([:len [/interface/veth/find where name="veth-clat"]] = 0) do={
    :put "--> Creating veth-clat interface..."
    /interface/veth/add name=veth-clat \
        address=172.31.64.2/24,fd9b:64:1:fe::2/64 \
        gateway=172.31.64.1 \
        gateway6=fd9b:64:1:fe::1 \
        dhcp=no \
        comment="[tayga-unified:clat] Container VETH"
}

# --- 9. Attach VETH to Bridge ---
:if ([:len [/interface/bridge/port/find where interface="veth-clat"]] = 0) do={
    :put "--> Attaching veth-clat to bridge-clat..."
    /interface/bridge/port/add bridge=bridge-clat interface=veth-clat comment="[tayga-unified:clat] VETH bridge port"
}

# --- 10. Configure Container Environment Variables (preserves existing user values) ---
:put "--> Configuring container environment list tayga-clat-envs..."
:local envEntries {
    {"MODE"; "clat"};
    {"TAYGA_WORKERS"; "3"};
    {"TAYGA_OFFLOAD"; "off"};
    {"TAYGA_OFFLINK_MTU"; "1280"};
    {"PREF64"; "auto"};
    {"ROUTER4"; "172.31.64.1"};
    {"ACTIVE_SLOT"; "clat-a"};
    {"LAST_GOOD_SLOT"; "clat-a"};
    {"SLOT_A_STATE"; "installed"};
    {"SLOT_B_STATE"; "empty"}
}
:foreach item in=$envEntries do={
    :local k ($item->0)
    :local v ($item->1)
    :local envId [/container/envs/find where list="tayga-clat-envs" and key=$k]
    :if ([:len $envId] = 0) do={
        /container/envs/add list=tayga-clat-envs key=$k value=$v
    }
}

# --- 11. Configure Return IPv6 Route for Mapped CLAT Client ---
:if ([:len [/ipv6/route/find where comment="[tayga-unified:clat] CLAT return route"]] = 0) do={
    :put "--> Adding IPv6 return route fd9b:64:1:ff::10/128 via container..."
    /ipv6/route/add dst-address=fd9b:64:1:ff::10/128 gateway=fd9b:64:1:fe::2 comment="[tayga-unified:clat] CLAT return route"
}

# --- 12. Configure NAT44 Rule (LAN -> CLAT Client 192.0.0.1) ---
:if ([:len [/ip/firewall/nat/find where comment="[tayga-unified:clat] NAT44 to CLAT client"]] = 0) do={
    :put "--> Adding NAT44 srcnat rule for traffic to bridge-clat..."
    /ip/firewall/nat/add chain=srcnat out-interface=bridge-clat action=src-nat to-addresses=192.0.0.1 comment="[tayga-unified:clat] NAT44 to CLAT client"
}

# --- 13. Configure IPv6 Transit Firewall Filters (Safe Placement before Drop) ---
:local dropRules [/ipv6/firewall/filter/find where chain="forward" and action="drop" and !dynamic]
:local placeOpt ""
:if ([:len $dropRules] > 0) do={
    :set placeOpt ($dropRules->0)
}

:if ([:len [/ipv6/firewall/filter/find where comment="[tayga-unified:clat:fwd-out] Allow CLAT IPv6 egress"]] = 0) do={
    :put "--> Adding IPv6 firewall forward filter for CLAT egress..."
    :if ([:len $placeOpt] > 0) do={
        /ipv6/firewall/filter/add place-before=$placeOpt chain=forward src-address=fd9b:64:1::/48 in-interface=bridge-clat out-interface=$wanIf action=accept comment="[tayga-unified:clat:fwd-out] Allow CLAT IPv6 egress"
    } else={
        /ipv6/firewall/filter/add chain=forward src-address=fd9b:64:1::/48 in-interface=bridge-clat out-interface=$wanIf action=accept comment="[tayga-unified:clat:fwd-out] Allow CLAT IPv6 egress"
    }
}

:if ([:len [/ipv6/firewall/filter/find where comment="[tayga-unified:clat:fwd-in] Allow CLAT return ingress"]] = 0) do={
    :put "--> Adding IPv6 firewall forward filter for CLAT return ingress..."
    :if ([:len $placeOpt] > 0) do={
        /ipv6/firewall/filter/add place-before=$placeOpt chain=forward dst-address=fd9b:64:1:ff::10/128 in-interface=$wanIf out-interface=bridge-clat connection-state=established,related action=accept comment="[tayga-unified:clat:fwd-in] Allow CLAT return ingress"
    } else={
        /ipv6/firewall/filter/add chain=forward dst-address=fd9b:64:1:ff::10/128 in-interface=$wanIf out-interface=bridge-clat connection-state=established,related action=accept comment="[tayga-unified:clat:fwd-in] Allow CLAT return ingress"
    }
}

# --- 14. Configure Mandatory IPv6 ULA Masquerade on WAN ---
:if ([:len [/ipv6/firewall/nat/find where comment="[tayga-unified:clat] ULA IPv6 Masquerade"]] = 0) do={
    :put ("--> Adding mandatory IPv6 NAT masquerade for ULA on WAN (" . $wanIf . ")...")
    :do {
        /ipv6/firewall/nat/add chain=srcnat src-address=fd9b:64:1::/48 out-interface=$wanIf action=masquerade comment="[tayga-unified:clat] ULA IPv6 Masquerade"
    } on-error={
        :put " [FAIL] /ipv6/firewall/nat masquerade failed. IPv6 NAT is mandatory for ULA on LTE WAN."
        :error "Aborted: IPv6 NAT masquerade failed"
    }
}

# --- 15. Create and Start Container (matches any CLAT container instance) ---
:local existingCont [/container/find where comment~"^\\[tayga-unified:clat\\]"]
:if ([:len $existingCont] = 0) do={
    :put ("--> Creating container from " . $imagePath . "...")
    /container/add file=$imagePath \
        root-dir=$rootfsPath \
        interface=veth-clat \
        envlist=tayga-clat-envs \
        memory-high=128M \
        memory-max=192M \
        start-on-boot=yes \
        restart-policy=on-failure \
        restart-interval=10s \
        logging=yes \
        comment="[tayga-unified:clat] TAYGA CLAT Container (Slot clat-a)"
    :delay 3s
}

:local contId [/container/find where comment~"^\\[tayga-unified:clat\\]"]
:if ([:len $contId] > 0) do={
    :local isRun [/container/get $contId running]
    :if ($isRun != true) do={
        :put "--> Starting container..."
        /container/start $contId
    }
}

# Poll for running state (up to 30s)
:put "--> Waiting for container startup and RFC 7050 discovery..."
:local contRunning false
:for i from=1 to=30 do={
    :if ($contRunning = false) do={
        :local r [/container/get $contId running]
        :if ($r = true) do={
            :set contRunning true
        } else={
            :delay 1s
        }
    }
}

# Additional warm-up for DNS64 resolution
:delay 5s

# --- 14. Configure Probe Route & Test Connectivity ---
:if ([:len [/ip/route/find where comment="[tayga-unified:clat:probe] Probe Route"]] = 0) do={
    :put "--> Adding probe route 1.1.1.1/32 via 172.31.64.2..."
    /ip/route/add dst-address=1.1.1.1/32 gateway=172.31.64.2 distance=1 comment="[tayga-unified:clat:probe] Probe Route"
}

:put "--> Testing CLAT probe ping (1.1.1.1 src 172.31.64.1 count 3)..."
:local probeOk false
:local pingRx [/ping 1.1.1.1 src-address=172.31.64.1 count=3]
:if ($pingRx > 0) do={
    :set probeOk true
    :put (" [PASS] CLAT probe ping successful (" . $pingRx . "/3 received)!")
} else={
    :put " [WARN] Probe ping received 0 packets. Check container logs: /log print where topics~'container'"
}

# --- 15. Activate Default Route ONLY if Probe Succeeded ---
:if ($probeOk = true) do={
    :if ([:len [/ip/route/find where comment="[tayga-unified:clat:default] Default route via TAYGA CLAT"]] = 0) do={
        :put "--> Activating default IPv4 route 0.0.0.0/0 via 172.31.64.2 (distance 10)..."
        /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 distance=10 comment="[tayga-unified:clat:default] Default route via TAYGA CLAT"
    }
    :put "============================================================"
    :put " TAYGA CLAT Installation Complete & Active!"
    :put "============================================================"
} else={
    :put "============================================================"
    :put " TAYGA CLAT Installed. Default route NOT activated automatically"
    :put " because probe test did not receive replies. Check logs and"
    :put " run routeros-verify.rsc to inspect."
    :put "============================================================"
}
