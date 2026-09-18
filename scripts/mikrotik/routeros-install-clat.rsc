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
:local controllerScript ($basePath . "/scripts/routeros-controller.rsc")
:local rootfsPath ($basePath . "/rootfs/clat-a")

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

# --- 2. Run Preflight Audit First (Strict CLAT Mode) ---
:global AUDITMODE "clat"
:do {
    /import file-name=$preflightScript
} on-error={
    :error "Installation aborted: preflight audit failed."
}

# --- 3. Check Required Image Archive on Storage ---
:if ($useRegistry = false and $hasLocalTar = false) do={
    :put (" [FAIL] Required image archive '" . $imagePath . "' not found and UseRegistry is false.")
    :put (" Either upload TAR to '" . $imagePath . "' or set :global UseRegistry true before /import")
    :error "Aborted: missing container image source"
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
    {"POLICY"; "auto"};
    {"PreferDirectIpv4"; "yes"};
    {"LAN_REQUIRES_IPV4"; "yes"};
    {"AllowLocalNat64"; "no"};
    {"Ipv6OnlyLanInterfaces"; ""};
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

# --- 15. Create Isolated Routing Tables for Zero-Leak Probing ---
# Migration cleanup: Remove any legacy /32 probe route from main table
:do { /ip/route/remove [find where dst-address="1.1.1.1/32" and comment~"^\\[tayga-unified"] } on-error={}

:local wanTable [/routing/table/find where name="wan-direct"]
:if ([:len $wanTable] = 0) do={
    :put "--> Creating isolated routing table wan-direct..."
    /routing/table/add name=wan-direct fib comment="[tayga-unified:direct] Isolated Direct WAN Routing Table"
} else={
    :local tComm [/routing/table/get ($wanTable->0) comment]
    :if (!($tComm ~ "^\\[tayga-unified")) do={
        :put " [FAIL] Routing table 'wan-direct' already exists and is not owned by this project."
        :error "Aborted: routing table wan-direct already exists and is unowned"
    }
}

:local clatTable [/routing/table/find where name="tayga-probe-clat"]
:if ([:len $clatTable] = 0) do={
    :put "--> Creating isolated routing table tayga-probe-clat..."
    /routing/table/add name=tayga-probe-clat fib comment="[tayga-unified:clat] Isolated CLAT Probe Table"
} else={
    :local cComm [/routing/table/get ($clatTable->0) comment]
    :if (!($cComm ~ "^\\[tayga-unified")) do={
        :put " [FAIL] Routing table 'tayga-probe-clat' already exists and is not owned by this project."
        :error "Aborted: routing table tayga-probe-clat already exists and is unowned"
    }
}

# --- 16. Create Container (Decoupled: Standby Mode start-on-boot=no) ---
:local existingCont [/container/find where comment~"^\\[tayga-unified:clat\\]"]
:if ([:len $existingCont] = 0) do={
    :if ($useRegistry = true) do={
        :put ("--> Setting container registry URL: " . $registryUrl . "...")
        :do { /container/config/set registry-url=$registryUrl } on-error={}
        :put ("--> Pulling remote container image '" . $remoteImage . "' into " . $rootfsPath . "...")
        /container/add remote-image=$remoteImage \
            root-dir=$rootfsPath \
            interface=veth-clat \
            envlist=tayga-clat-envs \
            memory-high=128M \
            memory-max=192M \
            start-on-boot=no \
            restart-policy=on-failure \
            restart-interval=10s \
            logging=yes \
            comment="[tayga-unified:clat] TAYGA CLAT Container (Slot clat-a)"

        :put "--> Downloading and extracting container layers from GHCR (may take 10-60s)..."
        :local candCont [/container/find where comment~"^\\[tayga-unified:clat\\]"]
        :if ([:len $candCont] > 0) do={
            :local cId ($candCont->0)
            :local extWait 0
            :local isExtracted false
            :while (($isExtracted = false) && ($extWait < 180)) do={
                :local isStopped [/container/get $cId stopped]
                :if ($isStopped = true) do={
                    :set isExtracted true
                } else={
                    :delay 2s
                    :set extWait ($extWait + 2)
                }
            }
            :if ($isExtracted = false) do={
                :error "Aborted: remote image download/extraction timed out (180s)"
            } else={
                :put " [PASS] Container layers downloaded and extracted successfully."
            }
        }
    } else={
        :put ("--> Creating container from local image " . $imagePath . "...")
        /container/add file=$imagePath \
            root-dir=$rootfsPath \
            interface=veth-clat \
            envlist=tayga-clat-envs \
            memory-high=128M \
            memory-max=192M \
            start-on-boot=no \
            restart-policy=on-failure \
            restart-interval=10s \
            logging=yes \
            comment="[tayga-unified:clat] TAYGA CLAT Container (Slot clat-a)"
        :delay 3s
    }
}

# --- 17. Configure Isolated Probe Route & Standby Default Route ---
:if ([:len [/ip/route/find where routing-table="tayga-probe-clat" and dst-address="0.0.0.0/0"]] = 0) do={
    :put "--> Adding isolated CLAT probe route in table tayga-probe-clat..."
    /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 routing-table=tayga-probe-clat comment="[tayga-unified:clat:probe] CLAT Probe Route"
}

:if ([:len [/ip/route/find where comment~"^\\[tayga-unified:clat:default\\]" and routing-table="main"]] = 0) do={
    :put "--> Adding standby default IPv4 route 0.0.0.0/0 via 172.31.64.2 (disabled=yes)..."
    /ip/route/add dst-address=0.0.0.0/0 gateway=172.31.64.2 distance=1 routing-table=main disabled=yes comment="[tayga-unified:clat:default] Default route via TAYGA CLAT"
}

# --- 18. Register Network State Controller in Scheduler ---
:local schedId [/system/scheduler/find where name="tayga-controller"]
:if ([:len $schedId] = 0) do={
    :put "--> Registering Network State Controller in /system/scheduler (interval: 15s)..."
    /system/scheduler/add name="tayga-controller" interval=15s on-event=("/import file-name=" . $controllerScript) comment="[tayga-unified:controller] Network State Controller"
} else={
    :put "--> Updating /system/scheduler tayga-controller..."
    /system/scheduler/set $schedId on-event=("/import file-name=" . $controllerScript)
}

# --- 19. Initial Network State Controller Evaluation ---
:put "--> Running initial Network State Controller cycle..."
:do {
    /import file-name=$controllerScript
} on-error={
    :put " [WARN] Controller initial execution encountered a non-fatal error; scheduler will retry."
}

:put "============================================================"
:put " TAYGA CLAT Installation Complete & Controlled by State Machine!"
:put "============================================================"
