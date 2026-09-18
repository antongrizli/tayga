# ==============================================================================
# RouterOS 7 Installation Script: TAYGA NAT64 (Server-Side Translator RFC 6146/6147)
# ==============================================================================
# Deploys TAYGA unified container in NAT64 mode with Unbound DNS64.
# Uses tagged configuration [tayga-unified:nat64] for safe idempotency & rollback.
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-install-nat64.rsc
# ==============================================================================

:put "============================================================"
:put " Deploying TAYGA Unified NAT64 + DNS64 Container..."
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
:local rootfsPath ($basePath . "/rootfs/nat64")

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
:global POLICY
:global PREFER_DIRECT_IPV4
:global ALLOW_LOCAL_NAT64
:global IPV6_ONLY_LAN_INTERFACES

:local policy "auto"
:if ([:len $POLICY] > 0) do={ :set policy $POLICY }

:local preferDirectIpv4 "yes"
:if ([:len $PREFER_DIRECT_IPV4] > 0) do={ :set preferDirectIpv4 $PREFER_DIRECT_IPV4 }

:local allowLocalNat64 "yes"
:if ([:len $ALLOW_LOCAL_NAT64] > 0) do={ :set allowLocalNat64 $ALLOW_LOCAL_NAT64 }

:local ipv6OnlyLanIfaces ""
:if ([:len $IPV6_ONLY_LAN_INTERFACES] > 0) do={ :set ipv6OnlyLanIfaces $IPV6_ONLY_LAN_INTERFACES }

:local useRegistry false
:if ($USE_REGISTRY = true) do={ :set useRegistry true }

:local remoteImage "ghcr.io/antongrizli/tayga-nat64:latest"
:if ([:len $REMOTE_IMAGE] > 0) do={ :set remoteImage $REMOTE_IMAGE }

:local registryUrl "https://ghcr.io"
:if ([:len $REGISTRY_URL] > 0) do={ :set registryUrl $REGISTRY_URL }

# Auto-detect: if local TAR is not present on storage, automatically switch to GHCR pull
:local hasLocalTar ([:len [/file/find where name=$imagePath]] > 0)
:if ($useRegistry = false and $hasLocalTar = false) do={
    :put ("--> Local image " . $imagePath . " not found; switching to GHCR registry pull (" . $remoteImage . ")...")
    :set useRegistry true
}

# --- 2. Run Preflight Audit First (NAT64 Mode) ---
:global AUDITMODE "nat64"
:do {
    /import file-name=$preflightScript
} on-error={
    :error "Installation aborted: preflight audit failed."
}

# Check container image source
:if ($useRegistry = false and $hasLocalTar = false) do={
    :put (" [FAIL] Required image archive '" . $imagePath . "' not found and USE_REGISTRY is false.")
    :put (" Either upload TAR to '" . $imagePath . "' or set :global USE_REGISTRY true before /import")
    :error "Aborted: missing container image source"
}

# --- 3. Detect WAN Interface and Gateway ---
:local wanIf "lte1"
:if ([:len [/interface/find where name="lte1"]] = 0) do={
    :local defRoute [/ip/route/find where dst-address="0.0.0.0/0" and active=yes]
    :if ([:len $defRoute] > 0) do={
        :set wanIf [/ip/route/get ($defRoute->0) gateway]
    } else={
        :set wanIf "ether1"
    }
}
:if ([:len [/interface/find where name=$wanIf]] = 0) do={
    :set wanIf "ether1"
}
:local wanGw "192.168.65.1"
:local gwRoute [/ip/route/find where dst-address="0.0.0.0/0" and active=yes]
:if ([:len $gwRoute] > 0) do={
    :do { :set wanGw [/ip/route/get ($gwRoute->0) gateway] } on-error={}
}
:put ("--> WAN interface detected: " . $wanIf . " (Gateway: " . $wanGw . ")")

# --- 4. Check Required Image Archive on Storage ---
:local imageFound [:len [/file/find where name=$imagePath]]
:if ($imageFound = 0) do={
    :put (" [FAIL] Required image archive '" . $imagePath . "' not found on storage drive.")
    :put (" Upload the image first: scp dist/tayga-arm64.tar admin@<router-ip>:" . $imagePath)
    :error "Aborted: missing container image archive"
}

# --- 3. Collision Check: Ensure Interface Names are not Claimed by Other Projects ---
:local existingBridge [/interface/bridge/find where name="bridge-nat64"]
:if ([:len $existingBridge] > 0) do={
    :local bComm [/interface/bridge/get $existingBridge comment]
    :if (!($bComm ~ "^\\[tayga-unified:nat64\\]")) do={
        :put " [FAIL] Conflict: 'bridge-nat64' already exists and is NOT owned by this project. Aborting."
        :error "Aborted: bridge-nat64 collision"
    }
}

:local existingVeth [/interface/veth/find where name="veth-nat64"]
:if ([:len $existingVeth] > 0) do={
    :local vComm [/interface/veth/get $existingVeth comment]
    :if (!($vComm ~ "^\\[tayga-unified:nat64\\]")) do={
        :put " [FAIL] Conflict: 'veth-nat64' already exists and is NOT owned by this project. Aborting."
        :error "Aborted: veth-nat64 collision"
    }
}

# --- 4. Create Dedicated Bridge for Container Transport ---
:if ([:len [/interface/bridge/find where name="bridge-nat64"]] = 0) do={
    :put "--> Creating bridge-nat64..."
    /interface/bridge/add name=bridge-nat64 comment="[tayga-unified:nat64] Transport Bridge"
} else={
    :put "--> bridge-nat64 already exists with project ownership (reusing)"
}

# --- 5. Configure RouterOS Gateway IP Addresses on Bridge ---
:if ([:len [/ip/address/find where comment="[tayga-unified:nat64] RouterOS IPv4 gateway"]] = 0) do={
    :put "--> Assigning IPv4 gateway 192.168.238.1/30 to bridge-nat64..."
    /ip/address/add address=192.168.238.1/30 interface=bridge-nat64 comment="[tayga-unified:nat64] RouterOS IPv4 gateway"
}

:if ([:len [/ipv6/address/find where comment="[tayga-unified:nat64] RouterOS IPv6 gateway"]] = 0) do={
    :put "--> Assigning IPv6 gateway fc68::1/126 to bridge-nat64..."
    /ipv6/address/add address=fc68::1/126 interface=bridge-nat64 advertise=no comment="[tayga-unified:nat64] RouterOS IPv6 gateway"
}

# --- 6. Create VETH Interface for Container ---
:if ([:len [/interface/veth/find where name="veth-nat64"]] = 0) do={
    :put "--> Creating veth-nat64 interface..."
    /interface/veth/add name=veth-nat64 \
        address=192.168.238.2/30,fc68::2/126 \
        gateway=192.168.238.1 \
        gateway6=fc68::1 \
        dhcp=no \
        comment="[tayga-unified:nat64] Container VETH"
}

# --- 7. Attach VETH to Bridge ---
:if ([:len [/interface/bridge/port/find where interface="veth-nat64"]] = 0) do={
    :put "--> Attaching veth-nat64 to bridge-nat64..."
    /interface/bridge/port/add bridge=bridge-nat64 interface=veth-nat64 comment="[tayga-unified:nat64] VETH bridge port"
}

# --- 8. Configure Container Environment Variables (key-by-key with list= / key= / value=) ---
:put "--> Configuring container environment list tayga-nat64-envs..."
:local envEntries {
    {"MODE"; "nat64"};
    {"TAYGA_PREF64"; "64:ff9b::/96"};
    {"TAYGA_POOL4"; "192.168.240.0/20"};
    {"TAYGA_ADDR4"; "192.168.240.1"};
    {"TAYGA_ADDR6"; "fc68::2"};
    {"TAYGA_WORKERS"; "3"};
    {"TAYGA_OFFLOAD"; "off"};
    {"DNS64_UPSTREAM"; "1.1.1.1,8.8.8.8"}
}
:foreach item in=$envEntries do={
    :local k ($item->0)
    :local v ($item->1)
    :local envId [/container/envs/find where list="tayga-nat64-envs" and key=$k]
    :if ([:len $envId] = 0) do={
        /container/envs/add list=tayga-nat64-envs key=$k value=$v
    }
}

# --- 8b. Configure Shared Policy Environment (tayga-policy-envs) ---
:put "--> Configuring shared policy environment list tayga-policy-envs..."
:local policyEntries {
    {"POLICY"; $policy};
    {"PREFER_DIRECT_IPV4"; $preferDirectIpv4};
    {"ALLOW_LOCAL_NAT64"; $allowLocalNat64};
    {"IPV6_ONLY_LAN_INTERFACES"; $ipv6OnlyLanIfaces}
}
:foreach item in=$policyEntries do={
    :local k ($item->0)
    :local v ($item->1)
    :local envId [/container/envs/find where list="tayga-policy-envs" and key=$k]
    :if ([:len $envId] = 0) do={
        /container/envs/add list=tayga-policy-envs key=$k value=$v
    } else={
        /container/envs/set ($envId->0) value=$v
    }
}

# --- 9. Configure Routes for NAT64 Prefix and IPv4 Pool ---
:local nat64PrefixRoutes [/ipv6/route/find where comment~"^\\[tayga-unified:nat64(:prefix)?\\]"]
:local disPrefixRoute "no"
:if ($policy = "auto") do={ :set disPrefixRoute "yes" }

:if ([:len $nat64PrefixRoutes] > 0) do={
    /ipv6/route/set ($nat64PrefixRoutes->0) dst-address=64:ff9b::/96 gateway=fc68::2 disabled=$disPrefixRoute comment="[tayga-unified:nat64:prefix] NAT64 prefix route"
} else={
    :put "--> Routing 64:ff9b::/96 via container (fc68::2)..."
    /ipv6/route/add dst-address=64:ff9b::/96 gateway=fc68::2 disabled=$disPrefixRoute comment="[tayga-unified:nat64:prefix] NAT64 prefix route"
}

:if ([:len [/ip/route/find where comment="[tayga-unified:nat64] NAT64 dynamic pool route"]] = 0) do={
    :put "--> Routing dynamic pool 192.168.240.0/20 via container (192.168.238.2)..."
    /ip/route/add dst-address=192.168.240.0/20 gateway=192.168.238.2 comment="[tayga-unified:nat64] NAT64 dynamic pool route"
}

# --- 9b. Isolated Probe Routing Table and Route for NAT64 Health Probing ---
:local nat64Table [/routing/table/find where name="tayga-probe-nat64"]
:if ([:len $nat64Table] = 0) do={
    :put "--> Creating isolated routing table tayga-probe-nat64..."
    /routing/table/add name=tayga-probe-nat64 fib comment="[tayga-unified:nat64] Isolated NAT64 Probe Table"
} else={
    :local nComm [/routing/table/get ($nat64Table->0) comment]
    :if (!($nComm ~ "^\\[tayga-unified")) do={
        :put " [FAIL] Routing table 'tayga-probe-nat64' already exists and is not owned by this project."
        :error "Aborted: routing table tayga-probe-nat64 already exists and is unowned"
    }
}
:if ([:len [/ipv6/route/find where routing-table="tayga-probe-nat64" and dst-address="64:ff9b::/96" and comment~"^\\[tayga-unified"]] = 0) do={
    :put "--> Adding isolated NAT64 probe route in table tayga-probe-nat64..."
    /ipv6/route/add dst-address=64:ff9b::/96 gateway=fc68::2 routing-table=tayga-probe-nat64 comment="[tayga-unified:nat64:probe] NAT64 Probe Route"
}

# --- 10. Configure NAT44 Masquerade for Dynamic Pool and Container DNS64 Transport ---
:if ([:len [/ip/firewall/nat/find where comment="[tayga-unified:nat64] NAT64 pool masquerade"]] = 0) do={
    :put ("--> Adding NAT44 srcnat masquerade for 192.168.240.0/20 on WAN (" . $wanIf . ")...")
    /ip/firewall/nat/add chain=srcnat src-address=192.168.240.0/20 out-interface=$wanIf action=masquerade comment="[tayga-unified:nat64] NAT64 pool masquerade"
}

:if ([:len [/ip/firewall/nat/find where comment="[tayga-unified:nat64] Container DNS64 WAN masquerade"]] = 0) do={
    :put ("--> Adding NAT44 srcnat masquerade for container transport 192.168.238.0/30 on WAN (" . $wanIf . ")...")
    /ip/firewall/nat/add chain=srcnat src-address=192.168.238.0/30 out-interface=$wanIf action=masquerade comment="[tayga-unified:nat64] Container DNS64 WAN masquerade"
}

# --- 10b. Policy Routing for NAT64 Pool (Prevents route collision when CLAT and NAT64 coexist) ---
:local wanTable [/routing/table/find where name="wan-direct"]
:if ([:len $wanTable] = 0) do={
    /routing/table/add name=wan-direct fib comment="[tayga-unified:direct] Isolated Direct WAN Routing Table"
} else={
    :local tComm [/routing/table/get ($wanTable->0) comment]
    :if (!($tComm ~ "^\\[tayga-unified")) do={
        :put " [FAIL] Routing table 'wan-direct' already exists and is not owned by this project."
        :error "Aborted: routing table wan-direct already exists and is unowned"
    }
}
:if ([:len [/ip/route/find where routing-table="wan-direct" and dst-address="0.0.0.0/0" and comment~"^\\[tayga-unified"]] = 0) do={
    /ip/route/add dst-address=0.0.0.0/0 gateway=$wanGw routing-table=wan-direct comment="[tayga-unified:nat64] Direct WAN default route"
}
:if ([:len [/routing/rule/find where src-address="192.168.240.0/20" and comment~"^\\[tayga-unified"]] = 0) do={
    /routing/rule/add src-address=192.168.240.0/20 table=wan-direct action=lookup-only-in-table comment="[tayga-unified:nat64] NAT64 pool policy rule"
}

# --- 10c. IPv6 Forward Transit between CLAT and NAT64 Bridges (for local coexistence) ---
:if ([:len [/interface/bridge/find where name="bridge-clat"]] > 0) do={
    :if ([:len [/ipv6/firewall/filter/find where comment="[tayga-unified:nat64:fwd-clat] CLAT to NAT64 bridge transit"]] = 0) do={
        /ipv6/firewall/filter/add chain=forward in-interface=bridge-clat out-interface=bridge-nat64 action=accept comment="[tayga-unified:nat64:fwd-clat] CLAT to NAT64 bridge transit"
    }
    :if ([:len [/ipv6/firewall/filter/find where comment="[tayga-unified:nat64:fwd-ret] NAT64 to CLAT bridge transit"]] = 0) do={
        /ipv6/firewall/filter/add chain=forward in-interface=bridge-nat64 out-interface=bridge-clat action=accept comment="[tayga-unified:nat64:fwd-ret] NAT64 to CLAT bridge transit"
    }
}

# --- 11. Create Container (Standby Mode: start-on-boot=no) ---
:local existingNatCont [/container/find where comment~"^\\[tayga-unified:nat64\\]"]
:if ([:len $existingNatCont] = 0) do={
    :if ($useRegistry = true) do={
        :put ("--> Setting container registry URL: " . $registryUrl . "...")
        :do { /container/config/set registry-url=$registryUrl } on-error={}
        :put ("--> Pulling remote container image '" . $remoteImage . "' into " . $rootfsPath . "...")
        /container/add remote-image=$remoteImage \
            root-dir=$rootfsPath \
            interface=veth-nat64 \
            envlist=tayga-nat64-envs \
            memory-high=128M \
            memory-max=192M \
            start-on-boot=no \
            restart-policy=on-failure \
            restart-interval=10s \
            logging=yes \
            comment="[tayga-unified:nat64] TAYGA NAT64 Container"

        :put "--> Downloading and extracting container layers from GHCR (may take 10-60s)..."
        :local candCont [/container/find where comment~"^\\[tayga-unified:nat64\\]"]
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
            interface=veth-nat64 \
            envlist=tayga-nat64-envs \
            memory-high=128M \
            memory-max=192M \
            start-on-boot=no \
            restart-policy=on-failure \
            restart-interval=10s \
            logging=yes \
            comment="[tayga-unified:nat64] TAYGA NAT64 Container"
        :delay 3s
    }
}

:local contId [/container/find where comment~"^\\[tayga-unified:nat64\\]"]
:if ($policy = "auto") do={
    :put "--> POLICY=auto: Container created in standby; Network State Controller will manage lifecycle."
} else={
    :if ([:len $contId] > 0) do={
        :local isRun [/container/get $contId running]
        :if ($isRun != true) do={
            :put "--> Starting container (POLICY=manual)..."
            /container/start $contId
        }
    }

    # Poll for running state (up to 30s)
    :put "--> Waiting for NAT64 + DNS64 initialization..."
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
}

# --- 12. Register Network State Controller in Scheduler ---
:local controllerScript ($basePath . "/scripts/routeros-controller.rsc")
:local schedId [/system/scheduler/find where name="tayga-controller"]
:if ([:len $schedId] = 0) do={
    :put "--> Registering Network State Controller in /system/scheduler (interval: 15s)..."
    /system/scheduler/add name="tayga-controller" interval=15s on-event=("/import file-name=" . $controllerScript) comment="[tayga-unified:controller] Network State Controller"
} else={
    :put "--> Updating /system/scheduler tayga-controller..."
    /system/scheduler/set $schedId on-event=("/import file-name=" . $controllerScript)
}

# --- 13. Initial Network State Controller Evaluation ---
:put "--> Running initial Network State Controller cycle..."
:do {
    /import file-name=$controllerScript
} on-error={
    :put " [WARN] Controller initial execution encountered a non-fatal error; scheduler will retry."
}

:put "============================================================"
:put " TAYGA NAT64 + DNS64 Installation Complete!"
:put " DNS64 server available at fc68::2 / 192.168.238.2"
:put "============================================================"
