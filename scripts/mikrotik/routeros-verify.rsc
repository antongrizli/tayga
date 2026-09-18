# ==============================================================================
# RouterOS 7 Verification Script: TAYGA Unified Service Health Check
# ==============================================================================
# Inspects container running state, VETH link status, probe ping,
# IPv4/IPv6 routing, and prints recent container logs.
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-verify.rsc
# ==============================================================================

:put "============================================================"
:put " TAYGA Unified Service Verification"
:put "============================================================"

# --- 1. Container Running State ---
:local conts [/container/find where comment~"^\\[tayga-unified"]
:if ([:len $conts] = 0) do={
    :put " [FAIL] No TAYGA container found."
} else={
    :foreach c in=$conts do={
        :local cComm [/container/get $c comment]
        :local isRun [/container/get $c running]
        :put (" [INFO] Container (" . $cComm . "):")
        :if ($isRun = true) do={
            :put "  -> [PASS] Container is RUNNING"
        } else={
            :put "  -> [FAIL] Container is NOT running"
        }
    }
}

# --- 2. VETH Interface Status ---
:local veths [/interface/veth/find where comment~"^\\[tayga-unified"]
:foreach v in=$veths do={
    :local vName [/interface/veth/get $v name]
    :local vRunning [/interface/veth/get $v running]
    :put (" [INFO] Interface " . $vName . ": running=" . $vRunning)
}

# --- 3. End-to-End Connectivity Pings (using numeric packet counts) ---
:put "--> Testing native IPv6 upstream connectivity (Cloudflare DNS 2606:4700:4700::1111)..."
:local v6Rx [/ping 2606:4700:4700::1111 count=3]
:if ($v6Rx > 0) do={
    :put (" [PASS] IPv6 upstream ping OK (" . $v6Rx . "/3 received)")
} else={
    :put " [FAIL] IPv6 upstream ping failed (0/3 received)"
}

:put "--> Testing IPv4 translation connectivity via CLAT (1.1.1.1)..."
:local v4Rx [/ping 1.1.1.1 src-address=172.31.64.1 count=3]
:if ($v4Rx > 0) do={
    :put (" [PASS] IPv4 translation ping OK (" . $v4Rx . "/3 received)")
} else={
    :put " [FAIL] IPv4 translation ping failed (0/3 received)"
}

# --- 4. Active Routes ---
:put "--> Active TAYGA IPv4 Routes:"
/ip/route/print where comment~"^\\[tayga-unified"

:put "--> Active TAYGA IPv6 Routes:"
/ipv6/route/print where comment~"^\\[tayga-unified"

# --- 5. Container Logs (Last 15 lines) ---
:put "--> Recent Container Log Entries:"
/log/print where topics~"container"

:put "============================================================"
:put " Verification Finished."
:put "============================================================"
