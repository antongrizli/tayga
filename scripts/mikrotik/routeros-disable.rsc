# ==============================================================================
# RouterOS 7 Script: Temporarily Disable TAYGA Service
# ==============================================================================
# Safely deactivates IPv4 default route / traffic steering before stopping the
# container. Preserves all configuration for quick re-enabling.
#
# Usage:
#   /import file-name=usb1/telekom-xlat/scripts/routeros-disable.rsc
# ==============================================================================

:put "============================================================"
:put " Disabling TAYGA Service..."
:put "============================================================"

# 1. Disable default and probe routes first (stops traffic steering)
:put "--> Disabling TAYGA IPv4 routes..."
/ip/route/disable [find where comment~"tayga-unified"]

:put "--> Disabling TAYGA IPv6 routes..."
/ipv6/route/disable [find where comment~"tayga-unified"]

# 2. Stop container
:put "--> Stopping container..."
:local conts [/container/find where comment~"tayga-unified"]
:foreach c in=$conts do={
    :do {
        /container/stop $c
    } on-error={
        :put "--> Container already stopped."
    }
}

:put "============================================================"
:put " TAYGA service disabled safely. Configuration preserved."
:put " To re-enable, start container and enable routes."
:put "============================================================"
