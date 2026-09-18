#!/bin/sh
set -eu

# Dispatcher for TAYGA unified container
MODE="${MODE:-clat}"

case "$MODE" in
  clat)
    echo "==> Starting TAYGA in CLAT mode (RFC 6877 / RFC 7050)..."
    exec /usr/local/sbin/clat-start.sh "$@"
    ;;
  nat64)
    echo "==> Starting TAYGA in NAT64 mode with Unbound DNS64..."
    exec /usr/local/sbin/nat64-start.sh "$@"
    ;;
  diagnose)
    echo "==> Running TAYGA diagnostic inspection..."
    exec /usr/local/sbin/diagnose.sh "$@"
    ;;
  *)
    echo "ERROR: Invalid MODE='$MODE'. Supported modes: clat, nat64, diagnose" >&2
    exit 1
    ;;
esac
