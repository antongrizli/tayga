#!/bin/sh
# Detached activation deadline. All recovery inputs live in the transaction.
set -eu
[ "$#" -eq 5 ] || exit 2
lock=$1
transaction=$2
seconds=$3
runner=$4
started=$5
case "$runner:$seconds" in *[!0-9:]*|:*|*:) exit 2 ;; esac
same_transaction() { [ -f "$lock/id" ] && [ "$(cat "$lock/id")" = "$transaction" ]; }
process_start() {
    if [ -d /proc/self ]; then
        [ -r "/proc/$runner/stat" ] || return 1
        awk '{print $22}' "/proc/$runner/stat"
    else LC_ALL=C ps -p "$runner" -o lstart= 2>/dev/null
    fi
}
process_group() {
    if [ -d /proc/self ]; then
        [ -r "/proc/$runner/stat" ] || return 1
        awk '{print $5}' "/proc/$runner/stat"
    else ps -p "$runner" -o pgid= 2>/dev/null | tr -d ' '
    fi
}
session_groups() {
    for stat in /proc/[0-9]*/stat; do
        [ -r "$stat" ] || continue
        record=$(cat "$stat" 2>/dev/null) || continue
        # comm may contain spaces, parentheses and newlines. Strip through its
        # LAST delimiter before splitting the kernel-controlled numeric fields.
        fields=${record##*) }
        [ "$fields" != "$record" ] || continue
        # shellcheck disable=SC2086 # intentional splitting of /proc stat fields
        set -- $fields
        [ "$#" -ge 4 ] || continue
        if [ "$4" = "$runner" ]; then printf '%s\n' "$3"; fi
    done | sort -u
}
signal_session() {
    signal=$1
    if [ -d /proc/self ]; then
        # timeout and some launchers create child groups in our session.
        groups=$(session_groups)
        for group in $groups; do kill "-$signal" "-$group" 2>/dev/null || :; done
    else
        kill "-$signal" "-$runner" 2>/dev/null || :
    fi
}
# Publish process identity before acknowledging arming. Manual recovery reuses
# the original guard's metadata so its sleeping process can be cancelled too.
same_transaction || exit 0
# Persisted snapshots must never target processes or routes from another boot
# or namespace (for example after a container restart).
if [ -f "$lock/boot.id" ]; then
    current_boot=
    if [ -r /proc/sys/kernel/random/boot_id ]; then
        current_boot=$(cat /proc/sys/kernel/random/boot_id)
    elif [ "$(uname -s)" = FreeBSD ]; then
        current_boot=$(sysctl -n kern.boottime 2>/dev/null | awk '{print $4,$7}')
    fi
    if [ -n "$current_boot" ] && [ "$current_boot" != "$(cat "$lock/boot.id")" ]; then
        echo 'Recovery belongs to another boot; backups retained for manual review' >&2
        exit 1
    fi
    if [ -f "$lock/pid.namespace" ] && [ -f "$lock/net.namespace" ]; then
        if [ "$(readlink /proc/self/ns/pid 2>/dev/null || :)" != "$(cat "$lock/pid.namespace")" ] ||
            [ "$(readlink /proc/self/ns/net 2>/dev/null || :)" != "$(cat "$lock/net.namespace")" ]; then
            echo 'Recovery belongs to another namespace; backups retained for manual review' >&2
            exit 1
        fi
    fi
fi
if [ ! -f "$lock/armed" ]; then
    printf '%s\n' "$$" > "$lock/watcher.pid"
    if [ -r "/proc/$$/stat" ]; then awk '{print $22}' "/proc/$$/stat" > "$lock/watcher.start"
    else LC_ALL=C ps -p "$$" -o lstart= > "$lock/watcher.start"
    fi
    printf 'armed\n' > "$lock/armed"
fi
sleep "$seconds"
same_transaction || exit 0
if ln "$lock/watchdog.intent" "$lock/decision" 2>/dev/null; then
    echo "TAYGA activation deadline expired ($transaction)" >&2
elif [ "$(cat "$lock/decision" 2>/dev/null || :)" = commit ] && [ "$seconds" != 0 ]; then
    # Readiness already won the atomic decision. Let its live owner complete
    # housekeeping; a dead owner still needs its committed backups retired.
    if [ "$(process_start || :)" = "$started" ]; then exit 0; fi
fi
same_transaction || exit 0
# Cancel the transaction's own session before replaying the recovery journal.
# Validate both leader identity and process group to avoid touching another job.
current=$(process_start || :)
owned=no
if [ "$current" = "$started" ] && [ "$(process_group || :)" = "$runner" ]; then owned=yes
elif [ -z "$current" ] && { kill -0 "-$runner" 2>/dev/null || { [ -d /proc/self ] && [ -n "$(session_groups)" ]; }; }; then
    # A killed leader can leave commands behind. The live orphan group retains
    # its group ID until its members exit, so terminate those commands too.
    owned=yes
fi
if [ "$owned" = yes ]; then
    signal_session TERM
    sleep 1
    current=$(process_start || :)
    if [ -z "$current" ] || [ "$current" = "$started" ]; then signal_session KILL; fi
fi
same_transaction || exit 0
# The copy remains available even if restoring files removes installed helpers.
exec sh "$lock/recover.sh" "$lock" "$transaction"
