#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Off-LAN DHT end-to-end test on a single machine (M4).
#
# The in-process/loopback tests cannot exercise the full send-over-DHT path:
# Prism's IP hygiene (correctly) strips loopback/private addresses before a
# locator is published, so no dialable address ever reaches the send path. This
# script builds a miniature "WAN" instead — two Linux network namespaces joined
# by a veth pair, each holding ONE globally-routable-looking IP (8.8.8.2 /
# 8.8.8.3). Those pass IP hygiene yet route only to each other, so two daemons
# discover and message each other purely through the Kademlia DHT, with mDNS
# OFF and no shared LAN.
#
# It is ROOTLESS: it re-execs itself inside `unshare --user --net
# --map-root-user`, where we are root in a private user+network namespace. No
# real root, no Docker. Requires unprivileged user namespaces to be enabled
# (`sysctl kernel.unprivileged_userns_clone=1` on some distros); if that is
# disabled this script cannot run, which is why it is a manual harness and not a
# CI job.
#
# Usage:  ./scripts/dht-wan-test.sh
# Exits 0 and prints "PASS" only if both directions deliver.

set -u

# ── Re-exec into a private user+network namespace ────────────────────────────
if [ "${_DHT_WAN_INNER:-}" != "1" ]; then
    unshare --user --net --map-root-user true 2>/dev/null || {
        echo "ERROR: unprivileged user namespaces are unavailable on this host." >&2
        echo "       (Try: sysctl -w kernel.unprivileged_userns_clone=1)" >&2
        exit 2
    }
    exec env _DHT_WAN_INNER=1 unshare --user --net --map-root-user "$0" "$@"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${PRISM_BIN:-$ROOT/target/debug}"
if [ ! -x "$BIN/prismd" ] || [ ! -x "$BIN/prism" ]; then
    echo "ERROR: build the binaries first (cargo build --bin prismd --bin prism)." >&2
    exit 2
fi

T="$(mktemp -d)"
PA=""; PB=""; A_PID=""; B_PID=""
cleanup() { kill "$A_PID" "$B_PID" "$PA" "$PB" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

# ── Two "hosts" joined by a veth link ────────────────────────────────────────
ip link set lo up 2>/dev/null
unshare --net sleep 900 & PA=$!
unshare --net sleep 900 & PB=$!
sleep 0.3
NSA="/proc/$PA/ns/net"; NSB="/proc/$PB/ns/net"
ip link add vethA type veth peer name vethB
ip link set vethA netns "$PA"
ip link set vethB netns "$PB"
nsenter --net=$NSA ip link set lo up
nsenter --net=$NSA ip addr add 8.8.8.2/24 dev vethA
nsenter --net=$NSA ip link set vethA up
nsenter --net=$NSB ip link set lo up
nsenter --net=$NSB ip addr add 8.8.8.3/24 dev vethB
nsenter --net=$NSB ip link set vethB up

start_daemon() { # ns handle-tag ...args
    local ns="$1" tag="$2"; shift 2
    nsenter --net="$ns" "$BIN/prismd" --socket "$T/$tag.sock" \
        --keystore "$T/$tag.pks" --sessions "$T/$tag.prs" "$@" >"$T/$tag.log" 2>&1 &
    for _ in $(seq 1 50); do [ -S "$T/$tag.sock" ] && break; sleep 0.1; done
}
init_id() { # tag nick
    printf '%s\npw-%s-secret\npw-%s-secret\n1\n' "$2" "$2" "$2" \
        | script -qec "$BIN/prism --socket $T/$1.sock init" /dev/null >/dev/null 2>&1
}

# Node A: bootstrap + DHT server on 8.8.8.2.
start_daemon "$NSA" a --listen /ip4/8.8.8.2/tcp/4001 \
    --external-address /ip4/8.8.8.2/tcp/4001 --no-mdns
A_PID=$!
init_id a alice
sleep 1
A_ID=$("$BIN/prism" --socket "$T/a.sock" status 2>/dev/null | grep -oE '12D3Koo[A-Za-z0-9]+' | head -1)
A_HANDLE=$("$BIN/prism" --socket "$T/a.sock" whoami | awk '/handle:/{print $2}')

# Node B on 8.8.8.3, bootstrapping to A.
start_daemon "$NSB" b --listen /ip4/8.8.8.3/tcp/4001 \
    --external-address /ip4/8.8.8.3/tcp/4001 --no-mdns \
    --bootstrap "/ip4/8.8.8.2/tcp/4001/p2p/$A_ID"
B_PID=$!
init_id b bob
B_HANDLE=$("$BIN/prism" --socket "$T/b.sock" whoami | awk '/handle:/{print $2}')

echo "A = $A_HANDLE @ 8.8.8.2   B = $B_HANDLE @ 8.8.8.3"
echo "waiting for DHT convergence…"
sleep 15

MSG_BA="hello A - from B over the DHT WAN"
MSG_AB="reply from A over the DHT WAN"
for _ in 1 2 3 4 5; do
    out=$("$BIN/prism" --socket "$T/b.sock" send "$A_HANDLE" "$MSG_BA")
    echo "$out" | grep -qi "^sent" && break
    sleep 4
done
sleep 1
"$BIN/prism" --socket "$T/a.sock" send "$B_HANDLE" "$MSG_AB" >/dev/null 2>&1
sleep 1

a_in="$("$BIN/prism" --socket "$T/a.sock" inbox)"
b_in="$("$BIN/prism" --socket "$T/b.sock" inbox)"

ok=1
echo "$a_in" | grep -qF "$MSG_BA" && echo "  B -> A: delivered" || { echo "  B -> A: FAILED"; ok=0; }
echo "$b_in" | grep -qF "$MSG_AB" && echo "  A -> B: delivered" || { echo "  A -> B: FAILED"; ok=0; }

if [ "$ok" = 1 ]; then echo "PASS: off-LAN DHT messaging works both directions"; exit 0
else echo "FAIL"; exit 1; fi
