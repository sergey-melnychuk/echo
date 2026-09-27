#!/usr/bin/env bash
# Runs one scenario's part on this node. Normally called by ops/harness.sh
# over ssh, which also writes peers.txt (discover) and ticket.txt (after the
# sharing step of scenarios 4/6) next to this script.
set -euo pipefail

#
# Usage: ./run_scenario.sh <scenario> <this-node> [target-node]
# With a target node, every other node ignores the call — that's how the
# docs scenarios stage their steps (scenario 4 home, then scenario 4 cell).
SCENARIO="$1"
NODE="$2"
TARGET="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PEERS_FILE="${SCRIPT_DIR}/peers.txt"
TICKET_FILE="${SCRIPT_DIR}/ticket.txt"

if [ -n "$TARGET" ] && [ "$TARGET" != "$NODE" ]; then
  exit 0
fi

# Look up one peer's id by node name from peers.txt ("name id" per line).
peer_id() {
  awk -v n="$1" '$1==n {print $2}' "$PEERS_FILE" 2>/dev/null | head -1
}

# Stop this node's previous probe, if any: the docs stores under probe-data
# can only be opened by one process at a time. probe.log is appended to, not
# truncated, so earlier scenarios' lines survive a restart (scenario 6 needs
# scenario 4's history); each run starts with its own `started` line.
stop_probe() {
  if [ -f probe.pid ] && kill -0 "$(cat probe.pid)" 2>/dev/null; then
    kill -INT "$(cat probe.pid)"
    for _ in $(seq 1 10); do
      kill -0 "$(cat probe.pid)" 2>/dev/null || break
      sleep 1
    done
  fi
  rm -f probe.pid
}

run_probe() {
  stop_probe
  # </dev/null so an ssh session that started this can close straight away
  nohup ./probe --name "$NODE" "$@" >> probe.log 2>&1 < /dev/null &
  echo $! > probe.pid
}

start_probe() {
  local peer_names=("$@")
  local ids=()
  for n in "${peer_names[@]}"; do
    local id
    id="$(peer_id "$n")"
    if [ -z "$id" ]; then
      echo "no known id for peer '$n' yet — run ./ops/harness.sh discover" >&2
      return 1
    fi
    ids+=("$id")
  done
  local joined
  joined="$(IFS=,; echo "${ids[*]}")"
  run_probe --peers "$joined"
}

# Sharing side of scenarios 4/6. The probe writes the doc's read ticket to
# probe-data/ticket.txt, which the harness then copies to the other nodes.
start_share() {
  local file="$1"
  if [ ! -f "$file" ]; then
    echo "missing $file on $NODE — create it first, e.g. head -c 300000000 /dev/urandom > $file" >&2
    return 1
  fi
  run_probe --share "$file"
}

# Receiving side of scenarios 4/6: ticket.txt is copied here by the harness
# from the sharing node.
start_join() {
  if [ ! -s "$TICKET_FILE" ]; then
    echo "no ticket on $NODE yet — run the sharing step first (harness scenario <n> home)" >&2
    return 1
  fi
  run_probe --join "$(cat "$TICKET_FILE")"
}

case "$SCENARIO" in
  1)
    case "$NODE" in
      anchor-us)   start_probe anchor-asia ;;
      anchor-asia) start_probe anchor-us ;;
      *) exit 0 ;;
    esac
    ;;
  2)
    case "$NODE" in
      home)      start_probe anchor-us ;;
      anchor-us) start_probe home ;;
      *) exit 0 ;;
    esac
    ;;
  3)
    case "$NODE" in
      cell)        start_probe anchor-asia ;;
      anchor-asia) start_probe cell ;;
      *) exit 0 ;;
    esac
    ;;
  4)
    # Home imports the test file and shares it; everyone else joins. Stage it
    # with a target node: scenario 4 home (the harness then hands the ticket
    # to everyone), then scenario 4 anchor-us, and once that finishes
    # anchor-asia and cell. For the changed-file comparison, edit the file on
    # home and run scenario 4 home again: same key, same doc, same ticket.
    case "$NODE" in
      home) start_share "${SHARE_FILE:-testfile.bin}" ;;
      *)    start_join ;;
    esac
    ;;
  5)
    # Same pairing as scenario 3; toggle cell's network while it runs.
    case "$NODE" in
      cell)        start_probe anchor-asia ;;
      anchor-asia) start_probe cell ;;
      *) exit 0 ;;
    esac
    ;;
  6)
    # Stop cell's probe first (harness stop cell), wait, then scenario 6 home
    # to add a new entry to the same doc, then scenario 6 cell to rejoin and
    # time the catch-up. cell's data dir keeps what it synced in scenario 4.
    case "$NODE" in
      home) start_share "${CATCHUP_FILE:-catchup.bin}" ;;
      cell) start_join ;;
      *) exit 0 ;;
    esac
    ;;
  *)
    echo "unknown scenario $SCENARIO" >&2
    exit 1
    ;;
esac
