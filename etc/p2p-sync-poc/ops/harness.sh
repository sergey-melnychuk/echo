#!/usr/bin/env bash
# Runs the experiment from your laptop over plain ssh: creates the anchor
# droplets, pushes the probe, collects ids for --peers, starts scenarios,
# streams and collects logs, and tears everything down.
#
# Usage: ./ops/harness.sh <command> [args]   (run from anywhere)
#
#   up                 create the droplets in HARNESS_NODES and wait for ssh
#   nodes              list every node the harness knows about
#   build              cross-compile the probe (Linux, glibc) and build it natively (macOS)
#   push               copy the right probe build + run_scenario.sh to every node
#   discover           collect every node's endpoint id, push peers.txt to all
#   scenario <n> [node]  run scenario n (on one node, or all); after the sharing
#                      step of 4/6 the doc ticket is handed to every other node
#   stop [node]        stop the probe (on one node, or all)
#   status             is each node's probe running, and its last log line
#   logs [lines]       follow every node's probe.log, merged and prefixed
#   collect            copy each probe.log into results/<date>/<node>.log
#   down [-y]          delete every droplet with HARNESS_TAG
#
# Nodes are the droplets tagged HARNESS_TAG, plus any lines in
# ops/harness.hosts (for machines that aren't droplets, like home and cell):
#
#   home  local                                   # this laptop, runs in ops/.harness/nodes/home
#   cell  me@localhost -o Port=2222 -J root@<anchor-ip>   # reached through a reverse tunnel
#
# Use `-o Port=N` rather than `-p N` there: the options go to both ssh and scp.
#
# Settings, from the environment or ops/harness.env:
#   HARNESS_TAG     droplet tag, default p2p-sync-poc
#   HARNESS_NODES   name:region pairs, default "anchor-us:nyc3 anchor-asia:sgp1"
#   HARNESS_SIZE    droplet size, default s-1vcpu-1gb
#   HARNESS_IMAGE   droplet image, default ubuntu-24-04-x64
#   HARNESS_KEY     ssh private key; its .pub must be added to DigitalOcean
#                   (doctl compute ssh-key import ...). Default ~/.ssh/id_ed25519
#   HARNESS_SHARER  node that shares the doc in scenarios 4/6, default home
#   HARNESS_NO_DOCTL=1  ignore droplets, use ops/harness.hosts only
#   HARNESS_HOSTS, HARNESS_STATE  other hosts file / state dir (for testing)
set -euo pipefail

OPS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$OPS_DIR/.." && pwd)"
STATE="${HARNESS_STATE:-$OPS_DIR/.harness}"
HOSTS_FILE="${HARNESS_HOSTS:-$OPS_DIR/harness.hosts}"
mkdir -p "$STATE"
# shellcheck disable=SC1091
[ -f "$OPS_DIR/harness.env" ] && . "$OPS_DIR/harness.env"

TAG="${HARNESS_TAG:-p2p-sync-poc}"
NODES_SPEC="${HARNESS_NODES:-anchor-us:nyc3 anchor-asia:sgp1}"
SIZE="${HARNESS_SIZE:-s-1vcpu-1gb}"
IMAGE="${HARNESS_IMAGE:-ubuntu-24-04-x64}"
KEY="${HARNESS_KEY:-$HOME/.ssh/id_ed25519}"
SHARER="${HARNESS_SHARER:-home}"
REMOTE_DIR="exp"
LINUX_TARGET="x86_64-unknown-linux-gnu"
# glibc to link against: 2.31 is Ubuntu 20.04, so the binary runs on it and
# anything newer (the droplets' 24.04 has 2.39).
LINUX_GLIBC="2.31"

# A known_hosts of our own: droplet IPs get reused, and this keeps them out
# of ~/.ssh/known_hosts.
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10
  -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$STATE/known_hosts")
[ -f "$KEY" ] && SSH_OPTS+=(-i "$KEY")

die() { echo "harness: $*" >&2; exit 1; }

# --- node registry -----------------------------------------------------------
# One line per node in $STATE/nodes.txt: "<name> <dest> [ssh options...]".

load_nodes() {
  : > "$STATE/nodes.txt"
  if [ -z "${HARNESS_NO_DOCTL:-}" ]; then
    command -v doctl >/dev/null || die "doctl not found (brew install doctl), or set HARNESS_NO_DOCTL=1"
    doctl compute droplet list --tag-name "$TAG" --format Name,PublicIPv4 --no-header \
      | awk 'NF == 2 { print $1, "root@" $2 }' >> "$STATE/nodes.txt"
  fi
  if [ -f "$HOSTS_FILE" ]; then
    sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$HOSTS_FILE" >> "$STATE/nodes.txt"
  fi
}

node_names() { awk '{ print $1 }' "$STATE/nodes.txt"; }

node_line() {
  awk -v n="$1" '$1 == n { $1 = ""; sub(/^ /, ""); print; exit }' "$STATE/nodes.txt"
}

# Only the one node, or every node when $1 is empty.
selected() {
  if [ -n "${1:-}" ]; then
    [ -n "$(node_line "$1")" ] || die "unknown node '$1' (see: harness nodes)"
    echo "$1"
  else
    node_names
  fi
}

local_dir() { echo "$STATE/nodes/$1"; }

# Run a shell command in the node's experiment directory.
node_run() {
  local name="$1" cmd="$2" line dest
  line="$(node_line "$name")"
  dest="${line%% *}"
  if [ "$dest" = "local" ]; then
    mkdir -p "$(local_dir "$name")"
    (cd "$(local_dir "$name")" && bash -c "$cmd")
  else
    # shellcheck disable=SC2086  # the extra options are meant to be split
    ssh "${SSH_OPTS[@]}" ${line#"$dest"} "$dest" "mkdir -p $REMOTE_DIR && cd $REMOTE_DIR && $cmd"
  fi
}

# Copy a local file to <experiment dir>/<remote name> on the node.
node_put() {
  local name="$1" src="$2" dst="$3" line dest
  line="$(node_line "$name")"
  dest="${line%% *}"
  if [ "$dest" = "local" ]; then
    mkdir -p "$(local_dir "$name")"
    cp "$src" "$(local_dir "$name")/$dst"
  else
    # shellcheck disable=SC2086
    scp -q -C "${SSH_OPTS[@]}" ${line#"$dest"} "$src" "$dest:$REMOTE_DIR/$dst"
  fi
}

# Copy <experiment dir>/<remote name> from the node to a local path.
node_get() {
  local name="$1" src="$2" dst="$3" line dest
  line="$(node_line "$name")"
  dest="${line%% *}"
  if [ "$dest" = "local" ]; then
    cp "$(local_dir "$name")/$src" "$dst"
  else
    # shellcheck disable=SC2086
    scp -q "${SSH_OPTS[@]}" ${line#"$dest"} "$dest:$REMOTE_DIR/$src" "$dst"
  fi
}

# Run "$@" once per node in parallel, prefixing output with the node name,
# and fail if any node failed.
for_each() {
  local nodes="$1"; shift
  local pids="" failed=0 n
  for n in $nodes; do
    ( "$@" "$n" 2>&1 | sed "s/^/[$n] /" ; exit "${PIPESTATUS[0]}" ) &
    pids="$pids $!"
  done
  for p in $pids; do wait "$p" || failed=1; done
  return "$failed"
}

# --- commands ----------------------------------------------------------------

cmd_up() {
  command -v doctl >/dev/null || die "doctl not found (brew install doctl)"
  [ -f "$KEY.pub" ] || die "no public key at $KEY.pub (set HARNESS_KEY)"
  local fp
  fp="$(ssh-keygen -l -E md5 -f "$KEY.pub" | awk '{ print $2 }' | sed 's/^MD5://')"
  doctl compute ssh-key list --format FingerPrint --no-header | grep -qx "$fp" \
    || die "key $KEY.pub isn't on DigitalOcean yet: doctl compute ssh-key import harness --public-key-file $KEY.pub"

  local existing spec name region pids=""
  existing="$(doctl compute droplet list --tag-name "$TAG" --format Name --no-header)"
  for spec in $NODES_SPEC; do
    name="${spec%%:*}"
    region="${spec#*:}"
    if echo "$existing" | grep -qx "$name"; then
      echo "[$name] already exists"
      continue
    fi
    echo "[$name] creating in $region ($SIZE)"
    doctl compute droplet create "$name" --region "$region" --size "$SIZE" \
      --image "$IMAGE" --ssh-keys "$fp" --tag-names "$TAG" --wait \
      --format Name,PublicIPv4 --no-header > /dev/null &
    pids="$pids $!"
  done
  for p in $pids; do wait "$p"; done

  load_nodes
  echo "waiting for ssh on every node"
  for_each "$(node_names)" wait_ssh
  cmd_nodes
}

wait_ssh() {
  local tries=0
  until node_run "$1" true 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -ge 30 ] && { echo "ssh still unreachable"; return 1; }
    sleep 5
  done
  echo "ssh ok"
}

cmd_nodes() {
  load_nodes
  [ -s "$STATE/nodes.txt" ] || { echo "no nodes (harness up, or add ops/harness.hosts)"; return; }
  cat "$STATE/nodes.txt"
}

cmd_build() {
  cd "$REPO_ROOT"
  command -v cargo-zigbuild >/dev/null || die "cargo-zigbuild not found: cargo install cargo-zigbuild (needs zig)"
  cargo zigbuild --release --target "$LINUX_TARGET.$LINUX_GLIBC"
  cargo build --release
}

# Which of our builds fits the node, from its `uname -sm`.
binary_for() {
  case "$1" in
    "Linux x86_64") echo "$REPO_ROOT/target/$LINUX_TARGET/release/probe" ;;
    "Darwin "*)     echo "$REPO_ROOT/target/release/probe" ;;
    *)              echo "" ;;
  esac
}

push_one() {
  local name="$1" platform bin
  platform="$(node_run "$name" 'uname -sm')"
  bin="$(binary_for "$platform")"
  [ -n "$bin" ] || { echo "no build for '$platform'"; return 1; }
  [ -f "$bin" ] || { echo "missing $bin (harness build)"; return 1; }
  # Copy under a temporary name first: a running probe keeps the old file.
  node_put "$name" "$bin" probe.new
  node_put "$name" "$OPS_DIR/run_scenario.sh" run_scenario.sh
  node_run "$name" 'mv -f probe.new probe && chmod +x probe run_scenario.sh'
  echo "pushed probe for $platform"
}

cmd_push() {
  load_nodes
  for_each "$(node_names)" push_one
}

cmd_discover() {
  load_nodes
  local n id
  : > "$STATE/peers.txt"
  for n in $(node_names); do
    id="$(node_run "$n" "./probe --name $n --print-id")"
    echo "$n $id" | tee -a "$STATE/peers.txt"
  done
  for_each "$(node_names)" put_peers
}

put_peers() { node_put "$1" "$STATE/peers.txt" peers.txt; }

scenario_one() {
  node_run "$1" "./run_scenario.sh $SCENARIO $1 ${TARGET:-}"
  echo "scenario $SCENARIO started"
}

cmd_scenario() {
  SCENARIO="${1:?usage: harness scenario <n> [node]}"
  TARGET="${2:-}"
  load_nodes
  for_each "$(selected "$TARGET")" scenario_one

  # After the sharing step of the docs scenarios, hand its ticket to everyone.
  if { [ "$SCENARIO" = 4 ] || [ "$SCENARIO" = 6 ]; } && [ "${TARGET:-$SHARER}" = "$SHARER" ]; then
    echo "waiting for $SHARER's doc ticket"
    local tries=0
    until node_get "$SHARER" probe-data/ticket.txt "$STATE/ticket.txt" 2>/dev/null; do
      tries=$((tries + 1))
      [ "$tries" -ge 120 ] && die "no ticket from $SHARER after 2 min — check: harness logs"
      sleep 1
    done
    local others
    others="$(node_names | grep -vx "$SHARER" || true)"
    [ -n "$others" ] && for_each "$others" put_ticket
  fi
}

put_ticket() { node_put "$1" "$STATE/ticket.txt" ticket.txt; echo "ticket delivered"; }

stop_one() {
  node_run "$1" 'if [ -f probe.pid ] && kill -INT "$(cat probe.pid)" 2>/dev/null; then echo stopping; else echo "not running"; fi'
}

cmd_stop() {
  load_nodes
  for_each "$(selected "${1:-}")" stop_one
}

status_one() {
  node_run "$1" 'if [ -f probe.pid ] && kill -0 "$(cat probe.pid)" 2>/dev/null; then s=running; else s=stopped; fi
    echo "$s | $(tail -n 1 probe.log 2>/dev/null | cut -c1-160)"'
}

cmd_status() {
  load_nodes
  for_each "$(node_names)" status_one
}

# One readable line per JSON log line; anything else passes through as-is.
pretty() {
  if command -v jq >/dev/null; then
    jq --unbuffered -R -r --arg n "$1" '. as $l | (try fromjson catch null) as $j
      | if ($j | type) == "object" then
          "[\($n)] \(($j.ts_ms / 1000 | floor | strftime("%H:%M:%S"))) \($j.kind) \(($j.peer // "")[0:8]) \($j.detail // "")"
        else "[\($n)] \($l)" end'
  else
    sed "s/^/[$1] /"
  fi
}

logs_one() {
  node_run "$1" "touch probe.log && tail -n $LINES -F probe.log" | pretty "$1"
}

cmd_logs() {
  LINES="${1:-20}"
  load_nodes
  trap 'kill 0' INT TERM
  local n
  for n in $(node_names); do logs_one "$n" & done
  wait
}

cmd_collect() {
  load_nodes
  local dir n
  dir="$REPO_ROOT/results/$(date +%Y-%m-%d)"
  mkdir -p "$dir"
  for n in $(node_names); do
    if node_get "$n" probe.log "$dir/$n.log" 2>/dev/null; then
      echo "[$n] -> results/$(basename "$dir")/$n.log"
    else
      echo "[$n] no probe.log"
    fi
  done
}

cmd_down() {
  command -v doctl >/dev/null || die "doctl not found"
  local list
  list="$(doctl compute droplet list --tag-name "$TAG" --format Name,PublicIPv4,Region --no-header)"
  [ -n "$list" ] || { echo "no droplets tagged $TAG"; return; }
  echo "$list"
  if [ "${1:-}" != "-y" ]; then
    printf "delete these droplets? [y/N] "
    read -r answer
    [ "$answer" = "y" ] || { echo "kept"; return; }
  fi
  doctl compute droplet delete --tag-name "$TAG" --force
  echo "deleted"
}

case "${1:-}" in
  up)       cmd_up ;;
  nodes)    cmd_nodes ;;
  build)    cmd_build ;;
  push)     cmd_push ;;
  discover) cmd_discover ;;
  scenario) shift; cmd_scenario "$@" ;;
  stop)     shift; cmd_stop "$@" ;;
  status)   cmd_status ;;
  logs)     shift; cmd_logs "$@" ;;
  collect)  cmd_collect ;;
  down)     shift; cmd_down "$@" ;;
  *)        sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'; exit 1 ;;
esac
