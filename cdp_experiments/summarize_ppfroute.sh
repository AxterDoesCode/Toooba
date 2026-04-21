#!/usr/bin/env bash
# Variant N (PPFRoute) metrics: per-benchmark issued, L1 vs LLC routing,
# useful/useless attribution, and cycles/instret.
set -u
logs_dir="${1:-builds/RV64ACDFIMSU_Toooba_bluesim/Logs}"
printf '%-10s %10s %10s %8s %8s %8s %8s %8s %8s %8s\n' \
  bench cycles instret IPC issued routeL1 routeLLC useful useless uselessEv
for f in "$logs_dir"/*.bin.log; do
  bn=$(basename "$f" .bin.log)
  pair=$(tac "$f" | grep -m 1 instret | sed -E 's/^instret:([0-9]+).*  +([0-9]+)$/\2 \1/')
  cycles=$(echo "$pair" | awk '{print $1}')
  instret=$(echo "$pair" | awk '{print $2}')
  ipc=$(awk "BEGIN { if($cycles>0) printf \"%.3f\", $instret/$cycles; else print \"-\" }")
  issued=$(grep -c "CDP PPFRoute filter MISS" "$f")
  routeL1=$(grep -c "CDP PPFRoute prefetch decision:.*route L1" "$f")
  routeLLC=$(grep -c "CDP PPFRoute prefetch decision:.*route LLC" "$f")
  useful=$(grep -c "CDP PPFRoute useful bump" "$f")
  useless=$(grep -c "CDP PPFRoute useless bump" "$f")
  ue=$(grep -c "AlexLog: L1 evicted PREFETCHED line" "$f")
  printf '%-10s %10s %10s %8s %8s %8s %8s %8s %8s %8s\n' \
    "$bn" "$cycles" "$instret" "$ipc" "$issued" "$routeL1" "$routeLLC" "$useful" "$useless" "$ue"
done
