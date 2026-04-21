#!/usr/bin/env bash
# Bit-match-only (CDP Naive) per-benchmark metrics.
set -u
logs_dir="${1:-builds/RV64ACDFIMSU_Toooba_bluesim/Logs}"
printf '%-10s %10s %10s %8s %10s %10s %10s %10s\n' \
  bench cycles instret IPC candidates tlbReqs issued uselessEv
for f in "$logs_dir"/*.bin.log; do
  bn=$(basename "$f" .bin.log)
  pair=$(tac "$f" | grep -m 1 instret | sed -E 's/^instret:([0-9]+).*  +([0-9]+)$/\2 \1/')
  cycles=$(echo "$pair" | awk '{print $1}')
  instret=$(echo "$pair" | awk '{print $2}')
  ipc=$(awk "BEGIN { if($cycles>0) printf \"%.3f\", $instret/$cycles; else print \"-\" }")
  candidates=$(grep -c "CDP Naive candidate vaddr" "$f")
  tlbreqs=$(grep -c "CDP Naive TLB req sent" "$f")
  issued=$(grep -c "CDP Naive Prefetch addr issued" "$f")
  ue=$(grep -c "AlexLog: L1 evicted PREFETCHED line" "$f")
  printf '%-10s %10s %10s %8s %10s %10s %10s %10s\n' \
    "$bn" "$cycles" "$instret" "$ipc" "$candidates" "$tlbreqs" "$issued" "$ue"
done
