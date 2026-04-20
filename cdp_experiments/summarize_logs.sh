#!/usr/bin/env bash
# Summarise CDP metrics for every *.bin.log in the passed Logs dir.
# Usage: ./summarize_logs.sh [logs_dir]
set -u
logs_dir="${1:-builds/RV64ACDFIMSU_Toooba_bluesim/Logs}"
printf '%-14s %10s %10s %8s %8s %8s %7s %10s %10s %10s %10s %10s\n' \
  bench cycles instret IPC issued useful acc% decisions noHighConf filterHit uselessEvict punishes
for f in "$logs_dir"/*.bin.log; do
  bn=$(basename "$f" .bin.log)
  pair=$(tac "$f" | grep -m 1 instret | sed -E 's/^instret:([0-9]+).*  +([0-9]+)$/\2 \1/')
  cycles=$(echo "$pair" | awk '{print $1}')
  instret=$(echo "$pair" | awk '{print $2}')
  ipc=$(awk "BEGIN { if($cycles>0) printf \"%.3f\", $instret/$cycles; else print \"-\" }")
  useful=$(grep -c "CDP Rel useful prefetch hit" "$f")
  issued=$(grep -c "CDP Rel filter MISS" "$f")
  fhit=$(grep -c "CDP Rel filter HIT" "$f")
  dec=$(grep -c "CDP Rel prefetch decision" "$f")
  nhc=$(grep -c "CDP Rel no high-conf" "$f")
  ue=$(grep -c "AlexLog: L1 evicted PREFETCHED line" "$f")
  pn=$(grep -c "CDP Rel PC table punish" "$f")
  acc=$(awk "BEGIN { if($issued>0) printf \"%.1f\", 100*$useful/$issued; else print \"-\" }")
  printf '%-14s %10s %10s %8s %8s %8s %7s %10s %10s %10s %10s %10s\n' \
    "$bn" "$cycles" "$instret" "$ipc" "$issued" "$useful" "$acc" "$dec" "$nhc" "$fhit" "$ue" "$pn"
done
