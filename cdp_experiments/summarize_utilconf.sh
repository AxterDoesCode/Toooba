#!/usr/bin/env bash
# Variant O (UtilConf) telemetry: cycles, issued, attribution bumps, per-PC conf dynamics.
set -u
logs_dir="${1:-builds/RV64ACDFIMSU_Toooba_bluesim/Logs}"
printf '%-10s %10s %10s %8s %8s %8s %8s %8s %8s %8s\n' \
  bench cycles instret IPC issued useful useless usefulBmp uselessBmp uselessEv
for f in "$logs_dir"/*.bin.log; do
  bn=$(basename "$f" .bin.log)
  pair=$(tac "$f" | grep -m 1 instret | sed -E 's/^instret:([0-9]+).*  +([0-9]+)$/\2 \1/')
  cycles=$(echo "$pair" | awk '{print $1}')
  instret=$(echo "$pair" | awk '{print $2}')
  ipc=$(awk "BEGIN { if($cycles>0) printf \"%.3f\", $instret/$cycles; else print \"-\" }")
  issued=$(grep -c "CDP UtilConf filter MISS" "$f")
  useful=$(grep -c "CDP UtilConf useful attrib" "$f")
  useless=$(grep -c "CDP UtilConf useless attrib" "$f")
  ubump=$(grep -c "CDP UtilConf useful bump" "$f")
  ubad=$(grep -c "CDP UtilConf useless bump" "$f")
  ue=$(grep -c "AlexLog: L1 evicted PREFETCHED line" "$f")
  printf '%-10s %10s %10s %8s %8s %8s %8s %8s %8s %8s\n' \
    "$bn" "$cycles" "$instret" "$ipc" "$issued" "$useful" "$useless" "$ubump" "$ubad" "$ue"
done
