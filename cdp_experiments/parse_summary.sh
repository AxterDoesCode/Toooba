#!/usr/bin/env bash
# Summarise CDP metrics using TooobaLogParser's full Python pipeline (parselogNew).
# Produces one row per benchmark + per-conf useful breakdown from the Direct path.
# Usage: ./parse_summary.sh [logs_dir]
set -u
logs_dir="${1:-builds/RV64ACDFIMSU_Toooba_bluesim/Logs}"
parser_main=/auto/homes/ac2822/Documents/Code/Toooba/TooobaLogParser/main.py
py=${CDP_PY:-/tmp/cdp_parse_venv/bin/python3}

printf '%-14s %10s %10s %8s %8s %8s %6s %10s %12s %10s\n' \
  bench cycles instret IPC issued usefulRaw acc% uselessEvict unattribDir filterHit
for f in "$logs_dir"/*.bin.log; do
  bn=$(basename "$f" .bin.log)
  pair=$(tac "$f" | grep -m 1 instret | sed -E 's/^instret:([0-9]+).*  +([0-9]+)$/\2 \1/')
  cycles=$(echo "$pair" | awk '{print $1}')
  instret=$(echo "$pair" | awk '{print $2}')
  ipc=$(awk "BEGIN { if($cycles>0) printf \"%.3f\", $instret/$cycles; else print \"-\" }")
  stats=$($py "$parser_main" "$f" 2>/dev/null)
  useful=$(echo "$stats" | awk '/^\tusefulPrefetches: /{print $2}' | head -1)
  issued=$(echo "$stats" | awk '/^\tfilterPrefetchesIssued: /{print $2}' | head -1)
  fhit=$(echo "$stats" | awk '/^\tfilterDuplicatesDropped: /{print $2}' | head -1)
  unat=$(echo "$stats" | awk '/^\tusefulPrefetchesUnattributed_Direct: /{print $2}' | head -1)
  ue=$(grep -c "AlexLog: L1 evicted PREFETCHED line" "$f")
  acc=$(awk "BEGIN { if(${issued:-0}>0) printf \"%.1f\", 100*${useful:-0}/${issued:-0}; else print \"-\" }")
  printf '%-14s %10s %10s %8s %8s %8s %6s %10s %12s %10s\n' \
    "$bn" "$cycles" "$instret" "$ipc" "${issued:-0}" "${useful:-0}" "$acc" "$ue" "${unat:-0}" "${fhit:-0}"
done
echo
echo "--- per-conf useful (Direct) / useless (via linking) ---"
for f in "$logs_dir"/*.bin.log; do
  bn=$(basename "$f" .bin.log)
  stats=$($py "$parser_main" "$f" 2>/dev/null)
  printf '%-14s' "$bn"
  for conf in 1 2 3 4 5 6 7; do
    u=$(echo "$stats" | awk -v c="$conf" '$0 ~ "usefulPrefetchesAtConf"c"_Direct: " {print $2}' | head -1)
    l=$(echo "$stats" | awk -v c="$conf" '$0 ~ "cdpUselessAtConf"c": " {print $2}' | head -1)
    printf ' c%d:%d/%d' "$conf" "${u:-0}" "${l:-0}"
  done
  echo
done
