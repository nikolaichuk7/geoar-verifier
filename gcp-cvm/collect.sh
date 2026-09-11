#!/bin/bash
# Poll the serial console of every VM in launched.txt until the probe archive appears, decode it
# into runs/<name>/, then delete the VM. bash 3.2 compatible. Usage: ./collect.sh [max-minutes]
set -uo pipefail
cd "$(dirname "$0")"; MAX=${1:-40}; mkdir -p runs; deadline=$(( $(date +%s) + MAX*60 )); done_list=" "
while :; do
  pending=0
  while read -r KIND ZONE NAME T0; do
    case "$done_list" in *" $NAME "*) continue;; esac
    gcloud compute instances get-serial-port-output "$NAME" --zone "$ZONE" --port 1 > "runs/$NAME.console" 2>/dev/null || true
    if grep -q "===PROBE-END===" "runs/$NAME.console"; then
      mkdir -p "runs/$NAME"
      awk '/===PROBE-BEGIN===/{f=1;next} /===PROBE-END===/{if(f)exit} f' "runs/$NAME.console" | tr -d '\r\n' | sed -E 's/\[[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+\]//g' | tr -cd 'A-Za-z0-9+/=' | base64 -d > "runs/$NAME/probe.tgz" \
        && tar xzf "runs/$NAME/probe.tgz" -C "runs/$NAME" && echo "$(date -u +%T) $NAME: archive decoded -> runs/$NAME/$(ls runs/$NAME | grep -v tgz)"
      gcloud compute instances delete "$NAME" --zone "$ZONE" --quiet > /dev/null 2>&1 && echo "$(date -u +%T) $NAME deleted"
      done_list="$done_list$NAME "
    else
      st=$(gcloud compute instances describe "$NAME" --zone "$ZONE" --format="value(status)" 2>/dev/null || echo GONE)
      if [ "$st" = "TERMINATED" ] || [ "$st" = "GONE" ]; then echo "$(date -u +%T) $NAME: $st without archive; console kept"; done_list="$done_list$NAME "; else pending=$((pending+1)); echo "$(date -u +%T) $NAME: $st, waiting ($(grep -c . "runs/$NAME.console" 2>/dev/null || echo 0) console lines)"; fi
    fi
  done < launched.txt
  [ "$pending" -eq 0 ] && break
  [ "$(date +%s)" -gt "$deadline" ] && { echo "timeout after $MAX min; pending: $pending"; break; }
  sleep 45
done
echo "collect finished $(date -u +%FT%TZ)"
