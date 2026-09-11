#!/bin/bash
# Poll the serial console of every VM in launched.txt until the probe archive appears, decode it
# into runs/<name>/, then delete the VM (KEEP=1 keeps it). bash 3.2 compatible. Usage: [KEEP=1] ./collect.sh [max-minutes] [name-filter]
set -uo pipefail
cd "$(dirname "$0")"; MAX=${1:-40}; mkdir -p runs; deadline=$(( $(date +%s) + MAX*60 )); done_list=" "
while :; do
  pending=0
  while read -r KIND ZONE NAME T0; do
    case "$done_list" in *" $NAME "*) continue;; esac
    [ -n "${2:-}" ] && case "$NAME" in *"$2"*) ;; *) continue;; esac
    gcloud compute instances get-serial-port-output "$NAME" --zone "$ZONE" --port 1 > "runs/$NAME.console" 2>/dev/null || true
    if grep -q "===PROBE-END===" "runs/$NAME.console"; then
      # reassemble by line index across the three copies and verify the SHA-256 (tools/decode_console.py);
      # the VM is deleted only after a verified extraction, never on a failed decode (dual1/dual2 were lost that way on 11 Sep)
      if python3 ../tools/decode_console.py "runs/$NAME.console" "runs/$NAME"; then
        echo "$(date -u +%T) $NAME: archive verified -> runs/$NAME/$(ls runs/$NAME | grep -v tgz)"
        if [ "${KEEP:-0}" = 1 ]; then echo "$(date -u +%T) $NAME kept (KEEP=1)"; else gcloud compute instances delete "$NAME" --zone "$ZONE" --quiet > /dev/null 2>&1 && echo "$(date -u +%T) $NAME deleted"; fi
        done_list="$done_list$NAME "
      else pending=$((pending+1)); echo "$(date -u +%T) $NAME: END marker seen but payload not yet complete; keeping the VM and re-reading"; fi
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
