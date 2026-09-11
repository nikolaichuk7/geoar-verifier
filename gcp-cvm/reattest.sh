#!/bin/bash
# Protocol 2 orchestration: wait for the first boot's archive from the re-attestation VM, stop and start
# the VM, wait for the second boot's archive, then delete the VM. Nothing is deleted before both archives
# have been reassembled and SHA-256-verified. Usage: ./reattest.sh <vm-name> <zone>
set -u
cd "$(dirname "$0")"; NAME=$1; ZONE=$2; mkdir -p runs
wait_archives() {  # $1 = number of verified boot archives expected, $2 = console capture file
  for i in $(seq 1 40); do
    gcloud compute instances get-serial-port-output "$NAME" --zone "$ZONE" --port 1 > "$2" 2>/dev/null || true
    if grep -q "PROBE DONE" "$2"; then
      python3 ../tools/decode_console.py "$2" "runs/$NAME" > /dev/null 2>&1
      n=$(ls -d "runs/$NAME"/2026* 2>/dev/null | wc -l | tr -d ' ')
      [ "$n" -ge "$1" ] && { echo "$(date -u +%T) $n boot archive(s) verified"; return 0; }
    fi
    echo "$(date -u +%T) waiting for boot archive $1 ($(grep -c . "$2" 2>/dev/null || echo 0) console lines)"; sleep 30
  done; return 1
}
wait_archives 1 "runs/$NAME.console" || { echo "first archive missing; VM kept"; exit 1; }
echo "$(date -u +%T) stopping"; gcloud compute instances stop "$NAME" --zone "$ZONE" --quiet > /dev/null 2>&1; echo "$(date -u +%T) stopped: $(gcloud compute instances describe "$NAME" --zone "$ZONE" --format='value(status)')"
echo "$(date -u +%T) starting"; gcloud compute instances start "$NAME" --zone "$ZONE" --quiet > /dev/null 2>&1; echo "$(date -u +%T) started: $(gcloud compute instances describe "$NAME" --zone "$ZONE" --format='value(status)')"
wait_archives 2 "runs/$NAME.console2" || { echo "second archive missing; VM kept"; exit 1; }
gcloud compute instances delete "$NAME" --zone "$ZONE" --quiet > /dev/null 2>&1 && echo "$(date -u +%T) $NAME deleted"
for d in "runs/$NAME"/2026*; do echo "== $d"; python3 -c "
import json,sys; s=json.load(open('$d/reattest-samples.json')); m=dict(l.split('=',1) for l in open('$d/metadata.txt').read().split() if '=' in l)
print('  boot-id', m.get('boot-id'), 'gce-instance-id', m.get('gce-instance-id'))
print('  samples ok:', sum(1 for x in s if x['ok']), '/', len(s), '| distinct chip_id:', len({x['chip_id'] for x in s if x['ok']}), '| distinct report_id:', len({x['report_id'] for x in s if x['ok']}), '| nonce ok:', all(x.get('report_data_is_nonce') for x in s if x['ok']))
print('  chip_id', s[0].get('chip_id','')[:16], 'report_id', s[0].get('report_id','')[:16], 'tcb', s[0].get('reported_tcb'), 'measurement', s[0].get('measurement','')[:16], 'first', s[0]['time'], 'last', s[-1]['time'])
"; done
