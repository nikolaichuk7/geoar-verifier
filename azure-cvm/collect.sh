#!/bin/bash
# Poll the boot-diagnostics serial log of every VM in launched.txt until the probe archive appears,
# decode into runs/<name>/, then delete the VM (and its NIC, IP, disk). Usage: ./collect.sh [max-minutes]
set -uo pipefail
cd "$(dirname "$0")"; MAX=${1:-45}; mkdir -p runs; deadline=$(( $(date +%s) + MAX*60 )); done_list=" "
while :; do
  pending=0
  while read -r KIND LOC NAME RG T0; do
    case "$done_list" in *" $NAME "*) continue;; esac
    az vm boot-diagnostics get-boot-log -g "$RG" -n "$NAME" > "runs/$NAME.console" 2>/dev/null || true
    # fallback after 6 minutes without a serial log (the boot-diagnostics blob is sometimes never created):
    # open port 22 to this machine only, read the archive over SSH as root, close the port again
    if ! grep -q "===PROBE-END===" "runs/$NAME.console" && [ -n "${SSH_KEY:-}" ] && [ $(( $(date +%s) - $(date -j -f %FT%TZ "$T0" +%s 2>/dev/null || date -d "$T0" +%s) )) -gt 360 ]; then
      IP=$(az vm show -d -g "$RG" -n "$NAME" --query publicIps -o tsv 2>/dev/null); MYIP=$(curl -s https://api.ipify.org)
      az network nsg rule create -g "$RG" --nsg-name "${NAME}NSG" -n probe-ssh --priority 100 --source-address-prefixes "$MYIP/32" --destination-port-ranges 22 --access Allow --protocol Tcp --output none 2>/dev/null
      B64=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 probe@"$IP" 'sudo bash -c "cat /root/probe/*.b64 2>/dev/null"' 2>/dev/null | tr -d '\r\n')
      if [ ${#B64} -gt 1000 ]; then printf '===PROBE-BEGIN=== ssh\n%s\n===PROBE-END===\n' "$B64" > "runs/$NAME.console"; echo "$(date -u +%T) $NAME: archive read over SSH (${#B64} chars)"; fi
      az network nsg rule delete -g "$RG" --nsg-name "${NAME}NSG" -n probe-ssh --output none 2>/dev/null
    fi
    if grep -q "===PROBE-END===" "runs/$NAME.console"; then
      mkdir -p "runs/$NAME"
      # the CLI returns the serial log as one JSON string (escaped newlines, NULs): decode it first, then cut the first BEGIN..END range
      python3 - "runs/$NAME.console" "runs/$NAME/probe.tgz" <<'PY' && tar xzf "runs/$NAME/probe.tgz" -C "runs/$NAME" && echo "$(date -u +%T) $NAME: archive decoded -> runs/$NAME/$(ls runs/$NAME | grep -v tgz)"
import json, re, base64, sys
raw = open(sys.argv[1], errors="replace").read()
try: s = json.loads(raw)
except Exception: s = raw
i = s.find("===PROBE-BEGIN==="); j = s.find("===PROBE-END===", i); body = s[s.find("\n", i) + 1:j]
body = re.sub(r"[^A-Za-z0-9+/=]", "", re.sub(r"\[\d{4}-\d{2}-\d{2}T[\d:.]+\]", "", body))
open(sys.argv[2], "wb").write(base64.b64decode(body + "=" * (-len(body) % 4)))
PY
      az vm delete -g "$RG" -n "$NAME" --yes --force-deletion yes --output none 2>/dev/null && echo "$(date -u +%T) $NAME deleted"
      done_list="$done_list$NAME "
    else
      st=$(az vm get-instance-view -g "$RG" -n "$NAME" --query "instanceView.statuses[?starts_with(code,'PowerState')].displayStatus | [0]" -o tsv 2>/dev/null || echo GONE)
      case "$st" in "VM stopped"|"VM deallocated"|GONE) echo "$(date -u +%T) $NAME: $st without archive; console kept"; done_list="$done_list$NAME ";;
        *) pending=$((pending+1)); echo "$(date -u +%T) $NAME: $st, waiting ($(grep -c . "runs/$NAME.console" 2>/dev/null || echo 0) console lines)";; esac
    fi
  done < launched.txt
  [ "$pending" -eq 0 ] && break
  [ "$(date +%s)" -gt "$deadline" ] && { echo "timeout after $MAX min; pending: $pending"; break; }
  sleep 60
done
echo "collect finished $(date -u +%FT%TZ)"
