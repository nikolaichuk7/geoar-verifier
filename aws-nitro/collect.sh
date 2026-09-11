#!/bin/bash
# Poll the serial console of every instance in launched.txt (round-robin) until the probe
# archive appears, decode it into runs/<instance>/ (verified by SHA-256), then terminate that instance.
# Works with bash 3.2 (macOS). Usage: ./collect.sh [max-minutes]
set -uo pipefail
cd "$(dirname "$0")"; export AWS_PAGER=""; MAX=${1:-40}; mkdir -p runs
deadline=$(( $(date +%s) + MAX*60 )); done_list=" "
while :; do
  pending=0
  while read -r R AZ ID AMI TYPE T0; do
    case "$done_list" in *" $ID "*) continue;; esac
    state=$(aws ec2 describe-instances --region "$R" --instance-ids "$ID" --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo unknown)
    aws ec2 get-console-output --region "$R" --instance-id "$ID" --latest --output text --query Output > "runs/$ID.console" 2>/dev/null || true
    if grep -q "===PROBE-END===" "runs/$ID.console"; then
      # reassemble by line index across the three copies and verify the SHA-256 (tools/decode_console.py);
      # the instance is terminated only after a verified extraction, never on a failed decode
      if python3 ../tools/decode_console.py "runs/$ID.console" "runs/$ID"; then
        echo "$(date -u +%T) $ID ($AZ): archive verified -> runs/$ID/$(ls runs/$ID | grep -v tgz)"
        echo "$(date -u +%T) $ID terminate: $(aws ec2 terminate-instances --region "$R" --instance-ids "$ID" --query 'TerminatingInstances[0].CurrentState.Name' --output text)"
        done_list="$done_list$ID "
      else
        pending=$((pending+1)); echo "$(date -u +%T) $ID ($AZ): END marker seen but payload not yet complete; keeping the instance and re-reading"
      fi
    elif [ "$state" = "stopped" ] || [ "$state" = "terminated" ] || [ "$state" = "shutting-down" ]; then
      echo "$(date -u +%T) $ID ($AZ): instance is $state without a probe archive; console kept in runs/$ID.console"; done_list="$done_list$ID "
    else
      pending=$((pending+1)); echo "$(date -u +%T) $ID ($AZ): $state, waiting ($(grep -c . "runs/$ID.console" 2>/dev/null || echo 0) console lines)"
    fi
  done < launched.txt
  [ "$pending" -eq 0 ] && break
  if [ "$(date +%s)" -gt "$deadline" ]; then echo "timeout after $MAX min; still pending: $pending"; break; fi
  sleep 45
done
echo "collect finished $(date -u +%FT%TZ)"
