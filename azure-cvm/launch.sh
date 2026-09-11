#!/bin/bash
# Launch Azure Confidential VMs with probe-azure.sh as cloud-init custom-data.
# Usage: ./launch.sh snp eastus   |   ./launch.sh tdx eastus2
# Needs: az login (subscription with quota for DCasv5 / DCesv5 in the region).
set -euo pipefail
cd "$(dirname "$0")"; KIND=$1; LOC=$2; RG=${RG:-rats-probe}
case "$KIND" in
  snp) SIZE=Standard_DC2as_v5;;
  tdx) SIZE=Standard_DC2es_v5;;
  *) echo "kind must be snp or tdx"; exit 1;;
esac
IMAGE=${IMAGE:-Canonical:ubuntu-24_04-lts:cvm:latest}
NAME="rats-$KIND-$LOC${SUFFIX:-}"
az group create -n "$RG" -l "$LOC" --output none 2>/dev/null || true
az vm create -g "$RG" -n "$NAME" -l "$LOC" --size "$SIZE" --image "$IMAGE" \
  --security-type ConfidentialVM --os-disk-security-encryption-type VMGuestStateOnly --enable-vtpm true --enable-secure-boot true \
  --admin-username probe --ssh-key-values "${SSH_PUBKEY:-$HOME/.ssh/id_ed25519.pub}" --nsg-rule NONE --public-ip-sku Standard \
  --custom-data probe-azure.sh --tags purpose=ietf-rats-geographic-results --output tsv --query '[name,location,powerState]'
az vm boot-diagnostics enable -g "$RG" -n "$NAME" --output none 2>/dev/null || true
echo "$KIND $LOC $NAME $RG $(date -u +%FT%TZ)" | tee -a launched.txt
