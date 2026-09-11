#!/bin/bash
# Launch Google Cloud Confidential VMs with probe-gcp.sh as the startup script.
# Usage: ./launch.sh snp us-central1-a   |   ./launch.sh tdx europe-west4-a
# Needs: gcloud auth login; gcloud config set project <id>; billing enabled on the project.
set -euo pipefail
cd "$(dirname "$0")"; KIND=$1; ZONE=$2; PROJECT=$(gcloud config get-value project 2>/dev/null)
[ -n "$PROJECT" ] || { echo "set a project first: gcloud config set project <id>"; exit 1; }
gcloud services enable compute.googleapis.com confidentialcomputing.googleapis.com --quiet
SA=$(gcloud iam service-accounts list --format="value(email)" --filter="email~-compute@developer.gserviceaccount.com" | head -1)
[ -n "$SA" ] && gcloud projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:$SA" --role roles/confidentialcomputing.workloadUser --condition=None --quiet > /dev/null
IMAGE_FAMILY=${IMAGE_FAMILY:-ubuntu-2404-lts-amd64}; IMAGE_PROJECT=${IMAGE_PROJECT:-ubuntu-os-cloud}; PROBE=${PROBE:-probe-gcp.sh}; SUFFIX=${SUFFIX:-}
NAME="rats-$KIND-${ZONE}${SUFFIX}"
case "$KIND" in
  snp) EXTRA=(--machine-type n2d-standard-2 --min-cpu-platform "AMD Milan" --confidential-compute-type SEV_SNP);;
  tdx) EXTRA=(--machine-type c3-standard-4 --confidential-compute-type TDX);;
  *) echo "kind must be snp or tdx"; exit 1;;
esac
gcloud compute instances create "$NAME" --zone "$ZONE" "${EXTRA[@]}" --maintenance-policy TERMINATE \
  --image-family "$IMAGE_FAMILY" --image-project "$IMAGE_PROJECT" \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring --scopes cloud-platform \
  --metadata-from-file startup-script="$PROBE" --labels purpose=ietf-rats-geographic-results --quiet \
  --format="value(name,zone.basename(),machineType.basename(),status)"
echo "$KIND $ZONE $NAME $(date -u +%FT%TZ)" | tee -a launched.txt
