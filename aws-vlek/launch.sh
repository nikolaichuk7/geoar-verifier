#!/bin/bash
# Launch SEV-SNP probe instances on AWS with a probe script as user-data. No key pair, no
# security-group rule, no IAM role: the instance talks out only and reports back through the
# serial console. Usage: ./launch.sh us-east-2a eu-west-1a
# Env: AMI_PARAM (default kernel-6.1 image; kernel-default 6.18 shut itself down under SEV-SNP on
#      2026-09-11), USERDATA (probe.sh | probe-keysel.sh | probe-dual.sh | none), TYPE, COUNT,
#      HOST_ID=h-... to place onto a Dedicated Host (VCEK-signed there), SUFFIX for the Name tag.
set -euo pipefail
cd "$(dirname "$0")"; export AWS_PAGER=""
TYPE=${TYPE:-m6a.large}; COUNT=${COUNT:-1}; SUFFIX=${SUFFIX:-}
AMI_PARAM=${AMI_PARAM:-al2023-ami-kernel-6.1-x86_64}
USERDATA=${USERDATA:-probe.sh}
UD=(); [ "$USERDATA" != "none" ] && UD=(--user-data "file://$USERDATA")
PL=(); [ -n "${HOST_ID:-}" ] && PL=(--placement "Tenancy=host,HostId=$HOST_ID")
for AZ in "$@"; do
  R=${AZ%?}
  AMI=$(aws ssm get-parameter --region "$R" --name "/aws/service/ami-amazon-linux-latest/$AMI_PARAM" --query Parameter.Value --output text)
  SUB=$(aws ec2 describe-subnets --region "$R" --filters Name=availability-zone,Values="$AZ" Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)
  IDS=$(aws ec2 run-instances --region "$R" --image-id "$AMI" --instance-type "$TYPE" --subnet-id "$SUB" --count "$COUNT" \
        --cpu-options AmdSevSnp=enabled ${UD[@]+"${UD[@]}"} ${PL[@]+"${PL[@]}"} \
        --metadata-options HttpTokens=required,HttpEndpoint=enabled \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=rats-probe-$AZ$SUFFIX},{Key=purpose,Value=ietf-rats-geographic-results}]" \
        --query 'Instances[].InstanceId' --output text)
  for ID in $IDS; do echo "$R $AZ $ID $AMI $TYPE $(date -u +%FT%TZ)" | tee -a launched.txt; done
done
