#!/bin/bash
# Launch one SEV-SNP (shared tenancy → VLEK-signed) probe instance per requested placement,
# with probe.sh as user-data. No key pair, no security-group rule, no IAM role: the instance
# talks out only (AMD KDS, GitHub, dnf mirrors) and reports back through the serial console.
# Usage: ./launch.sh us-east-2a us-east-2b eu-west-1a      (AZ names; region is derived)
set -euo pipefail
cd "$(dirname "$0")"; export AWS_PAGER=""
TYPE=${TYPE:-m6a.large}
AMI_PARAM=${AMI_PARAM:-al2023-ami-kernel-6.1-x86_64}   # kernel-default (6.18) shut itself down at boot under SEV-SNP on 2026-09-11
USERDATA=${USERDATA:-probe.sh}                          # USERDATA=none launches a control instance without the probe
UD=(); [ "$USERDATA" != "none" ] && UD=(--user-data "file://$USERDATA")
for AZ in "$@"; do
  R=${AZ%?}
  AMI=$(aws ssm get-parameter --region "$R" --name "/aws/service/ami-amazon-linux-latest/$AMI_PARAM" --query Parameter.Value --output text)
  SUB=$(aws ec2 describe-subnets --region "$R" --filters Name=availability-zone,Values="$AZ" Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)
  ID=$(aws ec2 run-instances --region "$R" --image-id "$AMI" --instance-type "$TYPE" --subnet-id "$SUB" \
        --cpu-options AmdSevSnp=enabled ${UD[@]+"${UD[@]}"} \
        --metadata-options HttpTokens=required,HttpEndpoint=enabled \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=rats-vlek-probe-$AZ},{Key=purpose,Value=ietf-rats-geographic-results}]" \
        --query 'Instances[0].InstanceId' --output text)
  echo "$R $AZ $ID $AMI $TYPE $(date -u +%FT%TZ)" | tee -a launched.txt
done
