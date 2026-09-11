#!/bin/bash
# Launch one enclave-enabled instance per availability zone with probe-nitro.sh as user-data.
# Usage: ./launch.sh us-east-2a eu-west-1a   (TYPE default m5.xlarge: 4 vCPU, enclaves supported)
set -euo pipefail
cd "$(dirname "$0")"; export AWS_PAGER=""; TYPE=${TYPE:-m5.xlarge}; SUFFIX=${SUFFIX:-}
for AZ in "$@"; do
  R=${AZ%?}
  AMI=$(aws ssm get-parameter --region "$R" --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64 --query Parameter.Value --output text)
  SUB=$(aws ec2 describe-subnets --region "$R" --filters Name=availability-zone,Values="$AZ" Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)
  ID=$(aws ec2 run-instances --region "$R" --image-id "$AMI" --instance-type "$TYPE" --subnet-id "$SUB" --count 1 \
        --enclave-options Enabled=true --user-data file://probe-nitro.sh --metadata-options HttpTokens=required,HttpEndpoint=enabled \
        --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=16,VolumeType=gp3}' \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=rats-nitro-$AZ$SUFFIX},{Key=purpose,Value=ietf-rats-geographic-results}]" \
        --query 'Instances[0].InstanceId' --output text)
  echo "$R $AZ $ID $AMI $TYPE $(date -u +%FT%TZ)" | tee -a launched.txt
done
