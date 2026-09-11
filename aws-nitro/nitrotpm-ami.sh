#!/bin/bash
# Register a copy of the current AL2023 AMI with TpmSupport=v2.0 (no public AL2023 or Ubuntu AMI in
# us-east-2 carries it), then launch one m6a.xlarge with probe-nitrotpm.sh. Prints the new AMI id.
set -euo pipefail; export AWS_PAGER=""; R=us-east-2; AZ=us-east-2a
cd "$(dirname "$0")"
SRC=$(aws ssm get-parameter --region $R --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64 --query Parameter.Value --output text)
SNAP=$(aws ec2 describe-images --region $R --image-ids "$SRC" --query 'Images[0].BlockDeviceMappings[0].Ebs.SnapshotId' --output text)
echo "source AMI $SRC snapshot $SNAP"
CP=$(aws ec2 copy-snapshot --region $R --source-region $R --source-snapshot-id "$SNAP" --description "AL2023 root for NitroTPM probe" --query SnapshotId --output text)
echo "copy $CP"; until [ "$(aws ec2 describe-snapshots --region $R --snapshot-ids "$CP" --query 'Snapshots[0].State' --output text)" = completed ]; do sleep 15; done
AMI=$(aws ec2 register-image --region $R --name "al2023-6.1-nitrotpm-$(date -u +%Y%m%d%H%M)" --architecture x86_64 --virtualization-type hvm --ena-support \
      --root-device-name /dev/xvda --boot-mode uefi --tpm-support v2.0 --imds-support v2.0 \
      --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=$CP,VolumeType=gp3,DeleteOnTermination=true}" --query ImageId --output text)
echo "AMI $AMI TpmSupport=$(aws ec2 describe-images --region $R --image-ids $AMI --query 'Images[0].TpmSupport' --output text)"
SUB=$(aws ec2 describe-subnets --region $R --filters Name=availability-zone,Values=$AZ Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)
ID=$(aws ec2 run-instances --region $R --image-id "$AMI" --instance-type m6a.xlarge --subnet-id "$SUB" --count 1 --user-data file://probe-nitrotpm.sh \
     --metadata-options HttpTokens=required,HttpEndpoint=enabled --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=rats-nitrotpm-$AZ},{Key=purpose,Value=ietf-rats-geographic-results}]" \
     --query 'Instances[0].InstanceId' --output text)
echo "$R $AZ $ID $AMI m6a.xlarge $(date -u +%FT%TZ)" | tee -a launched.txt
echo "$AMI $CP" > nitrotpm-ami.txt
