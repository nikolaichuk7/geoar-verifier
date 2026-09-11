#!/bin/bash
# Second NitroTPM run: launch the TPM-enabled AMI again and, while the instance runs, ask the EC2 control
# plane for the instance's EK public key (GetInstanceTpmEkPub) so that it can be compared with the EK the
# guest derives inside (tpm2_createek). The probe archive is collected as usual; the instance is terminated
# by the collector after a verified extraction. Usage: ./nitrotpm-ekpub.sh
set -uo pipefail; export AWS_PAGER=""; R=us-east-2; AZ=us-east-2a; cd "$(dirname "$0")"
AMI=$(cut -d' ' -f1 nitrotpm-ami.txt); SUB=$(aws ec2 describe-subnets --region $R --filters Name=availability-zone,Values=$AZ Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)
ID=$(aws ec2 run-instances --region $R --image-id "$AMI" --instance-type m6a.xlarge --subnet-id "$SUB" --count 1 --user-data file://probe-nitrotpm.sh \
     --metadata-options HttpTokens=required,HttpEndpoint=enabled --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=rats-nitrotpm-$AZ-2},{Key=purpose,Value=ietf-rats-geographic-results}]" \
     --query 'Instances[0].InstanceId' --output text)
echo "$R $AZ $ID $AMI m6a.xlarge $(date -u +%FT%TZ)" | tee -a launched.txt; mkdir -p "runs/$ID"
for i in $(seq 1 30); do
  for KT in rsa-2048 ecc-sec-p384; do
    [ -s "runs/$ID/ekpub-$KT.der" ] && continue
    aws ec2 get-instance-tpm-ek-pub --region $R --instance-id "$ID" --key-type "$KT" --key-format der --output json > "runs/$ID/ekpub-$KT.json" 2> "runs/$ID/ekpub-$KT.err" \
      && python3 -c "import json,base64,sys; d=json.load(open('runs/$ID/ekpub-$KT.json')); open('runs/$ID/ekpub-$KT.der','wb').write(base64.b64decode(d['KeyValue'])); print('$KT', d.get('KeyType'), d.get('KeyFormat'), len(base64.b64decode(d['KeyValue'])), 'bytes')" \
      || { echo "$(date -u +%T) $KT not yet: $(tail -c 160 runs/$ID/ekpub-$KT.err | tr '\n' ' ')"; }
  done
  [ -s "runs/$ID/ekpub-rsa-2048.der" ] && [ -s "runs/$ID/ekpub-ecc-sec-p384.der" ] && break; sleep 20
done
./collect.sh 25
