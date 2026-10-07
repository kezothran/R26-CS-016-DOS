#!/usr/bin/env bash
# Provisions one EC2 instance for Sentrix: security group (SSH + 8000 + 3000), key pair, an
# Ubuntu 22.04 t3.medium (4GB RAM - needed for TensorFlow/XGBoost; the free-tier t2/t3.micro's
# 1GB is not enough), and an Elastic IP so the address survives a stop/start.
#
# Run after `aws configure` has been set up (see soc-platform/CLOUD_DEPLOY.md). Idempotent-ish:
# safe to re-run, it reuses an existing security group/key pair by name instead of erroring.
set -euo pipefail

REGION="${AWS_REGION:-ap-south-1}"
NAME="sentrix"
INSTANCE_TYPE="t3.medium"
KEY_NAME="${NAME}-key"
SG_NAME="${NAME}-sg"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "== Region: $REGION | Instance type: $INSTANCE_TYPE =="

echo "== Finding the latest Ubuntu 22.04 AMI =="
AMI_ID=$(aws ec2 describe-images --region "$REGION" --owners 099720109477 \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" "Name=state,Values=available" \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)
echo "   AMI: $AMI_ID"

echo "== Key pair =="
if ! aws ec2 describe-key-pairs --region "$REGION" --key-names "$KEY_NAME" >/dev/null 2>&1; then
  aws ec2 create-key-pair --region "$REGION" --key-name "$KEY_NAME" --query 'KeyMaterial' --output text > "$HERE/$KEY_NAME.pem"
  chmod 600 "$HERE/$KEY_NAME.pem"
  echo "   Created $HERE/$KEY_NAME.pem - keep this safe, it's the only copy."
else
  echo "   Key pair '$KEY_NAME' already exists, reusing it (the .pem from when it was created still works)."
fi

echo "== Default VPC =="
VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" --filters "Name=isDefault,Values=true" --query 'Vpcs[0].VpcId' --output text)
echo "   VPC: $VPC_ID"

echo "== Security group =="
SG_ID=$(aws ec2 describe-security-groups --region "$REGION" --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")
if [ "$SG_ID" == "None" ] || [ -z "$SG_ID" ]; then
  SG_ID=$(aws ec2 create-security-group --region "$REGION" --group-name "$SG_NAME" --description "Sentrix SOC platform" --vpc-id "$VPC_ID" --query 'GroupId' --output text)
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" --protocol tcp --port 3000 --cidr 0.0.0.0/0 >/dev/null
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" --protocol tcp --port 8000 --cidr 0.0.0.0/0 >/dev/null
  echo "   Created $SG_ID (opened 22, 3000, 8000)"
else
  echo "   Reusing existing $SG_ID"
fi

echo "== Launching instance =="
INSTANCE_ID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$AMI_ID" --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" --security-group-ids "$SG_ID" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=30,VolumeType=gp3}' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" \
  --query 'Instances[0].InstanceId' --output text)
echo "   Instance: $INSTANCE_ID (waiting for it to start...)"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"

echo "== Allocating an Elastic IP (so the address never changes) =="
ALLOC_ID=$(aws ec2 allocate-address --region "$REGION" --domain vpc --query 'AllocationId' --output text)
aws ec2 associate-address --region "$REGION" --instance-id "$INSTANCE_ID" --allocation-id "$ALLOC_ID" >/dev/null
PUBLIC_IP=$(aws ec2 describe-addresses --region "$REGION" --allocation-ids "$ALLOC_ID" --query 'Addresses[0].PublicIp' --output text)

cat > "$HERE/instance_info.env" <<EOF
INSTANCE_ID=$INSTANCE_ID
PUBLIC_IP=$PUBLIC_IP
REGION=$REGION
KEY_FILE=$HERE/$KEY_NAME.pem
EOF

echo ""
echo "== Done =="
echo "Public IP: $PUBLIC_IP"
echo "SSH:       ssh -i $HERE/$KEY_NAME.pem ubuntu@$PUBLIC_IP"
echo "Saved to:  $HERE/instance_info.env"
echo ""
echo "Next: wait ~60s for the instance to finish booting, then run ./deploy.sh"
