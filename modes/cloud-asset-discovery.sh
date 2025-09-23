#!/bin/bash
# Cloud Asset Discovery Mode
# Author: Sn1per Security Team
# Description: Discovers and enumerates cloud assets across multiple providers

if [[ "$CLOUD_DISCOVERY" = "1" ]]; then
  echo "[sn1persecurity.com] •?((¯°·._.• Started Cloud Asset Discovery: $TARGET [cloud-asset-discovery] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Cloud Asset Discovery: $TARGET [cloud-asset-discovery] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi

  mkdir -p $LOOT_DIR/cloud/$TARGET
  
  # AWS Discovery
  if [[ "$AWS_DISCOVERY" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISCOVERING AWS ASSETS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    
    # Check for AWS CLI and install if not present
    if ! command -v aws &> /dev/null; then
      echo -e "$OKORANGE[i]$RESET AWS CLI not found. Installing..."
      pip3 install awscli --upgrade --user
      export PATH=~/.local/bin:$PATH
    fi
    
    # Run AWS recon if credentials are configured
    if aws sts get-caller-identity &> /dev/null; then
      # List all regions
      for region in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
        echo -e "${OKBLUE}[*]${RESET} Scanning AWS region: $region"
        
        # EC2 Instances
        echo -e "${OKBLUE}[*]${RESET} Enumerating EC2 instances..."
        aws ec2 describe-instances --region $region --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,PrivateIpAddress,PublicIpAddress,State.Name,Tags[?Key==`Name`].Value|[0]]' --output table > $LOOT_DIR/cloud/$TARGET/aws-ec2-$region.txt 2>&1
        
        # S3 Buckets
        echo -e "${OKBLUE}[*]${RESET} Enumerating S3 buckets..."
        aws s3 ls --region $region > $LOOT_DIR/cloud/$TARGET/aws-s3-$region.txt 2>&1
        
        # IAM Users and Policies
        echo -e "${OKBLUE}[*]${RESET} Enumerating IAM users and policies..."
        aws iam list-users > $LOOT_DIR/cloud/$TARGET/aws-iam-users.json 2>&1
        aws iam list-policies --scope Local --output json > $LOOT_DIR/cloud/$TARGET/aws-iam-policies.json 2>&1
        
        # Lambda Functions
        echo -e "${OKBLUE}[*]${RESET} Enumerating Lambda functions..."
        aws lambda list-functions --region $region > $LOOT_DIR/cloud/$TARGET/aws-lambda-$region.json 2>&1
      done
    else
      echo -e "${OKORANGE}[!]${RESET} AWS CLI not configured. Skipping AWS discovery."
    fi
  fi
  
  # Azure Discovery
  if [[ "$AZURE_DISCOVERY" = "1" ]]; then
    echo -e "\n${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISCOVERING AZURE ASSETS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    
    if command -v az &> /dev/null; then
      if az account show &> /dev/null; then
        # List all subscriptions
        for sub in $(az account list --query "[].id" -o tsv); do
          echo -e "${OKBLUE}[*]${RESET} Scanning Azure subscription: $sub"
          
          # Set subscription
          az account set --subscription $sub
          
          # List VMs
          echo -e "${OKBLUE}[*]${RESET} Enumerating virtual machines..."
          az vm list --output table > $LOOT_DIR/cloud/$TARGET/azure-vms-$sub.txt 2>&1
          
          # List Storage Accounts
          echo -e "${OKBLUE}[*]${RESET} Enumerating storage accounts..."
          az storage account list --output table > $LOOT_DIR/cloud/$TARGET/azure-storage-$sub.txt 2>&1
          
          # List App Services
          echo -e "${OKBLUE}[*]${RESET} Enumerating app services..."
          az webapp list --output table > $LOOT_DIR/cloud/$TARGET/azure-webapps-$sub.txt 2>&1
        done
      else
        echo -e "${OKORANGE}[!]${RESET} Azure CLI not logged in. Skipping Azure discovery."
      fi
    else
      echo -e "${OKORANGE}[!]${RESET} Azure CLI not found. Install with: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
    fi
  fi
  
  # GCP Discovery
  if [[ "$GCP_DISCOVERY" = "1" ]]; then
    echo -e "\n${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISCOVERING GCP ASSETS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    
    if command -v gcloud &> /dev/null; then
      # List all projects
      for project in $(gcloud projects list --format="value(projectId)"); do
        echo -e "${OKBLUE}[*]${RESET} Scanning GCP project: $project"
        
        # Set project
        gcloud config set project $project
        
        # List Compute Instances
        echo -e "${OKBLUE}[*]${RESET} Enumerating compute instances..."
        gcloud compute instances list > $LOOT_DIR/cloud/$TARGET/gcp-compute-$project.txt 2>&1
        
        # List Storage Buckets
        echo -e "${OKBLUE}[*]${RESET} Enumerating storage buckets..."
        gsutil ls -p $project > $LOOT_DIR/cloud/$TARGET/gcp-storage-$project.txt 2>&1
        
        # List Cloud Functions
        echo -e "${OKBLUE}[*]${RESET} Enumerating cloud functions..."
        gcloud functions list > $LOOT_DIR/cloud/$TARGET/gcp-functions-$project.txt 2>&1
      done
    else
      echo -e "${OKORANGE}[!]${RESET} Google Cloud SDK not found. Install with: curl https://sdk.cloud.google.com | bash"
    fi
  fi
  
  echo -e "\n${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED CLOUD ASSET DISCOVERY COMPLETE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  
  # Generate report
  if [[ "$GENERATE_REPORT" = "1" ]]; then
    generate_cloud_report "$TARGET"
  fi
  
  echo "[sn1persecurity.com] •?((¯°·._.• Finished Cloud Asset Discovery: $TARGET [cloud-asset-discovery] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Finished Cloud Asset Discovery: $TARGET [cloud-asset-discovery] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
fi

# Generate cloud discovery report
generate_cloud_report() {
  local target=$1
  local report_file="$LOOT_DIR/cloud/$target/cloud-asset-report-$(date +%Y%m%d%H%M).html"
  
  cat > "$report_file" << EOL
<!DOCTYPE html>
<html>
<head>
    <title>Cloud Asset Discovery Report - $target</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; }
        .finding { background: #f9f9f9; border-left: 4px solid #3498db; padding: 10px 15px; margin-bottom: 10px; }
        .critical { border-left-color: #e74c3c !important; }
        .high { border-left-color: #e67e22 !important; }
        .medium { border-left-color: #f39c12 !important; }
        .low { border-left-color: #2ecc71 !important; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Cloud Asset Discovery Report</h1>
        <p>Target: $target | Generated: $(date)</p>
    </div>
    
    <div class="section">
        <h2>Summary</h2>
        <p>Cloud asset discovery performed on $(date) against target $target.</p>
    </div>
    
    <div class="section">
        <h2>Assets Discovered</h2>
        <div class="finding">
            <h3>AWS Assets</h3>
            <pre>$(cat $LOOT_DIR/cloud/$target/aws-ec2-*.txt 2>/dev/null || echo "No AWS assets found")</pre>
        </div>
        
        <div class="finding">
            <h3>Azure Assets</h3>
            <pre>$(cat $LOOT_DIR/cloud/$target/azure-vms-*.txt 2>/dev/null || echo "No Azure assets found")</pre>
        </div>
        
        <div class="finding">
            <h3>GCP Assets</h3>
            <pre>$(cat $LOOT_DIR/cloud/$target/gcp-compute-*.txt 2>/dev/null || echo "No GCP assets found")</pre>
        </div>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <div class="finding low">
            <h3>Security Recommendations</h3>
            <ul>
                <li>Review and restrict IAM permissions following the principle of least privilege</li>
                <li>Enable logging and monitoring for all cloud resources</li>
                <li>Regularly audit and rotate access keys and credentials</li>
                <li>Implement network segmentation and security groups</li>
                <li>Enable multi-factor authentication for all privileged accounts</li>
            </ul>
        </div>
    </div>
    
    <div class="timestamp">
        Report generated by Sn1per Professional v$VERSION on $(date)
    </div>
</body>
</html>
EOL

  echo -e "${OKGREEN}[*]${RESET} Cloud asset discovery report generated: $report_file"
}
