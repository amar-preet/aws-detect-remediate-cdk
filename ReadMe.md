# AWS S3 Bucket Encryption Compliance and Remediation

This project sets up an AWS environment to monitor S3 buckets for encryption compliance and automatically remediate non-compliant buckets by encrypting them with a Customer Managed Key (CMK).

Prerequisites
AWS CLI installed and configured with appropriate permissions.
AWS CDK installed.
Python 3.8 or higher.

### Setup

1. Clone the Repository

2. Install Dependencies

```
npm install
```

3. Deploy with CDK

First, bootstrap the CDK (only needs to be done once per AWS account/region):

```
cdk bootstrap
```

Deploy the CDK stack:
```
cdk deploy
```

### Usage
Once deployed, the system will automatically monitor S3 buckets in the AWS account for encryption compliance. 

Detect: If a bucket is found to be non-compliant (i.e., not encrypted with a CMK), the system will:
Remediate: Create a new KMS key (or use an existing one with the description "Key for encrypting S3 bucket").
Encrypt the non-compliant S3 bucket with the CMK.
Logging & Notification: åSend a notification to the specified email address about the non-compliant bucket.

### Cleanup
To avoid incurring future charges, you can destroy the CDK stack
```
cdk destroy
```