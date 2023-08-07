# AWS Detect & Remediate with CDK

This repository provides a solution to detect and automatically remediate AWS security misconfigurations using AWS CDK (Cloud Development Kit). It focuses on ensuring that AWS resources are compliant with best practices, and if not, it triggers remediation actions.

## Overview
The solution uses AWS Config to continuously monitor and assess AWS resource configurations. When a resource is found to be non-compliant with the defined AWS Config Rules, AWS Lambda functions are triggered to remediate the misconfiguration and bring the resource back to a compliant state.

## Prerequisites
* AWS CLI installed and configured with appropriate permissions.
* AWS CDK installed.
* Node.js and NPM installed.
* Python 3.8 or later.

## Setup

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

## Usage
Once deployed, the solution will start monitoring the AWS resources defined in the AWS Config rules. If a resource is found to be non-compliant, the corresponding Lambda function will be triggered to remediate the misconfiguration.

## Cleanup
To avoid incurring future charges, you can destroy the CDK stack
```
cdk destroy
```