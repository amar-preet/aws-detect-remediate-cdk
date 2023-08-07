import boto3
import json
import logging
import os

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Constants
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

# AWS Clients
sns_client = boto3.client('sns')
s3_client = boto3.client("s3")
kms_client = boto3.client("kms")
config_client = boto3.client("config")


def notify_non_compliance(message):
    """Send a notification for non-compliant resources."""
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject='Non-compliant S3 Bucket Detected'
    )


def evaluate_bucket_encryption(bucket_name):
    """Evaluate the encryption status of an S3 bucket."""
    try:
        encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        master_key_id = encryption_response["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"]
        
        aliases = kms_client.list_aliases()["Aliases"]
        for alias in aliases:
            if alias.get("TargetKeyId") == master_key_id:
                if alias["AliasName"].startswith("alias/aws/"):
                    message = f"Bucket {bucket_name} is encrypted with AWS-managed key."
                    logger.info(message)
                    notify_non_compliance(message)
                    return "NON_COMPLIANT", message
                else:
                    return "COMPLIANT", "S3 bucket encrypted with Customer Managed Key"
    except s3_client.exceptions.NoSuchBucket:
        message = f"Bucket {bucket_name} does not exist."
        logger.warning(message)
        return 'NOT_APPLICABLE', message
    except s3_client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "AccessDenied":
            message = f"Access denied for bucket {bucket_name}."
            logger.warning(message)
            return 'NOT_APPLICABLE', message
        else:
            message = f"S3 bucket {bucket_name} does NOT have encryption enabled."
            notify_non_compliance(message)
            return "NON_COMPLIANT", message
    except Exception as e:
        message = f"Unhandled exception for bucket {bucket_name}: {e}"
        logger.error(message)
        return 'NOT_APPLICABLE', message


def handler(event, context):
    """Main Lambda function handler."""
    logger.info('Received event: %s', event)
    invoking_event = json.loads(event["invokingEvent"])
    bucket_name = invoking_event["configurationItem"]["resourceId"]
    
    compliance_type, annotation = evaluate_bucket_encryption(bucket_name)
    
    config_client.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": invoking_event["configurationItem"]["resourceType"],
                "ComplianceResourceId": bucket_name,
                "ComplianceType": compliance_type,
                "Annotation": annotation,
                "OrderingTimestamp": invoking_event["configurationItem"]["configurationItemCaptureTime"],
            },
        ],
        ResultToken=event["resultToken"],
    )
