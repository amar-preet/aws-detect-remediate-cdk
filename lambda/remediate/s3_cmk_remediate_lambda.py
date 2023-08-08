import boto3
import logging

# Setup logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Clients
s3_client = boto3.client("s3")
kms_client = boto3.client("kms")


def get_or_create_key(
    description="Key for encrypting S3 bucket", alias_name="alias/remediate"
):
    kms_client = boto3.client("kms")

    # List all keys
    keys = kms_client.list_keys()
    for key in keys["Keys"]:
        key_metadata = kms_client.describe_key(KeyId=key["KeyId"])
        if key_metadata["KeyMetadata"]["Description"] == description:
            return key["KeyId"]

    # If key with the given description is not found, create a new one
    response = kms_client.create_key(
        Description=description, KeyUsage="ENCRYPT_DECRYPT", Origin="AWS_KMS"
    )
    key_id = response["KeyMetadata"]["KeyId"]

    # Create an alias for the key
    try:
        kms_client.create_alias(AliasName=alias_name, TargetKeyId=key_id)
        logger.info(f"Created alias {alias_name} for key {key_id}")
    except kms_client.exceptions.AlreadyExistsException:
        logger.info(f"Alias {alias_name} already exists for key {key_id}")

    return key_id


def encrypt_bucket_with_CMK(bucket_name):
    """Encrypt the S3 bucket with a Customer Managed Key."""
    s3_client = boto3.client("s3")
    key_id = get_or_create_key()

    # Apply the CMK to the S3 bucket
    s3_client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": key_id,
                    }
                }
            ]
        },
    )
    logger.info(f"Bucket {bucket_name} encrypted with CMK {key_id}")


def handler(event, context):
    """Main Lambda function handler."""
    logger.info("Received event: %s", event)

    # Extract the bucket name from the event
    bucket_arn = event["detail"]["findings"]["Resources"][0]["Id"]
    bucket_name = bucket_arn.split(":")[-1].split("/")[-1]
    logger.info("Extracted bucket name: %s", bucket_name)

    # Encrypt the bucket with a CMK
    encrypt_bucket_with_CMK(bucket_name)
