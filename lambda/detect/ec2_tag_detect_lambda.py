import boto3
import json
from datetime import datetime

ec2_client = boto3.client('ec2')
config_client = boto3.client('config')
securityhub_client = boto3.client('securityhub')


def send_to_security_hub(instance_id, annotation):
    """Send a finding to AWS Security Hub."""
    finding = {
        'SchemaVersion': '2018-10-08',
        'Id': instance_id + '/ec2-environment-tag-check',
        'ProductArn': f'arn:aws:securityhub:{boto3.session.Session().region_name}:{boto3.client("sts").get_caller_identity().get("Account")}:product/{boto3.client("sts").get_caller_identity().get("Account")}/default',
        'GeneratorId': instance_id,
        'AwsAccountId': boto3.client("sts").get_caller_identity().get("Account"),
        'Types': ['Software and Configuration Checks/AWS Security Best Practices'],
        'CreatedAt': str(datetime.utcnow()),
        'UpdatedAt': str(datetime.utcnow()),
        'Severity': {'Label': 'HIGH'},
        'Title': 'EC2 Instance Environment Tag Check',
        'Description': annotation,
        'ProductFields': {'Product Name': 'EC2 Environment Tag Check'},
        'Resources': [{
            'Type': 'AwsEc2Instance',
            'Id': f'AWS::EC2::Instance::{instance_id}',
            'Partition': 'aws',
            'Region': boto3.session.Session().region_name
        }],
        'Compliance': {'Status': 'FAILED'},
        'Workflow': {'Status': 'NEW'},
        'RecordState': 'ACTIVE'
    }

    response = securityhub_client.batch_import_findings(Findings=[finding])
    return response

def evaluate_ec2_tags(instance_id):
    """Evaluate tags of an EC2 instance."""
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    instance = response['Reservations'][0]['Instances'][0]
    tags = instance.get('Tags', [])

    for tag in tags:
        if tag['Key'] == 'Environment':
            return "COMPLIANT", "EC2 instance has the 'Environment' tag."

    return "NON_COMPLIANT", "EC2 instance does not have the 'Environment' tag."

def handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    instance_id = invoking_event['configurationItem']['resourceId']

    compliance_type, annotation = evaluate_ec2_tags(instance_id)

    if compliance_type == "NON_COMPLIANT":
        send_to_security_hub(instance_id, annotation)

    config_client.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                'ComplianceResourceId': instance_id,
                'ComplianceType': compliance_type,
                'Annotation': annotation,
                'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
            }
        ],
        ResultToken=event['resultToken']
    )
