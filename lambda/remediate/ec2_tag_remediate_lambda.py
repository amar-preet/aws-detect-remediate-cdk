import boto3

ec2_client = boto3.client('ec2')

def remediate_ec2_tags(instance_id):
    """Add 'Environment' tag to an EC2 instance."""
    ec2_client.create_tags(
        Resources=[instance_id],
        Tags=[
            {
                'Key': 'Environment',
                'Value': 'Unknown'
            }
        ]
    )

def handler(event, context):
    # Assuming the instance ID is passed directly in the event
    # Adjust as needed based on your EventBridge rule setup
    instance_id = event['detail']['findings']['Resources'][0]['Id'].split(':')[-1].split('/')[-1]
    remediate_ec2_tags(instance_id)
