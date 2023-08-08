import * as cdk from '@aws-cdk/core';
import * as lambda from '@aws-cdk/aws-lambda';
import * as events from '@aws-cdk/aws-events';
import * as targets from '@aws-cdk/aws-events-targets';
import * as config from '@aws-cdk/aws-config';
import * as s3 from '@aws-cdk/aws-s3';
import * as iam from '@aws-cdk/aws-iam';
import * as sns from '@aws-cdk/aws-sns';
import * as subscriptions from '@aws-cdk/aws-sns-subscriptions';
//import * as securityhub from '@aws-cdk/aws-securityhub';

export class S3CMKStack extends cdk.Stack {
    constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        // Create an S3 bucket with AWS managed KMS encryption
        const bucket = new s3.Bucket(this, 'MyBucket', {
            encryption: s3.BucketEncryption.KMS_MANAGED,
        });
        // Create an SNS topic
        const nonCompliantNotificationTopic = new sns.Topic(this, 'NonCompliantNotificationTopic', {
            displayName: 'Non-compliant S3 Bucket detected',
        });

        // Subscribe an email to the topic
        nonCompliantNotificationTopic.addSubscription(new subscriptions.EmailSubscription('YOUR-EMAIL@EMAIL.com'));

        // Lambda function for detection
        const detectFunction = new lambda.Function(this, 'DetectFunction', {
            code: lambda.Code.fromAsset('./lambda/detect/'),
            handler: 's3_cmk_detect_lambda.handler',
            runtime: lambda.Runtime.PYTHON_3_8,
            environment: {
                'SNS_TOPIC_ARN': nonCompliantNotificationTopic.topicArn,
                'AWS_ACCOUNT_ID': this.account,  
                'DEPLOYED_REGION': this.region  
            }
        });

        // Lambda function for remediation
        const remediateFunction = new lambda.Function(this, 'RemediateFunction', {
            code: lambda.Code.fromAsset('./lambda/remediate/'),
            handler: 's3_cmk_remediate_lambda.py.handler',
            runtime: lambda.Runtime.PYTHON_3_8
        });

        // Grant permissions to list KMS aliases
        remediateFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: ['kms:CreateAlias'],
            resources: ['arn:aws:kms:us-west-2:779022664097:alias/remediate']
        }));

        remediateFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: ['s3:PutEncryptionConfiguration'],
            resources: [bucket.bucketArn]
        }));

        remediateFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: ['kms:*'],
            resources: ['*']
        }));


        // Grant the necessary permissions to the Lambda function's role
        const putEvaluationsPolicy = new iam.PolicyStatement({
            actions: ['config:PutEvaluations'],
            resources: ['*'],  // Adjust this if you want to restrict to specific resources
        });

        detectFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: ['s3:GetBucketEncryption'],
            resources: ['arn:aws:s3:::*'],  // All S3 buckets
        }));

        // Grant permissions to list KMS aliases
        detectFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: ['kms:ListAliases'],
            resources: ['*'],  // All KMS keys
        }));

        // Grant permissions to send findings to AWS Security Hub
        detectFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: ['securityhub:BatchImportFindings'],
            resources: ['*']
        }));

        // Custom AWS Config rule for S3 Buckets not encrypted with CMK
        const s3EncryptionRule = new config.CfnConfigRule(this, 'S3EncryptionRule', {
            configRuleName: 's3-bucket-cmk-encryption-check',
            source: {
                owner: 'CUSTOM_LAMBDA',
                sourceIdentifier: detectFunction.functionArn,
                sourceDetails: [{
                    eventSource: 'aws.config',
                    messageType: 'ConfigurationItemChangeNotification'
                }]
            },
            scope: {
                complianceResourceTypes: ['AWS::S3::Bucket'],
            }
        });

        detectFunction.role?.addToPrincipalPolicy(putEvaluationsPolicy);
        detectFunction.addPermission('AllowConfig', {
            principal: new iam.ServicePrincipal('config.amazonaws.com')
        });

        // Grant the Lambda function permissions to publish to the SNS topic
        nonCompliantNotificationTopic.grantPublish(detectFunction);

        // EventBridge rule to trigger Detect Lambda when Config rule compliance changes
        const eventRule = new events.Rule(this, 'ConfigRuleChange', {
            eventPattern: {
                source: ['aws.config'],
                detailType: ['AWS Config Rule Compliance Change'],
                detail: {
                    configRuleName: [s3EncryptionRule.configRuleName],
                    complianceType: ['NON_COMPLIANT'],
                },
            },
        });

        eventRule.addTarget(new targets.LambdaFunction(detectFunction));

        // EventBridge rule to trigger Remediation Lambda when Security Hub determines a compliance status of "FAILED"
        const securityHubFailedRule = new events.Rule(this, 'SecurityHubFailedRule', {
            eventPattern: {
                source: ['aws.securityhub'],
                detailType: ['Security Hub Findings - Imported'],
                detail: {
                    findings: {
                        Compliance: {
                            Status: ['FAILED']
                        }
                    }
                }
            }
        });

        securityHubFailedRule.addTarget(new targets.LambdaFunction(remediateFunction));

        // Enable AWS Security Hub
        // If you have SecurityHub already enable, comment out next 2 lines
        //const securityHub = new securityhub.CfnHub(this, 'SecurityHub');
        //securityHub.addDependsOn(s3EncryptionRule);
    }
}
