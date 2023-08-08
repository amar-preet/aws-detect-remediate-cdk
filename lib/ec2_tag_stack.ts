import * as cdk from '@aws-cdk/core';
import * as lambda from '@aws-cdk/aws-lambda';
import * as config from '@aws-cdk/aws-config';
import * as iam from '@aws-cdk/aws-iam';
import * as events from '@aws-cdk/aws-events';
import * as targets from '@aws-cdk/aws-events-targets';

export class EC2TagRuleStack extends cdk.Stack {
    constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        // Lambda function for EC2 tag detection
        const ec2TagDetectFunction = new lambda.Function(this, 'EC2TagDetectFunction', {
            code: lambda.Code.fromAsset('./lambda/detect/'),
            handler: 'ec2_tag_detect_lambda.handler',
            runtime: lambda.Runtime.PYTHON_3_8,
        });

        // Lambda function for EC2 tag remediation
        const ec2TagRemediateFunction = new lambda.Function(this, 'EC2TagRemediateFunction', {
            code: lambda.Code.fromAsset('./lambda/remediate/'),
            handler: 'ec2_tag_remediate_lambda.handler',
            runtime: lambda.Runtime.PYTHON_3_8,
        });

        // Grant necessary permissions to the detection Lambda
        ec2TagDetectFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: ['ec2:DescribeInstances'],
            resources: ['*']
        }));
        ec2TagDetectFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: ['config:PutEvaluations'],
            resources: ['*']
        }));

        // Grant necessary permissions to the remediation Lambda
        ec2TagRemediateFunction.addToRolePolicy(new iam.PolicyStatement({
            actions: ['ec2:CreateTags'],
            resources: ['*']
        }));

        // Custom AWS Config rule for EC2 tag check
        const ec2TagRule = new config.CfnConfigRule(this, 'EC2TagRule', {
            configRuleName: 'ec2-instance-environment-tag-check',
            source: {
                owner: 'CUSTOM_LAMBDA',
                sourceIdentifier: ec2TagDetectFunction.functionArn,
                sourceDetails: [{
                    eventSource: 'aws.config',
                    messageType: 'ConfigurationItemChangeNotification'
                }]
            },
            scope: {
                complianceResourceTypes: ['AWS::EC2::Instance'],
            }
        });

        ec2TagDetectFunction.addPermission('AllowConfig', {
            principal: new iam.ServicePrincipal('config.amazonaws.com')
        });

        // EventBridge rule to trigger EC2TagDetectFunction Lambda when Config rule compliance changes to NON_COMPLIANT
        const configNonCompliantRule = new events.Rule(this, 'ConfigNonCompliantRule', {
            eventPattern: {
                source: ['aws.config'],
                detailType: ['AWS Config Rule Compliance Change'],
                detail: {
                    configRuleName: [ec2TagRule.configRuleName],
                    complianceType: ['NON_COMPLIANT'],
                },
            },
        });

        configNonCompliantRule.addTarget(new targets.LambdaFunction(ec2TagDetectFunction));

        // EventBridge rule to trigger EC2TagRemediateFunction Lambda when Security Hub determines a compliance status of "FAILED"
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

        securityHubFailedRule.addTarget(new targets.LambdaFunction(ec2TagRemediateFunction));

        ec2TagDetectFunction.addPermission('AllowEventBridge', {
            principal: new iam.ServicePrincipal('events.amazonaws.com')
        });
    }
}
