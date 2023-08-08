// bin/detect_remediate.ts

import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { S3CMKStack } from '../lib/s3_cmk_stack';
import { EC2TagRuleStack } from '../lib/ec2_tag_stack';

const app = new cdk.App();
new S3CMKStack(app, 'S3CMKStack');
new EC2TagRuleStack(app, 'EC2TagRuleStack')