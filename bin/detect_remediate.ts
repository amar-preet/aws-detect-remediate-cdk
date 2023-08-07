// bin/detect_remediate.ts

import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { DetectRemediateStack } from '../lib/detect_remediate_stack';

const app = new cdk.App();
new DetectRemediateStack(app, 'DetectRemediateStack');
