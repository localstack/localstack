#!/usr/bin/env python3

import aws_cdk as cdk
from cloudtrail_tracking.cloudtrail_tracking_stack import CloudtrailTrackingStack

app = cdk.App()
CloudtrailTrackingStack(app, "CloudtrailTrackingStack")

app.synth()
