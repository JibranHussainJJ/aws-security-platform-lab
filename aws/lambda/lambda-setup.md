# Lambda Detection Engine Setup

## Overview

This Lambda function processes two event sources:

1. CloudTrail events delivered through CloudWatch Logs
2. GuardDuty findings delivered through EventBridge

It applies custom security detections and sends alerts through SNS.

---

## File Location

`aws/lambda/detection_engine.py`

---

## Architecture

### CloudTrail path
CloudTrail → CloudWatch Logs → Lambda → SNS

### GuardDuty path
GuardDuty → EventBridge → Lambda → SNS

---

## Detection Rules

### CloudTrail / IAM detections
- CreateUser
- DeleteTrail
- StopLogging
- AssumeRole
- PutUserPolicy
- AttachUserPolicy with AdministratorAccess
- CreateAccessKey
- Root account usage
- Failed console login attempts

### GuardDuty detections
- GuardDuty findings are forwarded directly from EventBridge
- Lambda publishes GuardDuty finding details to SNS

---

## Threshold Logic

For CloudTrail detections, Lambda groups detections by rule name and only sends SNS alerts when the same rule occurs more than `ALERT_THRESHOLD` times in a single Lambda invocation batch.

This reduces alert noise.

Note: this version does not maintain state across separate Lambda invocations.

---

## Environment Variables

- `SNS_TOPIC_ARN`
- `ALERT_THRESHOLD`

### Example

- `SNS_TOPIC_ARN = arn:aws:sns:us-east-2:123456789012:security-alerts`
- `ALERT_THRESHOLD = 5`

---

## IAM Permissions Required

The Lambda execution role requires:

- `sns:Publish`
- CloudWatch Logs permissions via `AWSLambdaBasicExecutionRole`

---

## Trigger Configuration

### CloudTrail trigger
CloudWatch Logs subscription filter connected to CloudTrail logs

### GuardDuty trigger
EventBridge rule with pattern:
- source = `aws.guardduty`
- detail-type = `GuardDuty Finding`

---

## Testing

### CloudTrail testing
Supports:
- CloudWatch Logs subscription events
- direct Lambda test events
- `records` array test events

### GuardDuty testing
Supports:
- sample findings generated in GuardDuty
- EventBridge delivery to Lambda

---

## Design Notes

- Lambda provides more flexible detection logic than metric filters alone
- GuardDuty integration adds managed AWS threat detection
- SNS provides a unified alerting path for both custom and managed detections