# Lambda Detection Engine Setup

## Overview

This Lambda function processes CloudTrail events from CloudWatch Logs and applies custom security detections for high-risk AWS activity.

It is designed to reduce noise by using threshold-based alerting and to send notifications through SNS when detection thresholds are exceeded.

---

## File Location

`aws/lambda/detection_engine.py`

---

## Purpose

The Lambda detection engine extends beyond basic CloudWatch metric filters by allowing:

- custom rule logic
- multiple detections in one function
- threshold-based suppression to reduce alert fatigue
- richer alert payloads

---

## Architecture

CloudTrail → CloudWatch Logs → Lambda → SNS → Email Alerts

---

## Detection Rules Implemented

The Lambda function currently detects:

- CreateUser
- DeleteTrail
- StopLogging
- AssumeRole
- PutUserPolicy
- AttachUserPolicy with `AdministratorAccess`
- CreateAccessKey
- Root account usage
- Failed console login attempts

---

## Threshold Logic

This Lambda is configured to reduce noisy alerting.

Current behavior:

- detections are grouped by rule name
- SNS alerts are sent only when the same rule occurs more than `ALERT_THRESHOLD` times in a single Lambda invocation batch

Example:

- if `ALERT_THRESHOLD = 5`
- then 6 matching events in the same batch will trigger an alert
- 5 or fewer matching events will not trigger an alert

Note: this implementation does **not** maintain state across separate Lambda invocations.

---

## Environment Variables

The function uses the following environment variables:

- `SNS_TOPIC_ARN`
- `ALERT_THRESHOLD`

### Example

- `SNS_TOPIC_ARN = arn:aws:sns:us-east-2:123456789012:security-alerts`
- `ALERT_THRESHOLD = 5`

---

## IAM Permissions Required

The Lambda execution role requires:

- `sns:Publish`
- CloudWatch Logs permissions through `AWSLambdaBasicExecutionRole`

---

## Trigger Configuration

Lambda is triggered by a CloudWatch Logs subscription filter connected to CloudTrail logs.

This allows CloudTrail events to be forwarded automatically to the function for processing.

---

## Supported Input Types

The function currently supports:

1. CloudWatch Logs subscription events  
2. Direct Lambda test events with a single CloudTrail-style record  
3. Direct Lambda test events using a `records` array  

This makes testing easier during development.

---

## Testing Approach

The function was tested using manual Lambda test events containing repeated CloudTrail-style records.

Example test strategy:

- send 6 `CreateUser` events in a single `records` array
- verify that the threshold logic triggers SNS alerting

---

## Alerting Behavior

When the threshold is exceeded, Lambda:

1. groups matching detections
2. builds a JSON alert payload
3. publishes the alert to SNS
4. sends the notification to the configured email subscriber

---

## Design Notes

- Lambda-based detections provide more flexibility than metric filters alone
- threshold-based logic reduces repetitive alerting
- the current version is suitable for batch-based suppression
- a future version could use DynamoDB for true time-window tracking across invocations

---

## Future Improvements

Potential future enhancements:

- add DynamoDB-backed rolling time windows
- add severity-based routing
- integrate with Slack or PagerDuty
- forward findings to Loki or Elasticsearch
- enrich alerts with user and account context