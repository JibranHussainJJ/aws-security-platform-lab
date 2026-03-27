# CloudWatch Alarms

## Overview

Each metric filter is connected to a CloudWatch alarm to trigger alerts when suspicious activity is detected.

All alarms are configured for near real-time detection.

---

## Alarm Configuration (Standard)

- Threshold: >= 1
- Evaluation Period: 1 period
- Period Duration: 300 seconds
- Statistic: Sum
- Comparison Operator: GreaterThanOrEqualToThreshold
- Treat Missing Data: Not Breaching

---

## Alarm Configuration (failed console logins)

- Threshold: >= 5
- Evaluation Period: 1 period
- Period Duration: 300 seconds
- Statistic: Sum
- Comparison Operator: GreaterThanOrEqualToThreshold
- Treat Missing Data: Not Breaching

---

## Alarm Naming Convention

- MEDIUM-IAM-UserCreated
- HIGH-IAM-AttachUserPolicy
- HIGH-IAM-CreateAccessKey
- HIGH-IAM-PutUserPolicy
- MEDIUM-STS-AssumeRole
- CRITICAL-CloudTrail-StopLogging
- CRITICAL-CloudTrail-DeleteTrail
- CRITICAL-Root-ConsoleLogin
- MEDIUM-IAM-FailedConsoleLogin

---

## Alarm Descriptions

### MEDIUM-IAM-UserCreated
Triggers when a new IAM user is created.

---

### HIGH-IAM-PrivEscAlarm
Triggers when AdministratorAccess policy is attached.

---

### HIGH-IAM-CreateAccessKey
Triggers when a new access key is created.

---

### HIGH-IAM-PutUserPolicy
Triggers when an inline policy is created.

---

### MEDIUM-STS-AssumeRole
Triggers on role assumption activity.

---

### CRITICAL-CloudTrail-StopLogging
Triggers when CloudTrail logging is stopped.

---

### CRITICAL-CloudTrail-DeleteTrail
Triggers when CloudTrail trail is deleted.

---

### CRITICAL-Root-ConsoleLogin
Triggers on root account activity.

---

### MEDIUM-IAM-FailedConsoleLogin
Triggers on failed console login attempts.