# SNS Alerting Configuration

## Overview

Amazon SNS is used to deliver real-time notifications when security events are detected by CloudWatch alarms.

This enables immediate visibility into suspicious activity and supports rapid incident response.

---

## Architecture

CloudTrail → CloudWatch Logs → Metric Filters → Alarms → SNS → Email Notification

---

## SNS Topic Configuration

- Topic Name: security-alerts
- Type: Standard
- Region: <region>

---

## Subscription

- Protocol: Email
- Endpoint: <email>
- Confirmation: Verified via email subscription

---

## Alarm Integration

All CloudWatch alarms are configured to trigger SNS notifications.

Each alarm sends a message to the SNS topic when:

- Alarm state = ALARM
- Suspicious activity is detected

---

## Example Alert Events

SNS notifications are triggered for:

- IAM user creation (CreateUser)
- Privilege escalation (AttachUserPolicy with AdministratorAccess)
- Access key creation (CreateAccessKey)
- Inline policy creation (PutUserPolicy)
- Role assumption activity (AssumeRole)
- CloudTrail logging disabled (StopLogging)
- CloudTrail deletion (DeleteTrail)
- Root account usage
- Failed console login attempts

---

## Example SNS Notification

Subject:
ALARM: "CreateUserAlarm" in AWS Account

Message:
A CloudWatch alarm has been triggered.

Alarm Name: CreateUserAlarm  
Metric: CreateUserMetric  
Threshold: >= 1  
State: ALARM  

---

## Design Considerations

- Email notifications provide immediate visibility for security events
- Low threshold ensures high-sensitivity detection
- SNS enables integration with other systems (Lambda, Slack, PagerDuty)
- Alerts are focused on high-risk actions to reduce noise

---

## Future Improvements

- Integrate SNS with Lambda for automated response
- Send alerts to Slack or incident management tools
- Add severity-based routing for alerts