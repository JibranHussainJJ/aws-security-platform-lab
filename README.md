# CloudWatch Security Dashboard

## Overview

A CloudWatch dashboard was created to monitor security activity.

---

## Metrics Included

- Lambda Invocations (Detection activity)
- Lambda Errors (System health)
- SNS Messages Published (Alert volume)

---

## Logs Insights

Used to display:

- Recent security events
- GuardDuty findings
- Detection activity

---

## Purpose

Provides real-time visibility into:

- Security detections
- Alerting pipeline
- System performance

---

## Architecture

CloudTrail → CloudWatch → Lambda → SNS  
GuardDuty → EventBridge → Lambda → SNS