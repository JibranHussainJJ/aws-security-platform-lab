# GuardDuty Setup

## Overview

Amazon GuardDuty is used for managed threat detection.

It analyzes AWS account activity and identifies:

- Unauthorized access
- Suspicious API calls
- Reconnaissance attempts
- Crypto mining activity

---

## Configuration Steps

1. Enabled GuardDuty in AWS console
2. Enabled all protection plans
3. Generated sample findings for testing
4. Verified findings in GuardDuty dashboard

---

## Integration

GuardDuty findings are sent to Lambda using EventBridge:

GuardDuty → EventBridge → Lambda → SNS

---

## Example Findings

- Impact:Kubernetes/TorIPCaller
- UnauthorizedAccess:IAMUser
- CryptoCurrency:EC2

---

## Purpose

Provides managed threat intelligence to complement custom detection logic.