# CloudWatch Metric Filters Implementation

## Overview

Each detection rule is implemented as a CloudWatch metric filter on CloudTrail logs.

Log Group:
`/aws/cloudtrail/security-monitoring`

Each filter generates a metric and triggers an alarm when matched.

---

## 1. CreateUser Detection

- Filter Pattern:
  { $.eventName = "CreateUser" }

- Metric Name:
  CreateUserMetric

---

## 2. Privilege Escalation Detection

- Filter Pattern:
  { ($.eventName = "AttachUserPolicy") && ($.requestParameters.policyArn = "*AdministratorAccess*") }

- Metric Name:
  PrivEscMetric

---

## 3. Access Key Creation

- Filter Pattern:
  { ($.eventSource = "iam.amazonaws.com") && ($.eventName = "CreateAccessKey") }

- Metric Name:
  CreateAccessKeyMetric

---

## 4. Inline Policy Creation

- Filter Pattern:
  { ($.eventSource = "iam.amazonaws.com") && ($.eventName = "PutUserPolicy") }

- Metric Name:
  PutUserPolicyMetric

---

## 5. AssumeRole Activity

- Filter Pattern:
  { ($.eventSource = "sts.amazonaws.com") && ($.eventName = "AssumeRole") }

- Metric Name:
  AssumeRoleMetric

---

## 6. StopLogging Detection

- Filter Pattern:
  { ($.eventSource = "cloudtrail.amazonaws.com") && ($.eventName = "StopLogging") }

- Metric Name:
  StopLoggingMetric

---

## 7. DeleteTrail Detection

- Filter Pattern:
  { ($.eventSource = "cloudtrail.amazonaws.com") && ($.eventName = "DeleteTrail") }

- Metric Name:
  DeleteTrailMetric

---

## 8. Root Account login

- Filter Pattern:
  { ($.eventName = "ConsoleLogin") && ($.userIdentity.type = "Root") && ($.responseElements.ConsoleLogin = "Success") }

- Metric Name:
   RootConsoleLoginCount 

---

## 9. Failed Console Login

- Filter Pattern:
  { ($.eventName = "ConsoleLogin") && ($.responseElements.ConsoleLogin = "Failure") }

- Metric Name:
  FailedLoginMetric