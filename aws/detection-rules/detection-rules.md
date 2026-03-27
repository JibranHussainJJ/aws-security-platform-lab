# Cloud Security Detection Rules

## Overview

These detection rules are designed to identify high-risk IAM activity and potential security threats within AWS environments using CloudTrail logs.

The rules focus on:
- IAM abuse
- Privilege escalation
- Persistence mechanisms
- Logging tampering
- Suspicious access patterns

---

## 1. IAM User Creation

**Description:** Detects creation of new IAM users.

**Risk:** Attackers may create new users for persistence.

**Pattern:**
{ $.eventName = "CreateUser" }

---

## 2. Privilege Escalation (Administrator Access)

**Description:** Detects attachment of AdministratorAccess policy to a user.

**Risk:** Full account takeover via privilege escalation.

**Pattern:**
{ ($.eventName = "AttachUserPolicy") && ($.requestParameters.policyArn = "*AdministratorAccess*") }

---

## 3. Access Key Creation

**Description:** Detects creation of new access keys.

**Risk:** Used for persistence and API-based attacks.

**Pattern:**
{ ($.eventSource = "iam.amazonaws.com") && ($.eventName = "CreateAccessKey") }

---

## 4. Inline Policy Creation

**Description:** Detects creation of inline policies on users.

**Risk:** Harder to detect privilege escalation compared to managed policies.

**Pattern:**
{ ($.eventSource = "iam.amazonaws.com") && ($.eventName = "PutUserPolicy") }

---

## 5. Role Assumption Activity

**Description:** Detects AssumeRole API calls.

**Risk:** May indicate lateral movement or cross-account access.

**Pattern:**
{ ($.eventSource = "sts.amazonaws.com") && ($.eventName = "AssumeRole") }

---

## 6. CloudTrail Logging Disabled

**Description:** Detects when CloudTrail logging is stopped.

**Risk:** Attackers disabling logging to evade detection.

**Pattern:**
{ ($.eventSource = "cloudtrail.amazonaws.com") && ($.eventName = "StopLogging") }

---

## 7. CloudTrail Deletion

**Description:** Detects deletion of CloudTrail trails.

**Risk:** Complete removal of audit logging.

**Pattern:**
{ ($.eventSource = "cloudtrail.amazonaws.com") && ($.eventName = "DeleteTrail") }

---

## 8. Root Account Usage

**Description:** Detects usage of the root account.

**Risk:** Root account has unrestricted access.

**Pattern:**
{ $.userIdentity.type = "Root" }

---

## 9. Failed Console Login

**Description:** Detects failed AWS console login attempts.

**Risk:** Brute-force or unauthorized access attempts.

**Pattern:**
{ ($.eventName = "ConsoleLogin") && ($.responseElements.ConsoleLogin = "Failure") }