import base64
import boto3
import gzip
import json
import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client("sns")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
ALERT_THRESHOLD = int(os.environ.get("ALERT_THRESHOLD", "5"))


def publish_sns(subject: str, message: str) -> None:
    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN is not set. Skipping SNS publish.")
        return

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject[:100],
        Message=message
    )


def safe_get(dct: Dict[str, Any], path: List[str], default: Any = None) -> Any:
    current = dct
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def contains_admin_access_policy(record: Dict[str, Any]) -> bool:
    policy_arn = safe_get(record, ["requestParameters", "policyArn"], "")
    return isinstance(policy_arn, str) and "AdministratorAccess" in policy_arn


def is_root_activity(record: Dict[str, Any]) -> bool:
    return safe_get(record, ["userIdentity", "type"], "") == "Root"


def is_failed_console_login(record: Dict[str, Any]) -> bool:
    return (
        record.get("eventName") == "ConsoleLogin"
        and safe_get(record, ["responseElements", "ConsoleLogin"], "") == "Failure"
    )


def build_alert(record: Dict[str, Any], rule_name: str, severity: str, reason: str) -> Dict[str, Any]:
    return {
        "rule_name": rule_name,
        "severity": severity,
        "reason": reason,
        "event_time": record.get("eventTime"),
        "event_name": record.get("eventName"),
        "event_source": record.get("eventSource"),
        "aws_region": record.get("awsRegion"),
        "source_ip": record.get("sourceIPAddress"),
        "user_type": safe_get(record, ["userIdentity", "type"]),
        "user_arn": safe_get(record, ["userIdentity", "arn"]),
        "user_name": safe_get(record, ["userIdentity", "userName"]),
        "account_id": safe_get(record, ["userIdentity", "accountId"]),
        "request_parameters": record.get("requestParameters"),
        "recipient_account_id": record.get("recipientAccountId"),
    }


def evaluate_record(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []

    event_name = record.get("eventName")
    event_source = record.get("eventSource")

    if event_name == "CreateUser":
        alerts.append(build_alert(
            record, "CreateUser", "medium", "A new IAM user was created."
        ))

    if event_source == "cloudtrail.amazonaws.com" and event_name == "DeleteTrail":
        alerts.append(build_alert(
            record, "DeleteTrail", "critical", "A CloudTrail trail was deleted."
        ))

    if event_source == "sts.amazonaws.com" and event_name == "AssumeRole":
        alerts.append(build_alert(
            record, "AssumeRole", "low", "An AssumeRole API call was made."
        ))

    if event_source == "iam.amazonaws.com" and event_name == "PutUserPolicy":
        alerts.append(build_alert(
            record, "PutUserPolicy", "high", "An inline IAM user policy was created or modified."
        ))

    if event_name == "AttachUserPolicy" and contains_admin_access_policy(record):
        alerts.append(build_alert(
            record,
            "AttachUserPolicy_AdminAccess",
            "critical",
            "AdministratorAccess policy was attached to a user."
        ))

    if event_source == "cloudtrail.amazonaws.com" and event_name == "StopLogging":
        alerts.append(build_alert(
            record, "StopLogging", "critical", "CloudTrail logging was stopped."
        ))

    if event_source == "iam.amazonaws.com" and event_name == "CreateAccessKey":
        alerts.append(build_alert(
            record, "CreateAccessKey", "high", "A new IAM access key was created."
        ))

    if is_root_activity(record):
        alerts.append(build_alert(
            record, "RootUsage", "high", "Root account activity detected."
        ))

    if is_failed_console_login(record):
        alerts.append(build_alert(
            record, "FailedConsoleLogin", "medium", "Failed AWS console login detected."
        ))

    return alerts


def extract_records(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    if "awslogs" in event:
        compressed_payload = base64.b64decode(event["awslogs"]["data"])
        uncompressed_payload = gzip.decompress(compressed_payload)
        payload = json.loads(uncompressed_payload)

        records: List[Dict[str, Any]] = []
        for log_event in payload.get("logEvents", []):
            message = log_event.get("message", "")
            try:
                records.append(json.loads(message))
            except json.JSONDecodeError:
                logger.warning("Skipping non-JSON log event: %s", message)
        return records

    if "records" in event and isinstance(event["records"], list):
        return [r for r in event["records"] if isinstance(r, dict)]

    if "eventName" in event:
        return [event]

    raise ValueError(
        "Unsupported event format. Expected CloudWatch Logs subscription event "
        "or direct CloudTrail-style test event."
    )


def format_threshold_alert_message(grouped_alerts: Dict[str, Dict[str, Any]]) -> str:
    return json.dumps(
        {
            "threshold": ALERT_THRESHOLD,
            "message": f"Alerts fire only when a rule occurs more than {ALERT_THRESHOLD} times in a single Lambda batch.",
            "detections": grouped_alerts,
        },
        indent=2,
        default=str
    )


def format_guardduty_message(detail: Dict[str, Any]) -> str:
    payload = {
        "source": "GuardDuty",
        "severity": detail.get("severity"),
        "type": detail.get("type"),
        "title": detail.get("title"),
        "description": detail.get("description"),
        "region": detail.get("region"),
        "accountId": detail.get("accountId"),
        "resource": detail.get("resource"),
    }
    return json.dumps(payload, indent=2, default=str)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    logger.info("Received event: %s", json.dumps(event))

    # GuardDuty via EventBridge
    if event.get("source") == "aws.guardduty" and event.get("detail-type") == "GuardDuty Finding":
        detail = event.get("detail", {})
        publish_sns(
            subject="AWS Security Alert - GuardDuty Finding",
            message=format_guardduty_message(detail)
        )
        logger.info("Processed GuardDuty finding")
        return {
            "statusCode": 200,
            "mode": "guardduty",
            "finding_type": detail.get("type"),
            "severity": detail.get("severity"),
        }

    # CloudTrail / CloudWatch logs path
    records = extract_records(event)

    grouped_counts: Dict[str, int] = {}
    grouped_samples: Dict[str, Dict[str, Any]] = {}
    processed_detections = 0

    for record in records:
        detections = evaluate_record(record)

        for detection in detections:
            processed_detections += 1
            rule_name = detection["rule_name"]

            grouped_counts[rule_name] = grouped_counts.get(rule_name, 0) + 1

            if rule_name not in grouped_samples:
                grouped_samples[rule_name] = detection

    threshold_breaches: Dict[str, Dict[str, Any]] = {}

    for rule_name, count in grouped_counts.items():
        if count > ALERT_THRESHOLD:
            threshold_breaches[rule_name] = {
                "count": count,
                "sample_event": grouped_samples[rule_name],
            }

    if threshold_breaches:
        subject = f"AWS Security Alert - Threshold exceeded for {len(threshold_breaches)} rule(s)"
        message = format_threshold_alert_message(threshold_breaches)
        publish_sns(subject, message)
        logger.info("Published threshold alert to SNS")
    else:
        logger.info("No threshold breaches triggered")

    return {
        "statusCode": 200,
        "mode": "cloudtrail",
        "record_count": len(records),
        "processed_detections": processed_detections,
        "grouped_counts": grouped_counts,
        "threshold_breaches": threshold_breaches,
        "threshold": ALERT_THRESHOLD,
    }