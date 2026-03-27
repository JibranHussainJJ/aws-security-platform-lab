# AWS Cloud Security Monitoring + Kubernetes Runtime Security

This project demonstrates a cloud-native security monitoring pipeline using AWS and Kubernetes.


## Architecture

AWS-based security monitoring pipeline:

CloudTrail → CloudWatch Logs → Lambda → SNS → Email Alerts

### Components

- aws/lambda → Detection engine
- aws/cloudwatch → Metrics and alarms
- aws/sns → Alert delivery


## Progress
- [x] CloudTrail setup
- [x] CloudWatch logs
- [x] Metric filters
- [ ] GuardDuty
- [ ] Falco
