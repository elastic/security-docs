---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/sns-topic-message-publish-by-rare-user.html
---

# SNS Topic Message Publish by Rare User [sns-topic-message-publish-by-rare-user]

Identifies when an SNS topic message is published by a rare user in AWS. Adversaries may publish messages to SNS topics for phishing campaigns, data exfiltration, or lateral movement within the AWS environment. SNS topics are used to send notifications and messages to subscribed endpoints such as applications, devices or email addresses, making them a valuable target for adversaries to distribute malicious content or exfiltrate sensitive data. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule that only flags when this behavior is observed for the first time on a user in the last 14 days.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/sns/latest/api/API_Publish.html](https://docs.aws.amazon.com/sns/latest/api/API_Publish.md)
* [https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/](https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS SNS
* Use Case: Threat Detection
* Resources: Investigation Guide
* Tactic: Lateral Movement
* Tactic: Exfiltration

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_892]

**Triage and Analysis**

**Investigating SNS Topic Message Publish by Rare User**

This rule identifies when a message is published to an SNS topic by a user who has rarely or never published messages before. This activity could indicate adversarial actions, such as using SNS topics for phishing campaigns, data exfiltration, or lateral movement within an AWS environment.

**Possible Investigation Steps**

* ***Identify the Actor and Resource***:
* ***User Identity and Role***: Examine the `aws.cloudtrail.user_identity.arn` to identify the user or role responsible for publishing the SNS message. Verify whether this actor is authorized to publish messages to SNS topics. This user is considered "rare" since they have not published messages to SNS topics in the last 14 days.
* ***Access Key Details***: Review the `aws.cloudtrail.user_identity.access_key_id` to determine if the access key used is valid or compromised.
* ***SNS Topic ARN***: Analyze `aws.cloudtrail.resources.arn` to confirm whether the SNS topic is critical, sensitive, or used for authorized purposes.
* ***Evaluate the Context of the SNS Message***:
* ***Published Message Details***: AWS redacts the message content in CloudTrail logs, but you can view the message ID, subject, and other metadata. Investigate the message details for any indicators of malicious content.
* ***Message Recipients***: Investigate the subscriptions associated with the SNS topic to identify if messages were sent to unauthorized or unexpected recipients.
* ***Analyze Source Information***:
* ***Source IP Address***: Examine the `source.ip` field to identify the origin of the activity. Unusual IP addresses or geolocations may indicate unauthorized access.
* ***User Agent***: Review `user_agent.original` to determine the tool or client used for publishing the SNS message. Automated tools or unexpected clients (e.g., `Boto3` from an unknown host) may signify misuse.
* ***Review Historical Activity***:
* ***Actor’s Past Behavior***: Identify whether the user has published messages to SNS topics before. Review similar past events for context.
* ***Frequency and Patterns***: Examine the time and frequency of messages published by the same user or to the same SNS topic to detect anomalies.
* ***Correlate with Other Events***:
* ***IAM or CloudTrail Events***: Look for events such as `AssumeRole`, `CreateAccessKey`, or other API actions associated with the same user ARN.
* ***Unusual IAM Role Activity***: Determine if the actor has assumed roles or performed administrative tasks atypical for their role.

**False Positive Analysis**

* ***Routine Operational Use***:
* Confirm if the publishing activity aligns with standard operational tasks or automation scripts.
* Validate whether new or rare users were recently granted permissions for publishing messages to SNS topics.
* ***Testing or Monitoring Scripts***:
* Automated testing or monitoring tools may trigger this rule if configured to publish messages to SNS topics.

**Response and Remediation**

* ***Immediate Action***:
* If unauthorized activity is confirmed, disable the access key or IAM role associated with the user.
* Restrict or remove permissions from the SNS topic to prevent further misuse.
* ***Review Policies and Subscriptions***:
* Audit the IAM policies tied to the user and SNS topic to ensure appropriate permissions.
* Validate the subscriptions of the SNS topic to confirm all endpoints are authorized.
* ***Enhance Monitoring and Alerting***:
* Set up additional logging or alerting for SNS publish actions, especially from rare or unknown users.
* Monitor for similar actions across other SNS topics within the environment.
* ***Conduct a Root Cause Analysis***:
* Investigate how the user or role gained access to publish messages to the SNS topic.
* Determine if other AWS resources or services have been affected.

**Additional Information**

For more information on SNS topic management and securing AWS resources, refer to: - [AWS SNS Publish API Documentation](https://docs.aws.amazon.com/sns/latest/api/API_Publish.md) - [AWS CloudTrail Documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.md)


## Rule query [_rule_query_948]

```js
event.dataset:"aws.cloudtrail"
    and event.provider:"sns.amazonaws.com"
    and event.action:"Publish"
    and event.outcome:"success"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Internal Spearphishing
    * ID: T1534
    * Reference URL: [https://attack.mitre.org/techniques/T1534/](https://attack.mitre.org/techniques/T1534/)

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Exfiltration Over Web Service
    * ID: T1567
    * Reference URL: [https://attack.mitre.org/techniques/T1567/](https://attack.mitre.org/techniques/T1567/)



