---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-sqs-queue-purge.html
---

# AWS SQS Queue Purge [prebuilt-rule-8-17-4-aws-sqs-queue-purge]

Identifies when an AWS Simple Queue Service (SQS) queue is purged. Adversaries may purge SQS queues to disrupt operations, delete messages, or impair monitoring and alerting mechanisms. This action can be used to evade detection and cover tracks by removing evidence of malicious activities.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_PurgeQueue.html](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_PurgeQueue.html)
* [https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/](https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS SQS
* Use Case: Threat Detection
* Use Case: Log Auditing
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3997]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS SQS Queue Purge**

AWS Simple Queue Service (SQS) is a managed message queuing service that enables decoupling and scaling of microservices, distributed systems, and serverless applications. Adversaries may exploit SQS by purging queues to erase messages, disrupt operations, or hinder monitoring. The detection rule identifies successful purge actions in AWS CloudTrail logs, signaling potential defense evasion attempts by adversaries.

**Possible investigation steps**

* Review the AWS CloudTrail logs for the specific event.provider "sqs.amazonaws.com" and event.action "PurgeQueue" to identify the time and source of the purge action.
* Identify the IAM user or role associated with the purge action by examining the user identity information in the CloudTrail logs to determine if the action was authorized or potentially malicious.
* Check the event.outcome "success" to confirm that the purge action was completed successfully and assess the impact on the queue’s message data.
* Investigate the context around the purge event by reviewing preceding and subsequent CloudTrail logs to identify any related or suspicious activities, such as unauthorized access attempts or changes to IAM policies.
* Assess the potential impact on operations and monitoring by determining which messages were purged and if they contained critical or sensitive information.
* Evaluate the necessity of implementing additional security measures, such as stricter IAM policies or enhanced logging and alerting, to prevent unauthorized queue purges in the future.

**False positive analysis**

* Routine maintenance activities by administrators may trigger the purge action. To handle this, identify and whitelist known maintenance operations or specific IAM roles used by trusted personnel.
* Automated scripts or applications that regularly purge queues as part of their normal operation can cause false positives. Review and document these processes, then create exceptions for these specific actions in your monitoring system.
* Testing environments where queues are frequently purged for development purposes can lead to alerts. Exclude these environments from the rule by filtering based on environment tags or specific queue names.
* Scheduled tasks that include queue purging as a cleanup mechanism might be misinterpreted as malicious. Ensure these tasks are logged and approved, and adjust the detection rule to ignore these scheduled events.
* Third-party integrations that manage SQS queues and perform purges as part of their functionality should be assessed. Verify the legitimacy of these integrations and exclude their actions from triggering alerts.

**Response and remediation**

* Immediately isolate the affected AWS SQS queue to prevent further unauthorized purging or access. This can be done by modifying the queue’s access policies to restrict permissions temporarily.
* Review AWS CloudTrail logs to identify the source of the purge action, including the IAM user or role responsible, and assess whether the action was authorized or part of a larger malicious activity.
* Revoke or adjust permissions for the identified IAM user or role to prevent further unauthorized actions. Ensure that only necessary permissions are granted following the principle of least privilege.
* Restore any critical messages or data that were purged, if possible, from backups or other data recovery solutions to minimize operational disruption.
* Notify the security team and relevant stakeholders about the incident, providing details of the purge action and any identified malicious activity, to ensure coordinated response efforts.
* Conduct a thorough review of IAM policies and access controls related to SQS to identify and remediate any potential security gaps that could be exploited in the future.
* Enhance monitoring and alerting mechanisms for AWS SQS by implementing additional logging and anomaly detection to quickly identify and respond to similar threats in the future.

**Triage and Analysis**

**Investigating AWS SQS Queue Purge**

This rule detects when an AWS SQS queue is purged, an action that adversaries may use to disrupt operations, delete messages, or impair monitoring and alerting mechanisms. Purging an SQS queue removes all messages, which could be used as a tactic to evade detection by deleting evidence of malicious activity or to disrupt legitimate workflows.

**Possible Investigation Steps**

* ***Identify the Actor and Resource***:
* ***User Identity and Permissions***: Review the field `aws.cloudtrail.user_identity.arn` to identify the IAM user or role responsible for the purge. Validate their permissions and determine if this action aligns with their typical responsibilities.
* ***SQS Queue Details***: Examine `aws.cloudtrail.resources.arn` and `aws.cloudtrail.flattened.request_parameters.queueUrl` to identify the specific SQS queue that was purged. Check its purpose, associated workflows, and whether it handles sensitive or critical messages.
* ***Evaluate the Context and Purpose of the Purge***:
* ***Time and Frequency***: Check the timestamp (`@timestamp`) to determine when the purge occurred and whether similar events have occurred recently. Frequent or repeated purges may indicate a larger issue or ongoing malicious activity.
* ***Legitimacy of the Action***: Consult with the owner or administrator of the affected queue to verify if the purge was intentional or authorized.
* ***Analyze for Potential Indicators of Malicious Activity***:
* ***Source IP and Geographic Location***: Review `source.ip` and `source.geo` to identify the origin of the request. Anomalies, such as unexpected locations, may indicate compromise.
* ***User Agent and Tooling***: Check `user_agent.original` to confirm the tool used to perform the purge. The use of unexpected or automated tooling may raise suspicion.
* ***Cross-Reference Related Activity***:
* ***Recent IAM Events***: Search for related IAM or security-related events tied to the same actor, such as `CreateAccessKey`, `AssumeRole`, or `UpdateRolePolicy`, which could indicate privilege escalation or preparation for malicious actions.
* ***Other SQS Activity***: Look for additional activity involving the same SQS queue, such as `SendMessage`, `ReceiveMessage`, or `DeleteQueue`, to identify further signs of unauthorized usage.

**False Positive Analysis**

* ***Legitimate Administrative Activity***: Administrators may purge SQS queues as part of maintenance or cleanup processes. Validate whether the action was part of an approved operation.
* ***Automation or Testing***: Automation tools or testing processes may perform queue purges as part of their workflow. Verify if the action aligns with known automated tasks or test scenarios.

**Response and Remediation**

* ***Immediate Actions***:
* ***Restrict Access***: If the action appears unauthorized, immediately revoke access for the actor responsible for the purge and investigate potential credential compromise.
* ***Restore Data***: If the purged queue contained critical or sensitive messages, attempt to restore them from backups if available.
* ***Preventative Measures***:
* ***Enhance Monitoring***: Enable additional monitoring for SQS-related activity to detect unusual patterns, such as frequent purges or changes to queue configurations.
* ***Audit Permissions***: Review and restrict IAM permissions for SQS to ensure only authorized users or roles can perform sensitive actions like `PurgeQueue`.
* ***Policy Updates***:
* ***Apply Least Privilege***: Adjust IAM policies to enforce the principle of least privilege, ensuring that only necessary permissions are granted. Review the policy assigned to the SQS queue as well to prevent unauthorized purges.
* ***MFA Enforcement***: Require Multi-Factor Authentication (MFA) for all users with access to sensitive AWS resources.

**Additional Information**

For further guidance on AWS SQS operations and best practices, refer to: - [AWS SQS PurgeQueue API Documentation](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_PurgeQueue.html)


## Rule query [_rule_query_5014]

```js
event.dataset:"aws.cloudtrail"
    and event.provider:"sqs.amazonaws.com"
    and event.action:"PurgeQueue"
    and event.outcome:"success"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Cloud Logs
    * ID: T1562.008
    * Reference URL: [https://attack.mitre.org/techniques/T1562/008/](https://attack.mitre.org/techniques/T1562/008/)



