---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-logging-sink-deletion.html
---

# GCP Logging Sink Deletion [prebuilt-rule-8-17-4-gcp-logging-sink-deletion]

Identifies a Logging sink deletion in Google Cloud Platform (GCP). Every time a log entry arrives, Logging compares the log entry to the sinks in that resource. Each sink whose filter matches the log entry writes a copy of the log entry to the sink’s export destination. An adversary may delete a Logging sink to evade detection.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/logging/docs/export](https://cloud.google.com/logging/docs/export)

**Tags**:

* Domain: Cloud
* Data Source: GCP
* Data Source: Google Cloud Platform
* Use Case: Log Auditing
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4164]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Logging Sink Deletion**

In GCP, logging sinks are crucial for exporting log entries to designated destinations for analysis and storage. Adversaries may delete these sinks to prevent logs from being exported, thereby evading detection. The detection rule identifies successful deletion events by monitoring specific audit logs, helping security teams quickly respond to potential defense evasion tactics.

**Possible investigation steps**

* Review the audit logs for the specific event.action: google.logging.v*.ConfigServiceV*.DeleteSink to identify the user or service account responsible for the deletion.
* Check the event.dataset:gcp.audit logs for any preceding or subsequent suspicious activities by the same user or service account, which might indicate a pattern of malicious behavior.
* Investigate the event.outcome:success to confirm the deletion was successful and determine the impact on log monitoring and export capabilities.
* Assess the context and timing of the deletion event to see if it coincides with other security alerts or incidents, which might suggest a coordinated attack.
* Verify the permissions and roles assigned to the user or service account involved in the deletion to ensure they align with the principle of least privilege and identify any potential misconfigurations.

**False positive analysis**

* Routine maintenance or configuration changes by authorized personnel can trigger false positives. To manage this, create exceptions for known maintenance windows or specific user accounts responsible for these tasks.
* Automated scripts or tools used for managing logging configurations might inadvertently delete sinks as part of their operation. Identify these scripts and exclude their actions from triggering alerts by using specific identifiers or service accounts.
* Changes in project ownership or restructuring within the organization can lead to legitimate sink deletions. Document these organizational changes and adjust the monitoring rules to account for them, ensuring that alerts are only generated for unexpected deletions.
* Test environments often undergo frequent changes, including sink deletions, which can result in false positives. Implement separate monitoring rules or exceptions for test environments to reduce noise in alerting.

**Response and remediation**

* Immediately revoke access to the affected GCP project for any suspicious or unauthorized users identified in the audit logs to prevent further malicious activity.
* Restore the deleted logging sink by recreating it with the original configuration to ensure that log entries are once again exported to the designated destination.
* Conduct a thorough review of recent log entries and audit logs to identify any other unauthorized changes or suspicious activities that may have occurred around the time of the sink deletion.
* Implement additional monitoring and alerting for any future attempts to delete logging sinks, focusing on the specific event action and outcome fields used in the detection query.
* Escalate the incident to the security operations team for further investigation and to determine if the sink deletion is part of a larger attack campaign.
* Review and update access controls and permissions for logging sink management to ensure that only authorized personnel have the ability to modify or delete sinks.
* Consider enabling additional security features such as VPC Service Controls or Organization Policy constraints to provide an extra layer of protection against unauthorized modifications to logging configurations.


## Setup [_setup_1034]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5173]

```js
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.DeleteSink and event.outcome:success
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



