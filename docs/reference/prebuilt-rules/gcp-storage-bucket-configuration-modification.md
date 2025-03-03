---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/gcp-storage-bucket-configuration-modification.html
---

# GCP Storage Bucket Configuration Modification [gcp-storage-bucket-configuration-modification]

Identifies when the configuration is modified for a storage bucket in Google Cloud Platform (GCP). An adversary may modify the configuration of a storage bucket in order to weaken the security controls of their target’s environment.

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

* [https://cloud.google.com/storage/docs/key-terms#buckets](https://cloud.google.com/storage/docs/key-terms#buckets)

**Tags**:

* Domain: Cloud
* Data Source: GCP
* Data Source: Google Cloud Platform
* Use Case: Identity and Access Audit
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_370]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Storage Bucket Configuration Modification**

Google Cloud Platform (GCP) storage buckets are essential for storing and managing data in the cloud. Adversaries may alter bucket configurations to weaken security, enabling unauthorized access or data exfiltration. The detection rule monitors audit logs for successful configuration changes, flagging potential defense evasion attempts by identifying suspicious modifications to storage settings.

**Possible investigation steps**

* Review the audit logs for the specific event.action "storage.buckets.update" to identify the user or service account responsible for the configuration change.
* Examine the event.outcome field to confirm the success of the configuration modification and gather details on what specific changes were made to the storage bucket settings.
* Investigate the context of the change by checking the timestamp of the event to determine if it aligns with any known maintenance or deployment activities.
* Assess the permissions and roles of the user or service account involved in the modification to ensure they have the appropriate level of access and determine if any privilege escalation occurred.
* Cross-reference the modified bucket’s configuration with security policies and best practices to identify any potential security weaknesses introduced by the change.
* Check for any other recent suspicious activities or alerts related to the same user or service account to identify patterns of potentially malicious behavior.
* If unauthorized changes are suspected, initiate a response plan to revert the configuration to its previous state and strengthen access controls to prevent future incidents.

**False positive analysis**

* Routine administrative updates to storage bucket configurations by authorized personnel can trigger alerts. To manage this, maintain a list of known administrators and their typical activities, and create exceptions for these actions in the monitoring system.
* Automated processes or scripts that regularly update bucket configurations for maintenance or compliance purposes may cause false positives. Identify these processes and exclude their actions from triggering alerts by using service accounts or specific identifiers.
* Changes made by cloud management tools or third-party services integrated with GCP might be flagged. Review and whitelist these tools if they are verified and necessary for operations.
* Scheduled updates or configuration changes as part of regular security audits can appear suspicious. Document these schedules and incorporate them into the monitoring system to prevent unnecessary alerts.
* Temporary configuration changes for testing or development purposes might be misinterpreted as threats. Ensure that such activities are logged and communicated to the security team to adjust monitoring rules accordingly.

**Response and remediation**

* Immediately revoke any unauthorized access to the affected GCP storage bucket by reviewing and adjusting IAM policies to ensure only legitimate users have access.
* Conduct a thorough review of recent bucket configuration changes to identify any unauthorized modifications and revert them to their original secure state.
* Isolate the affected storage bucket from the network if suspicious activity is detected, to prevent further unauthorized access or data exfiltration.
* Notify the security operations team and relevant stakeholders about the incident for further investigation and to ensure coordinated response efforts.
* Implement additional logging and monitoring on the affected bucket to detect any further unauthorized access attempts or configuration changes.
* Review and update security policies and access controls for all GCP storage buckets to prevent similar incidents in the future.
* Escalate the incident to the cloud security team for a comprehensive analysis and to determine if further action is required, such as involving legal or compliance teams.


## Setup [_setup_234]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_402]

```js
event.dataset:gcp.audit and event.action:"storage.buckets.update" and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Cloud Compute Infrastructure
    * ID: T1578
    * Reference URL: [https://attack.mitre.org/techniques/T1578/](https://attack.mitre.org/techniques/T1578/)



