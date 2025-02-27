---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-logging-sink-modification.html
---

# GCP Logging Sink Modification [prebuilt-rule-8-17-4-gcp-logging-sink-modification]

Identifies a modification to a Logging sink in Google Cloud Platform (GCP). Logging compares the log entry to the sinks in that resource. Each sink whose filter matches the log entry writes a copy of the log entry to the sink’s export destination. An adversary may update a Logging sink to exfiltrate logs to a different export destination.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/logging/docs/export#how_sinks_work](https://cloud.google.com/logging/docs/export#how_sinks_work)

**Tags**:

* Domain: Cloud
* Data Source: GCP
* Data Source: Google Cloud Platform
* Use Case: Log Auditing
* Tactic: Exfiltration
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4172]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Logging Sink Modification**

In GCP, logging sinks are used to route log entries to specified destinations for storage or analysis. Adversaries may exploit this by altering sink configurations to redirect logs to unauthorized locations, facilitating data exfiltration. The detection rule identifies successful modifications to logging sinks, signaling potential misuse by monitoring specific audit events related to sink updates.

**Possible investigation steps**

* Review the event details for the specific `event.action` field value `google.logging.v*.ConfigServiceV*.UpdateSink` to confirm the type of modification made to the logging sink.
* Check the `event.outcome` field to ensure the modification was successful, as indicated by the value `success`.
* Identify the user or service account responsible for the modification by examining the `actor` or `principalEmail` fields in the audit log.
* Investigate the `resource` field to determine which logging sink was modified and assess its intended purpose and usual configuration.
* Analyze the `destination` field in the sink configuration to verify if the new export destination is authorized and aligns with organizational policies.
* Review historical logs for any previous modifications to the same logging sink to identify patterns or repeated unauthorized changes.
* Correlate this event with other security alerts or anomalies in the environment to assess if this modification is part of a broader attack or data exfiltration attempt.

**False positive analysis**

* Routine updates to logging sinks by authorized personnel can trigger alerts. To manage this, maintain a list of known and trusted users who regularly perform these updates and create exceptions for their actions.
* Automated processes or scripts that update logging sinks as part of regular maintenance or deployment activities may cause false positives. Identify these processes and exclude their specific actions from triggering alerts.
* Changes to logging sinks during scheduled maintenance windows can be mistaken for unauthorized modifications. Define and exclude these time periods from monitoring to reduce unnecessary alerts.
* Integration with third-party tools that require sink modifications for functionality might generate false positives. Document these integrations and adjust the detection rule to account for their expected behavior.
* Frequent changes in a dynamic environment, such as development or testing environments, can lead to false positives. Consider applying the rule more stringently in production environments while relaxing it in non-production settings.

**Response and remediation**

* Immediately review the audit logs to confirm the unauthorized modification of the logging sink and identify the source of the change, including the user account and IP address involved.
* Revert the logging sink configuration to its original state to ensure logs are directed to the intended, secure destination.
* Temporarily disable or restrict access to the user account or service account that made the unauthorized change to prevent further unauthorized actions.
* Notify the security team and relevant stakeholders about the incident, providing details of the unauthorized modification and initial containment actions taken.
* Conduct a thorough investigation to determine if any data was exfiltrated and assess the potential impact on the organization.
* Implement additional monitoring and alerting for changes to logging sink configurations to detect similar unauthorized modifications in the future.
* Review and strengthen access controls and permissions related to logging sink configurations to prevent unauthorized modifications, ensuring that only authorized personnel have the necessary permissions.


## Setup [_setup_1042]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5181]

```js
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.UpdateSink and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Transfer Data to Cloud Account
    * ID: T1537
    * Reference URL: [https://attack.mitre.org/techniques/T1537/](https://attack.mitre.org/techniques/T1537/)



