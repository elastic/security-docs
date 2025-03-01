---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-pub-sub-topic-deletion.html
---

# GCP Pub/Sub Topic Deletion [prebuilt-rule-8-17-4-gcp-pub-sub-topic-deletion]

Identifies the deletion of a topic in Google Cloud Platform (GCP). In GCP, the publisher-subscriber relationship (Pub/Sub) is an asynchronous messaging service that decouples event-producing and event-processing services. A publisher application creates and sends messages to a topic. Deleting a topic can interrupt message flow in the Pub/Sub pipeline.

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

* [https://cloud.google.com/pubsub/docs/overview](https://cloud.google.com/pubsub/docs/overview)

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

## Investigation guide [_investigation_guide_4166]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Pub/Sub Topic Deletion**

Google Cloud Platform’s Pub/Sub service facilitates asynchronous messaging, allowing applications to communicate by publishing messages to topics. Deleting a topic can disrupt this communication, potentially as a tactic for defense evasion. Adversaries might exploit this by deleting topics to impair defenses or hide their tracks. The detection rule monitors audit logs for successful topic deletions, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the audit logs for the specific event.action: google.pubsub.v*.Publisher.DeleteTopic to identify the exact time and user or service account responsible for the deletion.
* Investigate the event.dataset:gcp.audit logs around the same timeframe to identify any related activities or anomalies that might indicate malicious intent or unauthorized access.
* Check the event.outcome:success to confirm the deletion was completed successfully and correlate it with any reported service disruptions or issues in the affected applications.
* Assess the permissions and roles of the user or service account involved in the deletion to determine if they had legitimate access and reasons for performing this action.
* Contact the user or team responsible for the deletion to verify if the action was intentional and authorized, and gather any additional context or justification for the deletion.
* Review any recent changes in IAM policies or configurations that might have inadvertently allowed unauthorized topic deletions.

**False positive analysis**

* Routine maintenance or updates by administrators can lead to legitimate topic deletions. To manage this, create exceptions for known maintenance periods or specific admin accounts.
* Automated scripts or tools that manage Pub/Sub topics might delete topics as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by using service account identifiers.
* Development and testing environments often involve frequent topic creation and deletion. Exclude these environments from monitoring by filtering based on project IDs or environment tags.
* Scheduled clean-up jobs that remove unused or temporary topics can trigger false positives. Document these jobs and adjust the detection rule to ignore deletions occurring during their execution times.
* Changes in project requirements or architecture might necessitate topic deletions. Ensure that such changes are communicated and documented, allowing for temporary exceptions during the transition period.

**Response and remediation**

* Immediately assess the impact of the topic deletion by identifying affected services and applications that rely on the deleted topic for message flow.
* Restore the deleted topic from backup if available, or recreate the topic with the same configuration to resume normal operations.
* Notify relevant stakeholders, including application owners and security teams, about the incident and potential service disruptions.
* Review access logs and permissions to identify unauthorized access or privilege escalation that may have led to the topic deletion.
* Implement stricter access controls and permissions for Pub/Sub topics to prevent unauthorized deletions in the future.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if the deletion is part of a larger attack pattern.
* Enhance monitoring and alerting for Pub/Sub topic deletions to ensure rapid detection and response to similar incidents in the future.


## Setup [_setup_1036]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5175]

```js
event.dataset:gcp.audit and event.action:google.pubsub.v*.Publisher.DeleteTopic and event.outcome:success
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



