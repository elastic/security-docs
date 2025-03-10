---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/gcp-pub-sub-topic-creation.html
---

# GCP Pub/Sub Topic Creation [gcp-pub-sub-topic-creation]

Identifies the creation of a topic in Google Cloud Platform (GCP). In GCP, the publisher-subscriber relationship (Pub/Sub) is an asynchronous messaging service that decouples event-producing and event-processing services. A topic is used to forward messages from publishers to subscribers.

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

* [https://cloud.google.com/pubsub/docs/admin](https://cloud.google.com/pubsub/docs/admin)

**Tags**:

* Domain: Cloud
* Data Source: GCP
* Data Source: Google Cloud Platform
* Use Case: Log Auditing
* Tactic: Collection
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_364]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Pub/Sub Topic Creation**

Google Cloud Pub/Sub is a messaging service that enables asynchronous communication between independent applications. It uses topics to route messages from publishers to subscribers. Adversaries might exploit this by creating unauthorized topics to exfiltrate data or disrupt services. The detection rule monitors successful topic creation events, helping identify potential misuse by flagging unexpected or suspicious activity.

**Possible investigation steps**

* Review the event details to confirm the presence of the event.action field with the value google.pubsub.v*.Publisher.CreateTopic and ensure the event.outcome is success.
* Identify the user or service account associated with the topic creation by examining the actor information in the event logs.
* Check the project and resource details to determine the context and environment where the topic was created, including the project ID and resource name.
* Investigate the purpose and necessity of the newly created topic by consulting with relevant stakeholders or reviewing documentation related to the project.
* Analyze historical logs to identify any unusual patterns or anomalies in topic creation activities by the same user or within the same project.
* Assess the permissions and roles assigned to the user or service account to ensure they align with the principle of least privilege.
* If suspicious activity is confirmed, consider implementing additional monitoring or access controls to prevent unauthorized topic creation in the future.

**False positive analysis**

* Routine topic creation by automated processes or scripts can trigger false positives. Identify and document these processes to create exceptions in the monitoring system.
* Development and testing environments often involve frequent topic creation. Exclude these environments from alerts by using environment-specific tags or labels.
* Scheduled maintenance or updates by cloud administrators may result in legitimate topic creation. Coordinate with the operations team to whitelist these activities during known maintenance windows.
* Third-party integrations or services that rely on Pub/Sub for communication might create topics as part of their normal operation. Review and approve these integrations to prevent unnecessary alerts.
* Internal applications with dynamic topic creation as part of their workflow should be assessed and, if deemed non-threatening, added to an exception list to reduce noise.

**Response and remediation**

* Immediately review the audit logs to confirm the unauthorized creation of the Pub/Sub topic and identify the user or service account responsible for the action.
* Revoke or limit permissions for the identified user or service account to prevent further unauthorized actions, ensuring that only necessary permissions are granted.
* Delete the unauthorized Pub/Sub topic to prevent any potential data exfiltration or disruption of services.
* Conduct a thorough review of other Pub/Sub topics and related resources to ensure no additional unauthorized topics have been created.
* Notify the security team and relevant stakeholders about the incident for further investigation and to assess potential impacts on the organization.
* Implement additional monitoring and alerting for Pub/Sub topic creation events to detect and respond to similar threats more quickly in the future.
* Consider enabling organization-wide policies that restrict who can create Pub/Sub topics to reduce the risk of unauthorized actions.


## Setup [_setup_228]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_396]

```js
event.dataset:gcp.audit and event.action:google.pubsub.v*.Publisher.CreateTopic and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Cloud Storage
    * ID: T1530
    * Reference URL: [https://attack.mitre.org/techniques/T1530/](https://attack.mitre.org/techniques/T1530/)



