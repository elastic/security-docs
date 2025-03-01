---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-pub-sub-subscription-creation.html
---

# GCP Pub/Sub Subscription Creation [prebuilt-rule-8-17-4-gcp-pub-sub-subscription-creation]

Identifies the creation of a subscription in Google Cloud Platform (GCP). In GCP, the publisher-subscriber relationship (Pub/Sub) is an asynchronous messaging service that decouples event-producing and event-processing services. A subscription is a named resource representing the stream of messages to be delivered to the subscribing application.

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
* Tactic: Collection
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4158]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Pub/Sub Subscription Creation**

Google Cloud Pub/Sub is a messaging service that enables asynchronous communication between applications by decoupling event producers and consumers. Adversaries might exploit this by creating unauthorized subscriptions to intercept or exfiltrate sensitive data streams. The detection rule monitors audit logs for successful subscription creation events, helping identify potential misuse by flagging unexpected or suspicious activity.

**Possible investigation steps**

* Review the audit log entry associated with the alert to identify the user or service account responsible for the subscription creation by examining the `event.dataset` and `event.action` fields.
* Verify the legitimacy of the subscription by checking the associated project and topic details to ensure they align with expected configurations and business needs.
* Investigate the history of the user or service account involved in the subscription creation to identify any unusual or unauthorized activities, focusing on recent changes or access patterns.
* Assess the permissions and roles assigned to the user or service account to determine if they have the necessary privileges for subscription creation and whether these permissions are appropriate.
* Consult with relevant stakeholders or application owners to confirm whether the subscription creation was authorized and necessary for operational purposes.

**False positive analysis**

* Routine subscription creation by automated deployment tools or scripts can trigger false positives. Identify and whitelist these tools by excluding their service accounts from the detection rule.
* Development and testing environments often create and delete subscriptions frequently. Exclude these environments by filtering out specific project IDs associated with non-production use.
* Scheduled maintenance or updates might involve creating new subscriptions temporarily. Coordinate with the operations team to understand regular maintenance schedules and adjust the rule to ignore these activities during known maintenance windows.
* Internal monitoring or logging services that create subscriptions for legitimate data collection purposes can be excluded by identifying their specific patterns or naming conventions and adding them to an exception list.

**Response and remediation**

* Immediately review the audit logs to confirm the unauthorized subscription creation and identify the source, including the user or service account responsible for the action.
* Revoke access for the identified user or service account to prevent further unauthorized actions. Ensure that the principle of least privilege is enforced.
* Delete the unauthorized subscription to stop any potential data interception or exfiltration.
* Conduct a thorough review of all existing subscriptions to ensure no other unauthorized subscriptions exist.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Implement additional monitoring and alerting for subscription creation events to detect similar activities in the future.
* If applicable, report the incident to Google Cloud support for further assistance and to understand if there are any broader implications or vulnerabilities.


## Setup [_setup_1028]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5167]

```js
event.dataset:gcp.audit and event.action:google.pubsub.v*.Subscriber.CreateSubscription and event.outcome:success
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



