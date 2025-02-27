---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-gcp-pub-sub-subscription-deletion.html
---

# GCP Pub/Sub Subscription Deletion [prebuilt-rule-1-0-2-gcp-pub-sub-subscription-deletion]

Identifies the deletion of a subscription in Google Cloud Platform (GCP). In GCP, the publisher-subscriber relationship (Pub/Sub) is an asynchronous messaging service that decouples event-producing and event-processing services. A subscription is a named resource representing the stream of messages to be delivered to the subscribing application.

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

* Elastic
* Cloud
* GCP
* Continuous Monitoring
* SecOps
* Log Auditing

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1432]

## Config

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1663]

```js
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Subscriber.DeleteSubscription and event.outcome:success
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



