---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-gcp-pub-sub-subscription-creation.html
---

# GCP Pub/Sub Subscription Creation [prebuilt-rule-8-3-3-gcp-pub-sub-subscription-creation]

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

* Elastic
* Cloud
* GCP
* Continuous Monitoring
* SecOps
* Log Auditing

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2911]



## Rule query [_rule_query_3332]

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



