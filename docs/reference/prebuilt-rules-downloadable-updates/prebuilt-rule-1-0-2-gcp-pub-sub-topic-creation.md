---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-gcp-pub-sub-topic-creation.html
---

# GCP Pub/Sub Topic Creation [prebuilt-rule-1-0-2-gcp-pub-sub-topic-creation]

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

## Investigation guide [_investigation_guide_1429]

## Config

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

## Rule query [_rule_query_1660]

```js
event.dataset:(googlecloud.audit or gcp.audit) and event.action:google.pubsub.v*.Publisher.CreateTopic and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Cloud Storage Object
    * ID: T1530
    * Reference URL: [https://attack.mitre.org/techniques/T1530/](https://attack.mitre.org/techniques/T1530/)



