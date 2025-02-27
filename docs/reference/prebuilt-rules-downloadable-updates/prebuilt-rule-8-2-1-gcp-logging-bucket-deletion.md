---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-gcp-logging-bucket-deletion.html
---

# GCP Logging Bucket Deletion [prebuilt-rule-8-2-1-gcp-logging-bucket-deletion]

Identifies a Logging bucket deletion in Google Cloud Platform (GCP). Log buckets are containers that store and organize log data. A deleted bucket stays in a pending state for 7 days, and Logging continues to route logs to the bucket during that time. To stop routing logs to a deleted bucket, you can delete the log sinks that have the bucket as their destination, or modify the filter for the sinks to stop it from routing logs to the deleted bucket. An adversary may delete a log bucket to evade detection.

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

* [https://cloud.google.com/logging/docs/buckets](https://cloud.google.com/logging/docs/buckets)
* [https://cloud.google.com/logging/docs/storage](https://cloud.google.com/logging/docs/storage)

**Tags**:

* Elastic
* Cloud
* GCP
* Continuous Monitoring
* SecOps
* Log Auditing

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1932]



## Rule query [_rule_query_2217]

```js
event.dataset:gcp.audit and event.action:google.logging.v*.ConfigServiceV*.DeleteBucket and event.outcome:success
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



