---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-gcp-storage-bucket-deletion.html
---

# GCP Storage Bucket Deletion [prebuilt-rule-8-2-1-gcp-storage-bucket-deletion]

Identifies when a Google Cloud Platform (GCP) storage bucket is deleted. An adversary may delete a storage bucket in order to disrupt their target’s business operations.

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

* Elastic
* Cloud
* GCP
* Continuous Monitoring
* SecOps
* Monitoring

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1945]



## Rule query [_rule_query_2230]

```js
event.dataset:gcp.audit and event.action:"storage.buckets.delete"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)



