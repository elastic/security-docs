---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-gcp-storage-bucket-configuration-modification.html
---

# GCP Storage Bucket Configuration Modification [prebuilt-rule-8-2-1-gcp-storage-bucket-configuration-modification]

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

* Elastic
* Cloud
* GCP
* Continuous Monitoring
* SecOps
* Identity and Access
* Defense Evasion

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1936]



## Rule query [_rule_query_2221]

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



