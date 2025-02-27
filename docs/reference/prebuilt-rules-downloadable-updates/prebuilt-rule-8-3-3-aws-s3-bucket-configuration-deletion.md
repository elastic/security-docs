---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-aws-s3-bucket-configuration-deletion.html
---

# AWS S3 Bucket Configuration Deletion [prebuilt-rule-8-3-3-aws-s3-bucket-configuration-deletion]

Identifies the deletion of various Amazon Simple Storage Service (S3) bucket configuration components.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketPolicy.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketPolicy.md)
* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketReplication.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketReplication.md)
* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.md)
* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketEncryption.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketEncryption.md)
* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Asset Visibility

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2887]



## Rule query [_rule_query_3312]

```js
event.dataset:aws.cloudtrail and event.provider:s3.amazonaws.com and
  event.action:(DeleteBucketPolicy or DeleteBucketReplication or DeleteBucketCors or
                DeleteBucketEncryption or DeleteBucketLifecycle)
  and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)



