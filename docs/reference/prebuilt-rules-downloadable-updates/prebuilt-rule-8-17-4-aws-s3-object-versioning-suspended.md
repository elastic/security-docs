---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-s3-object-versioning-suspended.html
---

# AWS S3 Object Versioning Suspended [prebuilt-rule-8-17-4-aws-s3-object-versioning-suspended]

Identifies when object versioning is suspended for an Amazon S3 bucket. Object versioning allows for multiple versions of an object to exist in the same bucket. This allows for easy recovery of deleted or overwritten objects. When object versioning is suspended for a bucket, it could indicate an adversary’s attempt to inhibit system recovery following malicious activity. Additionally, when versioning is suspended, buckets can then be deleted.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html/](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.md/)
* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketVersioning.html/](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketVersioning.md/)
* [https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-s3-post-exploitation/](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-s3-post-exploitation/)
* [https://www.invictus-ir.com/news/ransomware-in-the-cloud/](https://www.invictus-ir.com/news/ransomware-in-the-cloud/)
* [https://rhinosecuritylabs.com/aws/s3-ransomware-part-2-prevention-and-defense/](https://rhinosecuritylabs.com/aws/s3-ransomware-part-2-prevention-and-defense/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS S3
* Use Case: Threat Detection
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4032]

**Triage and analysis**

**Investigating AWS S3 Object Versioning Suspended**

This rule detects when object versioning for an S3 bucket is suspended. Adversaries with access to a misconfigured S3 bucket may disable object versioning prior to replacing or deleting S3 objects, inhibiting recovery initiatives. This rule uses [EQL](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-eql-rule) to look for use of the `PutBucketVersioning` operation where the `request_parameters` include `Status=Suspended`.

**Possible Investigation Steps:**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who performed the action. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Analyze the Source of the Request***: Investigate the `source.ip` and `source.geo` fields to determine the geographical origin of the request. An external or unexpected location might indicate compromised credentials or unauthorized access.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this action to see if the same actor or IP address engaged in other potentially suspicious activities.
* ***Check for Object Deletion or Access***: Look for `DeleteObject`, `DeleteObjects`, or `GetObject` API calls to the same S3 bucket that may indicate the adversary accessing and destroying objects including older object versions.
* ***Interview Relevant Personnel***: If the copy event was initiated by a user, verify the intent and authorization for this action with the person or team responsible for managing S3 buckets.

**False Positive Analysis:**

* ***Legitimate Administrative Actions***: Confirm if the action aligns with legitimate administrative tasks documented in change management systems.
* ***Consistency Check***: Compare the action against historical data of similar activities performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.

**Response and Remediation:**

* ***Immediate Review***: If the activity was unauthorized, search for replaced or deleted objects and review the bucket’s access logs for any suspicious activity.
* ***Educate and Train***: Provide additional training to users with administrative rights on the importance of security best practices concerning S3 bucket management and the risks of ransomware.
* ***Audit S3 Bucket Policies and Permissions***: Conduct a comprehensive audit of all S3 bucket policies and associated permissions to ensure they adhere to the principle of least privilege.
* ***Incident Response***: If there’s an indication of malicious intent or a security breach, initiate the incident response protocol to mitigate any damage and prevent future occurrences.

**Additional Information:**

For further guidance on managing S3 bucket security and protecting against ransomware, refer to the [AWS S3 documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.md) and AWS best practices for security. Additionally, consult the following resources for specific details on S3 ransomware protection: - [ERMETIC REPORT - AWS S3 Ransomware Exposure in the Wild](https://s3.amazonaws.com/bizzabo.file.upload/PtZzA0eFQwV2RA5ysNeo_ERMETIC%20REPORT%20-%20AWS%20S3%20Ransomware%20Exposure%20in%20the%20Wild.pdf) - [S3 Ransomware Part 1: Attack Vector](https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/)


## Rule query [_rule_query_5049]

```js
any where event.dataset == "aws.cloudtrail"
   and event.action == "PutBucketVersioning"
   and event.outcome == "success"
   and stringContains(aws.cloudtrail.request_parameters, "Status=Suspended")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Inhibit System Recovery
    * ID: T1490
    * Reference URL: [https://attack.mitre.org/techniques/T1490/](https://attack.mitre.org/techniques/T1490/)



