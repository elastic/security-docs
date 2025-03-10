---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-s3-object-encryption-using-external-kms-key.html
---

# AWS S3 Object Encryption Using External KMS Key [prebuilt-rule-8-17-4-aws-s3-object-encryption-using-external-kms-key]

Identifies `CopyObject` events within an S3 bucket using an AWS KMS key from an external account for encryption. Adversaries with access to a misconfigured S3 bucket and the proper permissions may encrypt objects with an external KMS key to deny their victims access to their own data.

**Rule type**: esql

**Rule indices**: None

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html/](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.md/)
* [https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html/](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.md/)
* [https://www.gem.security/post/cloud-ransomware-a-new-take-on-an-old-attack-pattern/](https://www.gem.security/post/cloud-ransomware-a-new-take-on-an-old-attack-pattern/)
* [https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/](https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS S3
* Data Source: AWS KMS
* Use Case: Threat Detection
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4031]

**Triage and analysis**

**Investigating AWS S3 Object Encryption Using External KMS Key**

This rule detects the use of an external AWS KMS key to encrypt objects within an S3 bucket. Adversaries with access to a misconfigured S3 bucket may use an external key to copy objects within a bucket and deny victims the ability to access their own data. This rule uses [ES|QL](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-esql-rule) to look for use of the `CopyObject` operation where the target bucket’s `cloud.account.id` is different from the `key.account.id` dissected from the AWS KMS key used for encryption.

**Possible Investigation Steps:**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who performed the action. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Review the Request Details***: Examine the `aws.cloudtrail.request_parameters` to understand the specific details of the `CopyObject` action. Look for any unusual parameters that could suggest unauthorized or malicious modifications or usage of an unknown KMS keyId.
* ***Analyze the Source of the Request***: Investigate the `source.ip` and `source.geo` fields to determine the geographical origin of the request. An external or unexpected location might indicate compromised credentials or unauthorized access.
* ***Contextualize with Timestamp***: Use the `@timestamp` field to check when the object was copied. Changes during non-business hours or outside regular maintenance windows might require further scrutiny.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this action to see if the same actor or IP address engaged in other potentially suspicious activities.
* ***Check for Object Deletion or Access***: Look for `DeleteObject`, `DeleteObjects`, or `GetObject` API calls to the same S3 bucket that may indicate the adversary accessing and destroying objects including older object versions.
* ***Interview Relevant Personnel***: If the copy event was initiated by a user, verify the intent and authorization for this action with the person or team responsible for managing S3 buckets.

**False Positive Analysis:**

* ***Legitimate Administrative Actions***: Confirm if the `CopyObject` action aligns with scheduled updates, maintenance activities, or legitimate administrative tasks documented in change management systems.
* ***Consistency Check***: Compare the action against historical data of similar activities performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.

**Response and Remediation:**

* ***Immediate Review***: If the activity was unauthorized, search for potential ransom note placed in S3 bucket and review the bucket’s access logs for any suspicious activity.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar `CopyObject` actions, especially those involving sensitive data or unusual file extensions.
* ***Educate and Train***: Provide additional training to users with administrative rights on the importance of security best practices concerning S3 bucket management and the risks of ransomware.
* ***Audit S3 Bucket Policies and Permissions***: Conduct a comprehensive audit of all S3 bucket policies and associated permissions to ensure they adhere to the principle of least privilege.
* ***Incident Response***: If there’s an indication of malicious intent or a security breach, initiate the incident response protocol to mitigate any damage and prevent future occurrences.

**Additional Information:**

For further guidance on managing S3 bucket security and protecting against ransomware, refer to the [AWS S3 documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.md) and AWS best practices for security. Additionally, consult the following resources for specific details on S3 ransomware protection: - [ERMETIC REPORT - AWS S3 Ransomware Exposure in the Wild](https://s3.amazonaws.com/bizzabo.file.upload/PtZzA0eFQwV2RA5ysNeo_ERMETIC%20REPORT%20-%20AWS%20S3%20Ransomware%20Exposure%20in%20the%20Wild.pdf) - [S3 Ransomware Part 1: Attack Vector](https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/)


## Setup [_setup_943]

AWS S3 data event types need to be enabled in the CloudTrail trail configuration.


## Rule query [_rule_query_5048]

```js
from logs-aws.cloudtrail-* metadata _id, _version, _index

// any successful copy event
| where event.dataset == "aws.cloudtrail"
    and event.provider == "s3.amazonaws.com"
    and event.action == "CopyObject"
    and event.outcome == "success"

// abstract key account id, key id, encrypted object bucket name and object name
| dissect aws.cloudtrail.request_parameters "{%{?bucketName}=%{target.bucketName},%{?x-amz-server-side-encryption-aws-kms-key-id}=%{?arn}:%{?aws}:%{?kms}:%{?region}:%{key.account.id}:%{?key}/%{keyId},%{?Host}=%{?tls.client.server_name},%{?x-amz-server-side-encryption}=%{?server-side-encryption},%{?x-amz-copy-source}=%{?bucket.objectName},%{?key}=%{target.objectName}}"

// filter for s3 objects whose account id is different from the encryption key's account id
// add exceptions based on key.account.id or keyId for known external accounts or encryption keys
| where cloud.account.id != key.account.id

// keep relevant fields
| keep @timestamp, aws.cloudtrail.user_identity.arn, cloud.account.id, event.action, target.bucketName, key.account.id, keyId, target.objectName
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Encrypted for Impact
    * ID: T1486
    * Reference URL: [https://attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/)



