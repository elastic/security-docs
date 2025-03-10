---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-aws-s3-bucket-ransomware-note-uploaded.html
---

# Potential AWS S3 Bucket Ransomware Note Uploaded [prebuilt-rule-8-17-4-potential-aws-s3-bucket-ransomware-note-uploaded]

Identifies potential ransomware note being uploaded to an AWS S3 bucket. This rule detects the `PutObject` S3 API call with a common ransomware note file extension such as `.ransom`, or `.lock`. Adversaries with access to a misconfigured S3 bucket may retrieve, delete, and replace objects with ransom notes to extort victims.

**Rule type**: esql

**Rule indices**: None

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://s3.amazonaws.com/bizzabo.file.upload/PtZzA0eFQwV2RA5ysNeo_ERMETIC%20REPORT%20-%20AWS%20S3%20Ransomware%20Exposure%20in%20the%20Wild.pdf](https://s3.amazonaws.com/bizzabo.file.upload/PtZzA0eFQwV2RA5ysNeo_ERMETIC%20REPORT%20-%20AWS%20S3%20Ransomware%20Exposure%20in%20the%20Wild.pdf)
* [https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.s3-ransomware-batch-deletion/](https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.s3-ransomware-batch-deletion/)
* [https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/](https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS S3
* Use Case: Threat Detection
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4030]

**Triage and analysis**

**Investigating Potential AWS S3 Bucket Ransomware Note Uploaded**

This rule detects the `PutObject` S3 API call with a common ransomware note file extension such as `.ransom`, or `.lock`. Adversaries with access to a misconfigured S3 bucket may retrieve, delete, and replace objects with ransom notes to extort victims.

**Possible Investigation Steps:**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who performed the action. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Review the Request Details***: Examine the `aws.cloudtrail.request_parameters` to understand the specific details of the `PutObject` action. Look for any unusual parameters that could suggest unauthorized or malicious modifications.
* ***Analyze the Source of the Request***: Investigate the `source.ip` and `source.geo` fields to determine the geographical origin of the request. An external or unexpected location might indicate compromised credentials or unauthorized access.
* ***Contextualize with Timestamp***: Use the `@timestamp` field to check when the ransom note was uploaded. Changes during non-business hours or outside regular maintenance windows might require further scrutiny.
* ***Inspect the Ransom Note***: Review the `aws.cloudtrail.request_parameters` for the `PutObject` action to identify the characteristics of the uploaded ransom note. Look for common ransomware file extensions such as `.txt`, `.note`, `.ransom`, or `.html`.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this action to see if the same actor or IP address engaged in other potentially suspicious activities.
* ***Check for Object Deletion or Access***: Look for `DeleteObject`, `DeleteObjects`, or `GetObject` API calls to the same S3 bucket that may indicate the adversary accessing and destroying objects before placing the ransom note.

**False Positive Analysis:**

* ***Legitimate Administrative Actions***: Confirm if the `PutObject` action aligns with scheduled updates, maintenance activities, or legitimate administrative tasks documented in change management systems.
* ***Consistency Check***: Compare the action against historical data of similar activities performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.
* ***Verify through Outcomes***: Check the `aws.cloudtrail.response_elements` and the `event.outcome` to confirm if the upload was successful and intended according to policy.

**Response and Remediation:**

* ***Immediate Review and Reversal if Necessary***: If the activity was unauthorized, remove the uploaded ransom notes from the S3 bucket and review the bucket’s access logs for any suspicious activity.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar `PutObject` actions, especially those involving sensitive data or unusual file extensions.
* ***Educate and Train***: Provide additional training to users with administrative rights on the importance of security best practices concerning S3 bucket management and the risks of ransomware.
* ***Audit S3 Bucket Policies and Permissions***: Conduct a comprehensive audit of all S3 bucket policies and associated permissions to ensure they adhere to the principle of least privilege.
* ***Incident Response***: If there’s an indication of malicious intent or a security breach, initiate the incident response protocol to mitigate any damage and prevent future occurrences.

**Additional Information:**

For further guidance on managing S3 bucket security and protecting against ransomware, refer to the [AWS S3 documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.md) and AWS best practices for security. Additionally, consult the following resources for specific details on S3 ransomware protection: - [ERMETIC REPORT - AWS S3 Ransomware Exposure in the Wild](https://s3.amazonaws.com/bizzabo.file.upload/PtZzA0eFQwV2RA5ysNeo_ERMETIC%20REPORT%20-%20AWS%20S3%20Ransomware%20Exposure%20in%20the%20Wild.pdf) - [AWS S3 Ransomware Batch Deletion](https://stratus-red-team.cloud/attack-techniques/AWS/aws.impact.s3-ransomware-batch-deletion/) - [S3 Ransomware Part 1: Attack Vector](https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/)


## Setup [_setup_942]

AWS S3 data types need to be enabled in the CloudTrail trail configuration.


## Rule query [_rule_query_5047]

```js
from logs-aws.cloudtrail-*

// any successful uploads via S3 API requests
| where event.dataset == "aws.cloudtrail"
    and event.provider == "s3.amazonaws.com"
    and event.action == "PutObject"
    and event.outcome == "success"

// abstract object name from API request parameters
| dissect aws.cloudtrail.request_parameters "%{?ignore_values}key=%{object_name}}"

// regex on common ransomware note extensions
| where object_name rlike "(.*)(ransom|lock|crypt|enc|readme|how_to_decrypt|decrypt_instructions|recovery|datarescue)(.*)"
    and not object_name rlike "(.*)(AWSLogs|CloudTrail|access-logs)(.*)"

// keep relevant fields
| keep tls.client.server_name, aws.cloudtrail.user_identity.arn, object_name

// aggregate by S3 bucket, resource and object name
| stats note_upload_count = count(*) by tls.client.server_name, aws.cloudtrail.user_identity.arn, object_name

// filter for single occurrence to eliminate common upload operations
| where note_upload_count == 1
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



