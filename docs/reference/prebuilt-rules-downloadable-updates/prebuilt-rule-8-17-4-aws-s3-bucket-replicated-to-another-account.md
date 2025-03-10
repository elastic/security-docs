---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-s3-bucket-replicated-to-another-account.html
---

# AWS S3 Bucket Replicated to Another Account [prebuilt-rule-8-17-4-aws-s3-bucket-replicated-to-another-account]

Identifies when the `PutBucketReplication` operation is used to replicate S3 objects to a bucket in another AWS account. Adversaries may use bucket replication to exfiltrate sensitive data to an environment they control.

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

* [https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-walkthrough-2.html/](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-walkthrough-2.md/)
* [https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.html/](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.md/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS S3
* Resources: Investigation Guide
* Use Case: Threat Detection
* Tactic: Exfiltration

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4018]

**Triage and analysis**

**Investigating AWS S3 Bucket Replicated to Another Account**

This rule identifies when an S3 bucket is replicated to another AWS account. While sharing bucket replication is a common practice, adversaries may exploit this feature to exfiltrate data by replicating objects to external accounts under their control.

**Possible Investigation Steps**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who made the change. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Review the Sharing Event***: Identify the S3 bucket involved and review the event details. Look for `PutBucketReplication` actions where an `Account` key-value pair is included signifying replication to an external account.
* ***Request and Response Parameters***: Check the `aws.cloudtrail.request_parameters` and `aws.cloudtrail.response_elements` fields in the CloudTrail event to identify the role used and account ID where the bucket was replicated.
* ***Verify the Shared Bucket***: Check the S3 bucket that was replicated and its contents to determine the sensitivity of the data stored within it.
* ***Validate External Account***: Examine the AWS account to which the bucket was replicated. Determine whether this account is known and previously authorized to access such resources.
* ***Contextualize with Recent Changes***: Compare this sharing event against recent changes in S3 configurations. Look for any other recent permissions changes or unusual administrative actions.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this change to see if the same actor or IP address engaged in other potentially suspicious activities.
* ***Interview Relevant Personnel***: If the share was initiated by a user, verify the intent and authorization for this action with the person or team responsible for managing DB backups and snapshots.

**False Positive Analysis**

* ***Legitimate Backup Actions***: Confirm if the S3 bucket replication aligns with scheduled backups or legitimate automation tasks.
* ***Consistency Check***: Compare the action against historical data of similar actions performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.

**Response and Remediation**

* ***Immediate Review and Reversal***: If the change was unauthorized, update the S3 configurations to remove any unauthorized replication rules.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar actions, especially those involving sensitive data or permissions.
* ***Policy Update***: Review and possibly update your organization’s policies on S3 bucket/object sharing to tighten control and prevent unauthorized access.
* ***Incident Response***: If malicious intent is confirmed, consider it a data breach incident and initiate the incident response protocol. This includes further investigation, containment, and recovery.

**Additional Information:**

For further guidance on managing and securing S3 buckets in AWS environments, refer to the [AWS S3 documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.md/) and AWS best practices for security.


## Rule query [_rule_query_5035]

```js
any where event.dataset == "aws.cloudtrail"
   and event.action == "PutBucketReplication"
   and event.outcome == "success"
   and stringContains(aws.cloudtrail.request_parameters, "Account")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Transfer Data to Cloud Account
    * ID: T1537
    * Reference URL: [https://attack.mitre.org/techniques/T1537/](https://attack.mitre.org/techniques/T1537/)



