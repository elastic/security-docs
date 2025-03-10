---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-aws-ec2-ebs-snapshot-shared-or-made-public.html
---

# AWS EC2 EBS Snapshot Shared or Made Public [prebuilt-rule-8-17-3-aws-ec2-ebs-snapshot-shared-or-made-public]

Identifies AWS EC2 EBS snaphots being shared with another AWS account or made public. EBS virtual disks can be copied into snapshots, which can then be shared with an external AWS account or made public. Adversaries may attempt this in order to copy the snapshot into an environment they control, to access the data.

**Rule type**: esql

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySnapshotAttribute.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySnapshotAttribute.md)
* [https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-ec2-ebs-ssm-and-vpc-post-exploitation/aws-ebs-snapshot-dump](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-ec2-ebs-ssm-and-vpc-post-exploitation/aws-ebs-snapshot-dump)
* [https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/](https://hackingthe.cloud/aws/exploitation/Misconfigured_Resource-Based_Policies/exploting_public_resources_attack_playbook/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS EC2
* Use Case: Threat Detection
* Tactic: Exfiltration

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3915]

**Triage and Analysis**

**Investigating AWS EC2 EBS Snapshot Shared or Made Public**

This rule detects when an AWS EC2 EBS snapshot is shared with another AWS account or made public. EBS virtual disks can be copied into snapshots, which can then be shared with an external AWS account or made public. Adversaries may attempt this to copy the snapshot into an environment they control to access the data. Understanding the context and legitimacy of such changes is crucial to determine if the action is benign or malicious.

**Possible Investigation Steps:**

* ***Identify the Actor***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` fields to identify who made the change. Verify if this actor typically performs such actions and if they have the necessary permissions.
* ***Review the Request Details***: Examine the `aws.cloudtrail.request_parameters` to understand the specific changes made to the snapshot permissions. Look for any unusual parameters that could suggest unauthorized or malicious modifications.
* ***Analyze the Source of the Request***: Investigate the `source.ip` and `source.geo` fields to determine the geographical origin of the request. An external or unexpected location might indicate compromised credentials or unauthorized access.
* ***Contextualize with Timestamp***: Use the `@timestamp` field to check when the change occurred. Modifications during non-business hours or outside regular maintenance windows might require further scrutiny.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this change to see if the same actor or IP address engaged in other potentially suspicious activities.
* ***Review UserID***: Check the `userId` field to identify the AWS account with which the snapshot was shared. Verify if this account is authorized to access the data or if it belongs to a known third party. If this value is `all`, the snapshot is made public.

**False Positive Analysis:**

* ***Legitimate Administrative Actions***: Confirm if the snapshot sharing aligns with scheduled updates, development activities, or legitimate administrative tasks documented in change management systems.
* ***Consistency Check***: Compare the action against historical data of similar actions performed by the user or within the organization. If the action is consistent with past legitimate activities, it might indicate a false alarm.
* ***Verify through Outcomes***: Check the `aws.cloudtrail.response_elements` and the `event.outcome` to confirm if the change was successful and intended according to policy.

**Response and Remediation:**

* ***Immediate Review and Reversal if Necessary***: If the change was unauthorized, update the snapshot permissions to remove any unauthorized accounts and restore it to its previous state.
* ***Enhance Monitoring and Alerts***: Adjust monitoring systems to alert on similar actions, especially those involving sensitive data or permissions.
* ***Educate and Train***: Provide additional training to users with administrative rights on the importance of security best practices concerning snapshot management and sharing permissions.
* ***Audit Snapshots and Policies***: Conduct a comprehensive audit of all snapshots and associated policies to ensure they adhere to the principle of least privilege.
* ***Incident Response***: If there’s an indication of malicious intent or a security breach, initiate the incident response protocol to mitigate any damage and prevent future occurrences.

**Additional Information:**

For further guidance on managing EBS snapshots and securing AWS environments, refer to the [AWS EBS documentation](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.md) and AWS best practices for security. Additionally, consult the following resources for specific details on EBS snapshot security: - [AWS EBS Snapshot Permissions](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.md) - [AWS API ModifySnapshotAttribute](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySnapshotAttribute.md) - [AWS EBS Snapshot Dump](https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-post-exploitation/aws-ec2-ebs-ssm-and-vpc-post-exploitation/aws-ebs-snapshot-dump)


## Rule query [_rule_query_4848]

```js
from logs-aws.cloudtrail-* metadata _id, _version, _index
| where event.provider == "ec2.amazonaws.com" and event.action == "ModifySnapshotAttribute" and event.outcome == "success"
| dissect aws.cloudtrail.request_parameters "{%{?snapshotId}=%{snapshotId},%{?attributeType}=%{attributeType},%{?createVolumePermission}={%{operationType}={%{?items}=[{%{?userId}=%{userId}}]}}}"
| where operationType == "add" and cloud.account.id != userId
| keep @timestamp, aws.cloudtrail.user_identity.arn, cloud.account.id, event.action, snapshotId, attributeType, operationType, userId
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



