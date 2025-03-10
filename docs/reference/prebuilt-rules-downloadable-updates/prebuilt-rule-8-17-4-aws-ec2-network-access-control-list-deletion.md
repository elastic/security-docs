---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-ec2-network-access-control-list-deletion.html
---

# AWS EC2 Network Access Control List Deletion [prebuilt-rule-8-17-4-aws-ec2-network-access-control-list-deletion]

Identifies the deletion of an Amazon Elastic Compute Cloud (EC2) network access control list (ACL) or one of its ingress/egress entries.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-network-acl.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-network-acl.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAcl.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAcl.md)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-network-acl-entry.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-network-acl-entry.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAclEntry.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAclEntry.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Use Case: Network Security Monitoring
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3988]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS EC2 Network Access Control List Deletion**

AWS EC2 Network ACLs are essential for controlling inbound and outbound traffic to subnets, acting as a firewall layer. Adversaries may delete these ACLs to disable security controls, facilitating unauthorized access or data exfiltration. The detection rule monitors AWS CloudTrail logs for successful deletion events of ACLs or their entries, signaling potential defense evasion attempts.

**Possible investigation steps**

* Review the AWS CloudTrail logs to identify the specific user or role associated with the deletion event by examining the user identity information in the logs.
* Check the time and date of the deletion event to determine if it coincides with any other suspicious activities or known maintenance windows.
* Investigate the source IP address and location from which the deletion request was made to assess if it aligns with expected access patterns or if it appears anomalous.
* Examine the AWS account activity around the time of the event to identify any other unusual actions or changes, such as the creation of new resources or modifications to existing ones.
* Assess the impact of the deleted Network ACL or entries by identifying the affected subnets and evaluating the potential exposure or risk to the network.
* Review any recent changes to IAM policies or roles that might have inadvertently granted excessive permissions to users or services, allowing them to delete Network ACLs.

**False positive analysis**

* Routine maintenance or updates by authorized personnel may trigger deletion events. Verify if the deletion aligns with scheduled maintenance activities and consider excluding these events from alerts.
* Automated scripts or infrastructure-as-code tools like Terraform or CloudFormation might delete and recreate ACLs as part of normal operations. Identify these tools and exclude their actions from triggering alerts.
* Changes in network architecture or security policy updates can lead to legitimate ACL deletions. Document these changes and adjust the detection rule to ignore such planned modifications.
* Ensure that the AWS accounts involved in the deletion events are recognized and trusted. Exclude actions from these accounts if they are part of regular administrative tasks.
* Collaborate with the security team to establish a baseline of normal ACL deletion activities and refine the detection rule to minimize false positives based on this baseline.

**Response and remediation**

* Immediately isolate the affected subnet to prevent further unauthorized access or data exfiltration. This can be done by applying a restrictive security group or temporarily removing the subnet from the VPC.
* Review AWS CloudTrail logs to identify the source of the deletion event, including the IAM user or role responsible, and assess whether the action was authorized or part of a larger compromise.
* Recreate the deleted Network ACL or its entries using the most recent backup or configuration documentation to restore intended security controls.
* Implement a temporary monitoring solution to track any further unauthorized changes to network ACLs or related security configurations.
* Escalate the incident to the security operations team for a comprehensive investigation to determine the root cause and scope of the breach, including potential lateral movement or data exfiltration.
* Revoke or rotate credentials for any compromised IAM users or roles involved in the deletion event to prevent further unauthorized actions.
* Enhance detection capabilities by configuring alerts for any future unauthorized changes to network ACLs, ensuring rapid response to similar threats.


## Setup [_setup_922]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5005]

```js
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(DeleteNetworkAcl or DeleteNetworkAclEntry) and event.outcome:success
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

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



