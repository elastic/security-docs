---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-ec2-network-access-control-list-creation.html
---

# AWS EC2 Network Access Control List Creation [prebuilt-rule-8-17-4-aws-ec2-network-access-control-list-creation]

Identifies the creation of an AWS Elastic Compute Cloud (EC2) network access control list (ACL) or an entry in a network ACL with a specified rule number.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAcl.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAcl.md)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl-entry.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/create-network-acl-entry.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAclEntry.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAclEntry.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS EC2
* Use Case: Network Security Monitoring
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4038]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS EC2 Network Access Control List Creation**

AWS EC2 Network ACLs are stateless firewalls for controlling inbound and outbound traffic at the subnet level. Adversaries may exploit ACLs to establish persistence or exfiltrate data by creating permissive rules. The detection rule monitors successful creation events of ACLs or entries, flagging potential unauthorized modifications that align with persistence tactics, aiding in early threat identification.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event.dataset:aws.cloudtrail entries to identify the user or role (event.user) that initiated the CreateNetworkAcl or CreateNetworkAclEntry actions.
* Examine the event.provider:ec2.amazonaws.com logs to determine the IP addresses and locations associated with the request to assess if they are expected or suspicious.
* Check the event.action details to understand the specific rules created in the Network ACL, focusing on any overly permissive rules that could indicate a security risk.
* Investigate the event.outcome:success entries to confirm the successful creation of the ACL or ACL entry and correlate with any other suspicious activities in the AWS environment.
* Cross-reference the event with other security alerts or logs to identify any patterns or anomalies that could suggest malicious intent or unauthorized access.
* Assess the impact of the new ACL rules on the network security posture, ensuring they do not inadvertently allow unauthorized access or data exfiltration.

**False positive analysis**

* Routine infrastructure updates or deployments may trigger the creation of new network ACLs or entries. To manage this, establish a baseline of expected changes during scheduled maintenance windows and exclude these from alerts.
* Automated scripts or infrastructure-as-code tools like Terraform or CloudFormation can create network ACLs as part of normal operations. Identify and whitelist these automated processes to prevent unnecessary alerts.
* Changes made by trusted administrators or security teams for legitimate purposes can be mistaken for suspicious activity. Implement a process to log and review approved changes, allowing you to exclude these from detection.
* Temporary ACLs created for troubleshooting or testing purposes can generate alerts. Document and track these activities, and use tags or naming conventions to easily identify and exclude them from monitoring.
* Third-party services or integrations that require specific network configurations might create ACLs. Review and validate these services, and if deemed safe, add them to an exception list to reduce false positives.

**Response and remediation**

* Immediately review the AWS CloudTrail logs to confirm the creation of the Network ACL or entry and identify the IAM user or role responsible for the action. This helps determine if the action was authorized or potentially malicious.
* Revoke any suspicious or unauthorized IAM credentials associated with the creation of the Network ACL or entry to prevent further unauthorized access.
* Modify or delete the newly created Network ACL or entry if it is determined to be unauthorized or overly permissive, ensuring that it aligns with your organization’s security policies.
* Conduct a security review of the affected AWS environment to identify any other unauthorized changes or indicators of compromise, focusing on persistence mechanisms.
* Implement additional monitoring and alerting for changes to Network ACLs and other critical AWS resources to enhance detection of similar threats in the future.
* Escalate the incident to the security operations team or incident response team for further investigation and to determine if additional containment or remediation actions are necessary.
* Review and update IAM policies and permissions to ensure the principle of least privilege is enforced, reducing the risk of unauthorized changes to network configurations.


## Setup [_setup_945]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5055]

```js
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(CreateNetworkAcl or CreateNetworkAclEntry) and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: External Remote Services
    * ID: T1133
    * Reference URL: [https://attack.mitre.org/techniques/T1133/](https://attack.mitre.org/techniques/T1133/)



