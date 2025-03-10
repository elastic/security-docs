---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-route53-private-hosted-zone-associated-with-a-vpc.html
---

# AWS Route53 private hosted zone associated with a VPC [prebuilt-rule-8-17-4-aws-route53-private-hosted-zone-associated-with-a-vpc]

Identifies when a Route53 private hosted zone has been associated with VPC.

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

* [https://docs.aws.amazon.com/Route53/latest/APIReference/API_AssociateVPCWithHostedZone.html](https://docs.aws.amazon.com/Route53/latest/APIReference/API_AssociateVPCWithHostedZone.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS Route53
* Use Case: Asset Visibility
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4056]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS Route53 private hosted zone associated with a VPC**

AWS Route53 private hosted zones allow for DNS management within a Virtual Private Cloud (VPC), ensuring internal resources are accessible only within the VPC. Adversaries might exploit this by associating unauthorized VPCs to intercept or reroute traffic. The detection rule identifies successful associations of VPCs with hosted zones, signaling potential misuse or unauthorized access attempts.

**Possible investigation steps**

* Review the CloudTrail logs for the event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com to gather details about the AssociateVPCWithHostedZone action, including the time of the event and the identity of the user or role that performed the action.
* Verify the event.outcome:success to confirm that the association was successful and identify the specific VPC and hosted zone involved in the association.
* Check the AWS IAM policies and permissions of the user or role that initiated the association to ensure they have the appropriate level of access and determine if the action aligns with their expected responsibilities.
* Investigate the associated VPC to determine if it is authorized and expected to be linked with the private hosted zone. Look for any unusual or unauthorized VPCs that may indicate potential misuse.
* Review recent changes or activities in the AWS account to identify any other suspicious actions or patterns that could suggest a broader security incident or compromise.

**False positive analysis**

* Routine infrastructure changes may trigger this rule when legitimate VPCs are associated with private hosted zones during regular operations. To manage this, maintain an updated list of authorized VPCs and compare them against the detected associations.
* Automated deployment tools or scripts that frequently associate VPCs with hosted zones can cause false positives. Identify these tools and create exceptions for their known activities to reduce noise.
* Development and testing environments often involve frequent changes and associations of VPCs with hosted zones. Consider excluding these environments from the rule or setting up a separate monitoring policy with adjusted thresholds.
* Scheduled maintenance or updates might involve temporary associations of VPCs with hosted zones. Document these schedules and incorporate them into the monitoring system to prevent false alerts during these periods.

**Response and remediation**

* Immediately isolate the VPC associated with the unauthorized Route53 private hosted zone to prevent further unauthorized access or data exfiltration.
* Review CloudTrail logs to identify the source and method of the unauthorized VPC association, focusing on the user or role that performed the action.
* Revoke any unauthorized access or permissions identified during the log review, particularly those related to the IAM roles or users involved in the incident.
* Conduct a security review of the affected VPC and associated resources to ensure no other configurations have been tampered with or compromised.
* Notify the security operations team and relevant stakeholders about the incident for further investigation and potential escalation.
* Implement additional monitoring and alerting for similar events in the future, ensuring that any unauthorized associations are detected promptly.
* Review and update IAM policies and security group rules to enforce the principle of least privilege, reducing the risk of similar incidents occurring.


## Setup [_setup_953]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5073]

```js
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:AssociateVPCWithHostedZone and
event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



