---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-route-53-domain-transferred-to-another-account.html
---

# AWS Route 53 Domain Transferred to Another Account [aws-route-53-domain-transferred-to-another-account]

Identifies when a request has been made to transfer a Route 53 domain to another AWS account.

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

* [https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html](https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.md)

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

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_80]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS Route 53 Domain Transferred to Another Account**

AWS Route 53 is a scalable domain name system (DNS) web service designed to route end-user requests to internet applications. Transferring a domain to another AWS account can be legitimate but may also indicate unauthorized access or account manipulation. Adversaries might exploit this to gain persistent control over a domain. The detection rule monitors successful domain transfer requests, flagging potential misuse by correlating specific AWS CloudTrail events, thus aiding in identifying unauthorized domain transfers.

**Possible investigation steps**

* Review the AWS CloudTrail logs to identify the specific event with event.action:TransferDomainToAnotherAwsAccount and event.outcome:success to gather details about the domain transfer request.
* Verify the identity of the AWS account to which the domain was transferred by examining the event details, including the account ID and any associated user or role information.
* Check the AWS account’s activity history for any unusual or unauthorized access patterns around the time of the domain transfer event.
* Contact the domain’s original owner or administrator to confirm whether the transfer was authorized and legitimate.
* Investigate any recent changes in IAM policies or permissions that might have allowed unauthorized users to initiate the domain transfer.
* Assess the potential impact of the domain transfer on your organization’s operations and security posture, considering the domain’s role in your infrastructure.

**False positive analysis**

* Routine domain transfers between accounts within the same organization can trigger alerts. To manage this, create exceptions for known internal account transfers by whitelisting specific account IDs involved in regular transfers.
* Scheduled domain management activities by IT teams may result in false positives. Coordinate with IT to document and schedule these activities, then exclude them from alerts during these periods.
* Automated scripts or tools used for domain management might inadvertently trigger alerts. Identify these scripts and their associated user accounts, and configure exceptions for these known, benign activities.
* Transfers related to mergers or acquisitions can be mistaken for unauthorized actions. Ensure that such events are communicated to the security team in advance, allowing them to temporarily adjust monitoring rules to accommodate these legitimate transfers.

**Response and remediation**

* Immediately revoke any unauthorized access to the AWS account by changing the credentials and access keys associated with the account where the domain was transferred.
* Contact AWS Support to report the unauthorized domain transfer and request assistance in reversing the transfer if it was not authorized.
* Review AWS CloudTrail logs to identify any other suspicious activities or unauthorized access attempts around the time of the domain transfer.
* Implement multi-factor authentication (MFA) for all AWS accounts to enhance security and prevent unauthorized access.
* Conduct a thorough audit of IAM roles and permissions to ensure that only authorized users have the ability to transfer domains.
* Notify relevant stakeholders, including IT security teams and domain administrators, about the incident and the steps being taken to remediate it.
* Enhance monitoring and alerting for similar events by configuring additional AWS CloudWatch alarms or integrating with a Security Information and Event Management (SIEM) system to detect future unauthorized domain transfer attempts.


## Setup [_setup_47]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_84]

```js
event.dataset:aws.cloudtrail and event.provider:route53.amazonaws.com and event.action:TransferDomainToAnotherAwsAccount and event.outcome:success
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

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)



