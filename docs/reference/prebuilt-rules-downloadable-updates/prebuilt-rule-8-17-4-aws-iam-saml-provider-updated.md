---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-iam-saml-provider-updated.html
---

# AWS IAM SAML Provider Updated [prebuilt-rule-8-17-4-aws-iam-saml-provider-updated]

Identifies when a user has updated a SAML provider in AWS. SAML providers are used to enable federated access to the AWS Management Console. This activity could be an indication of an attacker attempting to escalate privileges.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS IAM
* Use Case: Identity and Access Audit
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4063]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS IAM SAML Provider Updated**

AWS IAM SAML providers facilitate federated access, allowing users to authenticate via external identity providers. Adversaries may exploit this by updating SAML providers to gain unauthorized access or escalate privileges. The detection rule monitors successful updates to SAML providers, flagging potential privilege escalation attempts by correlating specific AWS CloudTrail events.

**Possible investigation steps**

* Review the AWS CloudTrail logs to identify the user or role associated with the UpdateSAMLProvider event. Check for any unusual or unauthorized users making changes.
* Examine the context of the UpdateSAMLProvider event, including the time of the event and any associated IP addresses or locations, to identify any anomalies or suspicious patterns.
* Investigate the history of changes to the specific SAML provider to determine if there have been any recent unauthorized or unexpected modifications.
* Check for any other related AWS CloudTrail events around the same timeframe, such as changes to IAM roles or policies, which might indicate a broader privilege escalation attempt.
* Assess the permissions and access levels of the user or role that performed the update to ensure they align with expected privileges and responsibilities.
* If suspicious activity is confirmed, consider revoking or limiting access for the involved user or role and review the security posture of the AWS environment to prevent future incidents.

**False positive analysis**

* Routine administrative updates to SAML providers by authorized personnel can trigger alerts. To manage this, maintain a list of known administrators and their expected activities, and create exceptions for these users in the detection rule.
* Scheduled updates or maintenance activities involving SAML providers may also result in false positives. Document these activities and adjust the detection rule to exclude events occurring during these scheduled times.
* Automated scripts or tools used for managing SAML providers can generate alerts if they perform updates. Identify these scripts and their expected behavior, then configure the detection rule to recognize and exclude these specific actions.
* Changes made by trusted third-party services integrated with AWS IAM might be flagged. Verify the legitimacy of these services and consider adding them to an allowlist to prevent unnecessary alerts.

**Response and remediation**

* Immediately revoke any unauthorized changes to the SAML provider by restoring the previous configuration from backups or logs.
* Conduct a thorough review of recent IAM activity logs to identify any unauthorized access or privilege escalation attempts associated with the updated SAML provider.
* Temporarily disable the affected SAML provider to prevent further unauthorized access while the investigation is ongoing.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Implement additional monitoring and alerting for any future changes to SAML providers to ensure rapid detection of unauthorized modifications.
* Review and tighten IAM policies and permissions to ensure that only authorized personnel can update SAML providers.
* Consider implementing multi-factor authentication (MFA) for all users with permissions to modify IAM configurations to enhance security.


## Setup [_setup_956]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5080]

```js
event.dataset:aws.cloudtrail
    and event.provider: iam.amazonaws.com
    and event.action: UpdateSAMLProvider
    and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Domain or Tenant Policy Modification
    * ID: T1484
    * Reference URL: [https://attack.mitre.org/techniques/T1484/](https://attack.mitre.org/techniques/T1484/)

* Sub-technique:

    * Name: Trust Modification
    * ID: T1484.002
    * Reference URL: [https://attack.mitre.org/techniques/T1484/002/](https://attack.mitre.org/techniques/T1484/002/)



