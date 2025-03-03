---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-sts-getsessiontoken-abuse.html
---

# AWS STS GetSessionToken Abuse [aws-sts-getsessiontoken-abuse]

Identifies the suspicious use of GetSessionToken. Tokens could be created and used by attackers to move laterally and escalate privileges.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS STS
* Use Case: Identity and Access Audit
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_100]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS STS GetSessionToken Abuse**

AWS Security Token Service (STS) provides temporary credentials for AWS resources, crucial for managing access without long-term credentials. Adversaries may exploit GetSessionToken to create temporary credentials, enabling lateral movement and privilege escalation. The detection rule identifies successful GetSessionToken requests by IAM users, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the CloudTrail logs for the specific GetSessionToken event to gather details about the IAM user involved, including the time of the request and the source IP address.
* Check the IAM user’s activity history to identify any unusual patterns or deviations from their normal behavior, such as accessing resources they typically do not use.
* Investigate the source IP address from which the GetSessionToken request originated to determine if it is associated with known malicious activity or if it is an unexpected location for the user.
* Examine the permissions and roles associated with the temporary credentials issued by the GetSessionToken request to assess the potential impact of their misuse.
* Correlate the GetSessionToken event with other security events or alerts in the same timeframe to identify any related suspicious activities or potential indicators of compromise.

**False positive analysis**

* Routine administrative tasks by IAM users can trigger GetSessionToken requests. To manage this, identify and whitelist IAM users or roles that regularly perform these tasks as part of their job functions.
* Automated scripts or applications that use GetSessionToken for legitimate purposes may cause false positives. Review and document these scripts, then create exceptions for their activity in the detection rule.
* Scheduled jobs or services that require temporary credentials for periodic tasks might be flagged. Ensure these are documented and excluded from alerts by adjusting the rule to recognize their specific patterns.
* Development and testing environments often generate GetSessionToken requests during normal operations. Consider excluding these environments from the rule or adjusting the risk score to reflect their lower threat level.
* Cross-account access scenarios where users from one account access resources in another using temporary credentials can appear suspicious. Verify these access patterns and exclude them if they are part of regular operations.

**Response and remediation**

* Immediately revoke the temporary credentials associated with the suspicious GetSessionToken request to prevent further unauthorized access.
* Conduct a thorough review of the IAM user’s activity logs to identify any unauthorized actions or access patterns that may indicate lateral movement or privilege escalation.
* Isolate any affected resources or accounts to contain potential threats and prevent further exploitation.
* Reset the credentials of the IAM user involved and enforce multi-factor authentication (MFA) to enhance security.
* Notify the security operations team and relevant stakeholders about the incident for awareness and further investigation.
* Implement additional monitoring and alerting for unusual GetSessionToken requests to detect similar activities in the future.
* Review and tighten IAM policies and permissions to ensure the principle of least privilege is enforced, reducing the risk of privilege escalation.


## Setup [_setup_56]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_104]

```js
event.dataset:aws.cloudtrail and event.provider:sts.amazonaws.com and event.action:GetSessionToken and
aws.cloudtrail.user_identity.type:IAMUser and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Application Access Token
    * ID: T1550.001
    * Reference URL: [https://attack.mitre.org/techniques/T1550/001/](https://attack.mitre.org/techniques/T1550/001/)



