---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-sts-assumerole-with-new-mfa-device.html
---

# AWS STS AssumeRole with New MFA Device [aws-sts-assumerole-with-new-mfa-device]

Identifies when a user has assumed a role using a new MFA device. Users can assume a role to obtain temporary credentials and access AWS resources using the AssumeRole API of AWS Security Token Service (STS). While a new MFA device is not always indicative of malicious behavior it should be verified as adversaries can use this technique for persistence and privilege escalation.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.md)
* [https://github.com/RhinoSecurityLabs/cloudgoat/blob/d5863b80afd082d853f2e8df1955c6393695a4da/scenarios/iam_privesc_by_key_rotation/README.md](https://github.com/RhinoSecurityLabs/cloudgoat/blob/d5863b80afd082d853f2e8df1955c6393695a4da/scenarios/iam_privesc_by_key_rotation/README.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS STS
* Use Case: Identity and Access Audit
* Tactic: Privilege Escalation
* Tactic: Persistence
* Tactic: Lateral Movement
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_97]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS STS AssumeRole with New MFA Device**

AWS Security Token Service (STS) allows users to assume roles and gain temporary credentials for accessing AWS resources. This process can involve Multi-Factor Authentication (MFA) for enhanced security. However, adversaries may exploit new MFA devices to maintain persistence or escalate privileges. The detection rule identifies successful role assumptions with new MFA devices, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the event details in AWS CloudTrail to identify the user who assumed the role, focusing on the user.id field to determine if the user is legitimate and authorized to use the new MFA device.
* Check the serialNumber in the aws.cloudtrail.flattened.request_parameters to verify the registration and legitimacy of the new MFA device associated with the role assumption.
* Investigate the context of the AssumeRole action by examining the event.action field to understand if it was part of a legitimate workflow or an unusual activity.
* Analyze the event.outcome field to confirm the success of the role assumption and cross-reference with any recent changes in user permissions or MFA device registrations.
* Correlate the event with other logs or alerts to identify any patterns of suspicious behavior, such as multiple role assumptions or changes in MFA devices within a short timeframe.
* Contact the user or relevant team to confirm if the new MFA device registration and role assumption were expected and authorized.

**False positive analysis**

* New employee onboarding processes may trigger this rule when new MFA devices are issued. To manage this, create exceptions for known onboarding activities by correlating with HR records or onboarding schedules.
* Routine device replacements or upgrades can result in new MFA devices being registered. Implement a process to track and verify device changes through IT support tickets or asset management systems.
* Users with multiple roles or responsibilities might frequently switch roles using different MFA devices. Establish a baseline of normal behavior for these users and create exceptions for their typical activity patterns.
* Organizational policy changes that require MFA updates can lead to multiple new MFA device registrations. Coordinate with security teams to whitelist these events during policy rollout periods.
* Temporary contractors or third-party vendors may use new MFA devices when accessing AWS resources. Ensure that their access is logged and reviewed, and create temporary exceptions for their known access periods.

**Response and remediation**

* Immediately revoke the temporary credentials associated with the assumed role to prevent unauthorized access to AWS resources.
* Verify the legitimacy of the new MFA device by contacting the user or administrator associated with the role assumption. Confirm whether the device was intentionally registered and used.
* If the new MFA device is determined to be unauthorized, disable or remove it from the user’s account to prevent further misuse.
* Conduct a review of recent AWS CloudTrail logs to identify any suspicious activities or patterns associated with the user or role in question, focusing on privilege escalation or lateral movement attempts.
* Escalate the incident to the security operations team for further investigation and to determine if additional containment measures are necessary.
* Implement additional monitoring and alerting for unusual MFA device registrations and role assumptions to enhance detection of similar threats in the future.
* Review and update IAM policies and MFA device management procedures to ensure they align with best practices for security and access control.


## Setup [_setup_55]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_101]

```js
event.dataset:aws.cloudtrail
    and event.provider:sts.amazonaws.com
    and event.action:(AssumeRole or AssumeRoleWithSAML or AssumeRoleWithWebIdentity)
    and event.outcome:success
    and user.id:*
    and aws.cloudtrail.flattened.request_parameters.serialNumber:*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)

* Sub-technique:

    * Name: Multi-Factor Authentication
    * ID: T1556.006
    * Reference URL: [https://attack.mitre.org/techniques/T1556/006/](https://attack.mitre.org/techniques/T1556/006/)

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



