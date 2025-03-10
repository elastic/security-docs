---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/first-occurrence-of-sts-getfederationtoken-request-by-user.html
---

# First Occurrence of STS GetFederationToken Request by User [first-occurrence-of-sts-getfederationtoken-request-by-user]

Identifies the first occurrence of an AWS Security Token Service (STS) `GetFederationToken` request made by a user within the last 10 days. The `GetFederationToken` API call allows users to request temporary security credentials to access AWS resources. Adversaries may use this API to obtain temporary credentials to access resources they would not normally have access to.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://hackingthe.cloud/aws/post_exploitation/survive_access_key_deletion_with_sts_getfederationtoken/](https://hackingthe.cloud/aws/post_exploitation/survive_access_key_deletion_with_sts_getfederationtoken/)

**Tags**:

* Domain: Cloud
* Data Source: Amazon Web Services
* Data Source: AWS
* Data Source: AWS STS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_342]

**Triage and analysis**

[TBC: QUOTE]
**Investigating First Occurrence of STS GetFederationToken Request by User**

AWS Security Token Service (STS) enables users to request temporary credentials for accessing AWS resources. While beneficial for legitimate use, adversaries may exploit this to gain unauthorized access. The detection rule identifies unusual activity by flagging the first instance of a `GetFederationToken` request by a user within a 10-day window, helping to uncover potential misuse aimed at evading defenses.

**Possible investigation steps**

* Review the specific user account associated with the GetFederationToken request to determine if the activity aligns with their typical behavior and role within the organization.
* Examine the AWS CloudTrail logs for additional context around the time of the GetFederationToken request, looking for any other unusual or suspicious activities by the same user or related accounts.
* Check the source IP address and geolocation of the GetFederationToken request to identify if it originates from an expected or unexpected location.
* Investigate the resources accessed using the temporary credentials obtained from the GetFederationToken request to assess if there was any unauthorized or suspicious access.
* Consult with the user or their manager to verify if the GetFederationToken request was legitimate and necessary for their work tasks.

**False positive analysis**

* Routine administrative tasks by cloud administrators may trigger the rule if they are using `GetFederationToken` for legitimate purposes. To manage this, create exceptions for known administrative accounts that regularly perform these actions.
* Automated scripts or applications that use `GetFederationToken` for legitimate operations might be flagged. Identify these scripts and exclude their associated user accounts from the rule to prevent unnecessary alerts.
* Third-party services integrated with AWS that require temporary credentials might cause false positives. Review and whitelist these services if they are verified and trusted to avoid repeated alerts.
* New employees or contractors accessing AWS resources for the first time may trigger the rule. Implement a process to verify their access requirements and exclude their accounts if their actions are deemed non-threatening.

**Response and remediation**

* Immediately revoke the temporary credentials associated with the `GetFederationToken` request to prevent unauthorized access to AWS resources.
* Review CloudTrail logs to identify any suspicious activities performed using the temporary credentials and assess the potential impact on AWS resources.
* Isolate the affected user account by disabling it temporarily to prevent further unauthorized actions until a thorough investigation is completed.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Conduct a root cause analysis to determine how the `GetFederationToken` request was initiated and identify any potential security gaps or misconfigurations.
* Implement additional monitoring and alerting for `GetFederationToken` requests to detect and respond to similar activities promptly in the future.
* Review and update IAM policies and permissions to ensure that only authorized users have the ability to request temporary credentials, reducing the risk of misuse.


## Rule query [_rule_query_372]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: sts.amazonaws.com
    and event.action: GetFederationToken
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Application Access Token
    * ID: T1550.001
    * Reference URL: [https://attack.mitre.org/techniques/T1550/001/](https://attack.mitre.org/techniques/T1550/001/)



