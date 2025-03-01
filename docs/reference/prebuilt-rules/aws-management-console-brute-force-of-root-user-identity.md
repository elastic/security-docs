---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-management-console-brute-force-of-root-user-identity.html
---

# AWS Management Console Brute Force of Root User Identity [aws-management-console-brute-force-of-root-user-identity]

Identifies a high number of failed authentication attempts to the AWS management console for the Root user identity. An adversary may attempt to brute force the password for the Root user identity, as it has complete access to all services and resources for the AWS account.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-20m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Use Case: Identity and Access Audit
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_63]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS Management Console Brute Force of Root User Identity**

The AWS Management Console is a web-based interface for accessing and managing AWS services. The root user identity has unrestricted access, making it a prime target for adversaries seeking unauthorized control. Attackers may attempt brute force attacks to guess the root password. The detection rule identifies such attempts by monitoring failed login events specifically for the root user, flagging potential credential access threats.

**Possible investigation steps**

* Review the CloudTrail logs for the specific time frame of the failed login attempts to identify patterns or anomalies in the source IP addresses or user agents.
* Check the geographical location of the IP addresses involved in the failed login attempts to determine if they are consistent with known or expected locations for legitimate access.
* Investigate any successful login attempts from the same IP addresses or user agents to assess if the brute force attempt was successful at any point.
* Analyze the frequency and timing of the failed login attempts to determine if they align with typical brute force attack patterns, such as rapid or sequential attempts.
* Correlate the failed login events with other security events or alerts in the AWS environment to identify any concurrent suspicious activities that may indicate a broader attack campaign.
* Review AWS CloudTrail logs for any changes in IAM policies or unusual activity following the failed login attempts to ensure no unauthorized access was gained.

**False positive analysis**

* Legitimate users may forget their password and repeatedly attempt to log in, triggering the rule. To manage this, monitor for patterns of failed logins followed by successful ones and consider excluding these from alerts if they originate from known IP addresses.
* Automated scripts or applications using outdated credentials can cause repeated failed login attempts. Identify and update these credentials or exclude the associated IP addresses from the rule.
* Security testing or penetration testing activities might simulate brute force attacks. Coordinate with your security team to whitelist IP addresses or timeframes associated with these activities to prevent false positives.
* Shared accounts or environments where multiple users attempt to access the root account can lead to multiple failed attempts. Implement stricter access controls and consider excluding known internal IP ranges from the rule.

**Response and remediation**

* Immediately disable the root user account to prevent further unauthorized access attempts. This can be done through the AWS Management Console by navigating to the IAM section and selecting the root user account.
* Review the CloudTrail logs to identify the source IP addresses of the failed login attempts. Block these IP addresses using AWS security groups or network ACLs to prevent further access attempts from these locations.
* Reset the root user password and ensure it is strong and unique. Use a password manager to generate and store the new password securely.
* Enable multi-factor authentication (MFA) for the root user account to add an additional layer of security. This can be configured in the AWS Management Console under the IAM section.
* Conduct a thorough audit of recent account activity to ensure no unauthorized changes have been made. Pay special attention to IAM roles, policies, and permissions.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation. Provide them with details of the attempted breach and actions taken.
* Implement additional monitoring and alerting for unusual login patterns or failed login attempts to the root account to enhance early detection of similar threats in the future.


## Setup [_setup_36]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_66]

```js
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:ConsoleLogin and aws.cloudtrail.user_identity.type:Root and event.outcome:failure
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)



