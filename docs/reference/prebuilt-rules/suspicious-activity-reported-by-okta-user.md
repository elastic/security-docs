---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-activity-reported-by-okta-user.html
---

# Suspicious Activity Reported by Okta User [suspicious-activity-reported-by-okta-user]

Detects when a user reports suspicious activity for their Okta account. These events should be investigated, as they can help security teams identify when an adversary is attempting to gain access to their network.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Use Case: Identity and Access Audit
* Data Source: Okta
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 410

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_966]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Activity Reported by Okta User**

Okta is a widely used identity management service that facilitates secure user authentication and access control. Adversaries may exploit compromised credentials to gain unauthorized access, posing a threat to network security. The detection rule monitors for user-reported suspicious activity, signaling potential unauthorized access attempts. By analyzing these alerts, security teams can swiftly identify and mitigate threats, leveraging Okta’s logging capabilities to trace and respond to malicious actions.

**Possible investigation steps**

* Review the specific event details in the Okta logs where event.dataset is okta.system and event.action is user.account.report_suspicious_activity_by_enduser to gather initial context about the reported activity.
* Identify the user who reported the suspicious activity and check their recent login history and access patterns for any anomalies or deviations from their typical behavior.
* Correlate the reported suspicious activity with other security logs and alerts to determine if there are any related incidents or patterns indicating a broader attack.
* Verify if there are any known vulnerabilities or compromised credentials associated with the user’s account that could have been exploited.
* Contact the user to gather additional information about the suspicious activity they observed and confirm whether they recognize any recent access attempts or changes to their account.
* Assess the risk and potential impact of the suspicious activity on the network and determine if any immediate containment or remediation actions are necessary.

**False positive analysis**

* Users frequently accessing their accounts from new devices or locations may trigger false positives. Implement geofencing or device recognition to reduce these alerts.
* Routine administrative actions, such as password resets or account updates, might be misinterpreted as suspicious. Exclude these actions from alerts if they are performed by known administrators.
* Automated scripts or applications using service accounts can generate alerts if not properly configured. Ensure these accounts are whitelisted or have appropriate permissions set.
* Employees using VPNs or proxy services for remote work can cause location-based false positives. Consider marking known VPN IP addresses as safe.
* High-volume login attempts from legitimate users, such as during password recovery, can be mistaken for suspicious activity. Monitor for patterns and adjust thresholds accordingly.

**Response and remediation**

* Immediately isolate the affected user account by temporarily disabling it to prevent further unauthorized access.
* Notify the user and relevant stakeholders about the suspicious activity and the actions being taken to secure the account.
* Conduct a password reset for the affected user account and enforce multi-factor authentication (MFA) if not already enabled.
* Review recent login activity and access logs for the affected account to identify any unauthorized access or data exfiltration attempts.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if other accounts or systems have been compromised.
* Implement additional monitoring on the affected account and related systems to detect any further suspicious activity.
* Update security policies and procedures based on findings to prevent similar incidents in the future, ensuring alignment with MITRE ATT&CK framework recommendations for Initial Access and Valid Accounts.


## Setup [_setup_613]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_1014]

```js
event.dataset:okta.system and event.action:user.account.report_suspicious_activity_by_enduser
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



