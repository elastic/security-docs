---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-microsoft-365-portal-login-from-rare-location.html
---

# Microsoft 365 Portal Login from Rare Location [prebuilt-rule-8-17-4-microsoft-365-portal-login-from-rare-location]

Detects successful Microsoft 365 portal logins from rare locations. Rare locations are defined as locations that are not commonly associated with the user’s account. This behavior may indicate an adversary attempting to access a Microsoft 365 account from an unusual location or behind a VPN.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-o365.audit-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.huntress.com/blog/time-travelers-busted-how-to-detect-impossible-travel-](https://www.huntress.com/blog/time-travelers-busted-how-to-detect-impossible-travel-)

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Threat Detection
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4233]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Portal Login from Rare Location**

Microsoft 365 is a cloud-based suite offering productivity tools accessible from anywhere, making it crucial for business operations. Adversaries may exploit this by logging in from uncommon locations, potentially using VPNs to mask their origin. The detection rule identifies successful logins from atypical locations, flagging potential unauthorized access attempts by analyzing login events and user location patterns.

**Possible investigation steps**

* Review the login event details from the o365.audit dataset to confirm the user’s identity and the timestamp of the login.
* Analyze the location data associated with the login event to determine if it is indeed rare or unusual for the user’s typical access patterns.
* Check the user’s recent login history to identify any other logins from the same rare location or any other unusual locations.
* Investigate the IP address used during the login to determine if it is associated with known VPN services or suspicious activity.
* Contact the user to verify if they initiated the login from the rare location or if they are aware of any unauthorized access attempts.
* Examine any recent changes to the user’s account settings or permissions that could indicate compromise or unauthorized access.
* Correlate this event with other security alerts or logs to identify any patterns or additional indicators of compromise.

**False positive analysis**

* Users traveling frequently may trigger alerts due to logins from new locations. Implement a process to update known travel patterns for these users to reduce false positives.
* Employees using VPNs for legitimate purposes might appear to log in from rare locations. Maintain a list of approved VPN IP addresses and exclude them from triggering alerts.
* Remote workers who occasionally connect from different locations can cause false positives. Establish a baseline of expected locations for these users and adjust the detection rule accordingly.
* Shared accounts accessed by multiple users from different locations can lead to false alerts. Consider monitoring these accounts separately and applying stricter access controls.
* Temporary relocations, such as business trips or remote work arrangements, may result in unusual login locations. Communicate with users to anticipate these changes and adjust the detection parameters temporarily.

**Response and remediation**

* Immediately isolate the affected user account by disabling it to prevent further unauthorized access.
* Notify the user and relevant IT security personnel about the suspicious login activity to ensure awareness and initiate further investigation.
* Conduct a password reset for the affected account and enforce multi-factor authentication (MFA) if not already enabled to enhance account security.
* Review and analyze recent activity logs for the affected account to identify any unauthorized actions or data access that may have occurred.
* If unauthorized access is confirmed, initiate a security incident response plan, including data breach notification procedures if necessary.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems or accounts are compromised.
* Implement geo-blocking or conditional access policies to restrict access from rare or high-risk locations, reducing the likelihood of similar incidents in the future.


## Rule query [_rule_query_5231]

```js
event.dataset: "o365.audit"
    and event.provider: "AzureActiveDirectory"
    and event.action: "UserLoggedIn"
    and event.outcome: "success"
    and not o365.audit.UserId: "Not Available"
    and o365.audit.Target.Type: ("0" or "2" or "3" or "5" or "6" or "10")
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

* Sub-technique:

    * Name: Cloud Accounts
    * ID: T1078.004
    * Reference URL: [https://attack.mitre.org/techniques/T1078/004/](https://attack.mitre.org/techniques/T1078/004/)



