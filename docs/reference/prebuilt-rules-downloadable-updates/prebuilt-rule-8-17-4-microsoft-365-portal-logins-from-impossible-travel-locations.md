---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-microsoft-365-portal-logins-from-impossible-travel-locations.html
---

# Microsoft 365 Portal Logins from Impossible Travel Locations [prebuilt-rule-8-17-4-microsoft-365-portal-logins-from-impossible-travel-locations]

Detects successful Microsoft 365 portal logins from impossible travel locations. Impossible travel locations are defined as two different countries within a short time frame. This behavior may indicate an adversary attempting to access a Microsoft 365 account from a compromised account or a malicious actor attempting to access a Microsoft 365 account from a different location.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-o365.audit-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-15m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

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

## Investigation guide [_investigation_guide_4232]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Portal Logins from Impossible Travel Locations**

Microsoft 365’s cloud-based services enable global access, but this can be exploited by adversaries logging in from disparate locations within short intervals, indicating potential account compromise. The detection rule identifies such anomalies by analyzing login events for rapid geographic shifts, flagging suspicious activity that may suggest unauthorized access attempts.

**Possible investigation steps**

* Review the login events associated with the specific UserId flagged in the alert to confirm the occurrence of logins from different countries within a short time frame.
* Check the IP addresses associated with the login events to determine if they are from known or suspicious sources, and verify if they are consistent with the user’s typical login behavior.
* Investigate the user’s recent activity in Microsoft 365 to identify any unusual or unauthorized actions that may indicate account compromise.
* Contact the user to verify if they were traveling or using a VPN service that could explain the login from an unexpected location.
* Examine any recent changes to the user’s account settings or permissions that could suggest unauthorized access or tampering.
* Review the organization’s security logs and alerts for any other suspicious activities or patterns that might correlate with the detected anomaly.

**False positive analysis**

* Frequent business travelers may trigger false positives due to legitimate logins from different countries within short time frames. To manage this, create exceptions for users with known travel patterns by whitelisting their accounts or using conditional access policies.
* Use of VPNs or proxy services can result in logins appearing from different geographic locations. Identify and exclude IP ranges associated with trusted VPN services to reduce false positives.
* Employees working remotely from different countries may cause alerts. Implement user-based exceptions for remote workers who regularly log in from multiple locations.
* Automated systems or services that log in from various locations for legitimate reasons can be mistaken for suspicious activity. Exclude these service accounts from the rule to prevent unnecessary alerts.
* Consider time zone differences that might affect the perceived timing of logins. Adjust the rule’s sensitivity to account for legitimate time zone shifts that could appear as impossible travel.

**Response and remediation**

* Immediately isolate the affected user account by disabling it to prevent further unauthorized access.
* Initiate a password reset for the compromised account and enforce multi-factor authentication (MFA) to enhance security.
* Review recent login activity and audit logs for the affected account to identify any unauthorized access or data exfiltration attempts.
* Notify the user of the suspicious activity and advise them to verify any recent changes or actions taken on their account.
* Escalate the incident to the security operations team for further investigation and to determine if other accounts or systems have been compromised.
* Implement geo-blocking for high-risk countries or regions where the organization does not typically conduct business to prevent similar unauthorized access attempts.
* Update and refine security monitoring rules to enhance detection of similar anomalous login patterns in the future.


## Rule query [_rule_query_5230]

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



