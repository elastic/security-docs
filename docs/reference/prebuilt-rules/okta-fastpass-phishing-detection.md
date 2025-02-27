---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/okta-fastpass-phishing-detection.html
---

# Okta FastPass Phishing Detection [okta-fastpass-phishing-detection]

Detects when Okta FastPass prevents a user from authenticating to a phishing website.

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
* [https://sec.okta.com/fastpassphishingdetection](https://sec.okta.com/fastpassphishingdetection)
* [https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection](https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Tactic: Initial Access
* Use Case: Identity and Access Audit
* Data Source: Okta
* Resources: Investigation Guide

**Version**: 308

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_603]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Okta FastPass Phishing Detection**

Okta FastPass is a passwordless authentication solution that enhances security by verifying user identity without traditional credentials. Adversaries may attempt to exploit this by directing users to phishing sites mimicking legitimate services. The detection rule identifies failed authentication attempts where FastPass blocks access, indicating a phishing attempt, by analyzing specific event patterns and outcomes.

**Possible investigation steps**

* Review the event details to confirm the presence of the specific outcome reason "FastPass declined phishing attempt" to ensure the alert is related to a phishing attempt.
* Identify the user associated with the failed authentication attempt and gather additional context about their recent activities and access patterns.
* Investigate the source IP address and geolocation of the failed authentication attempt to determine if it aligns with the user’s typical access locations or if it appears suspicious.
* Check for any other recent authentication attempts from the same user or IP address to identify potential patterns or repeated phishing attempts.
* Communicate with the affected user to verify if they received any suspicious communications or if they attempted to access any unfamiliar websites around the time of the alert.
* Review any additional logs or alerts from other security systems that might provide further context or corroborate the phishing attempt.

**False positive analysis**

* Legitimate third-party applications that mimic the behavior of phishing sites may trigger false positives. Users can create exceptions for these applications by whitelisting their domains in the Okta FastPass settings.
* Internal testing environments that simulate phishing scenarios for training purposes might be flagged. To prevent this, ensure that these environments are registered and recognized within the Okta system to avoid unnecessary alerts.
* Users accessing legitimate services through unusual network paths or VPNs may be mistakenly identified as phishing attempts. Regularly review and update network configurations and trusted IP addresses to minimize these occurrences.
* Frequent failed authentication attempts due to user error, such as incorrect device settings or outdated software, can be mistaken for phishing. Educate users on maintaining their devices and software to align with Okta FastPass requirements to reduce these false positives.

**Response and remediation**

* Immediately isolate the affected user accounts to prevent further unauthorized access attempts. This can be done by temporarily disabling the accounts or enforcing additional authentication measures.
* Notify the affected users about the phishing attempt and instruct them to avoid interacting with suspicious emails or websites. Provide guidance on recognizing phishing attempts.
* Conduct a thorough review of the affected users' recent activities to identify any potential data exposure or unauthorized access to sensitive information.
* Escalate the incident to the security operations team for further investigation and to determine if there are any broader implications or related incidents.
* Implement additional monitoring on the affected accounts and related systems to detect any further suspicious activities or attempts to bypass security controls.
* Review and update security policies and configurations related to Okta FastPass to ensure they are optimized for detecting and preventing similar phishing attempts in the future.
* Coordinate with the IT team to ensure that all systems and applications are patched and up-to-date to mitigate any vulnerabilities that could be exploited in conjunction with phishing attacks.


## Setup [_setup_389]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.

This rule requires Okta to have the following turned on:

Okta Identity Engine - select *Phishing Resistance for FastPass* under Settings > Features in the Admin Console.


## Rule query [_rule_query_645]

```js
event.dataset:okta.system and event.category:authentication and
  okta.event_type:user.authentication.auth_via_mfa and event.outcome:failure and okta.outcome.reason:"FastPass declined phishing attempt"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)



