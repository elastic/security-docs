---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-first-occurrence-of-entra-id-auth-via-devicecode-protocol.html
---

# First Occurrence of Entra ID Auth via DeviceCode Protocol [prebuilt-rule-8-17-4-first-occurrence-of-entra-id-auth-via-devicecode-protocol]

Identifies when a user is observed for the first time in the last 14 days authenticating using the deviceCode protocol. The device code authentication flow can be abused by attackers to phish users and steal access tokens to impersonate the victim. By its very nature, device code should only be used when logging in to devices without keyboards, where it is difficult to enter emails and passwords.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-azure.signinlogs-*
* logs-azure.activitylogs-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://aadinternals.com/post/phishing/](https://aadinternals.com/post/phishing/)
* [https://www.blackhillsinfosec.com/dynamic-device-code-phishing/](https://www.blackhillsinfosec.com/dynamic-device-code-phishing/)

**Tags**:

* Domain: Cloud
* Data Source: Azure
* Data Source: Microsoft Entra ID
* Use Case: Identity and Access Audit
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic
* Matteo Potito Giorgio

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4086]

**Triage and analysis**

[TBC: QUOTE]
**Investigating First Occurrence of Entra ID Auth via DeviceCode Protocol**

The DeviceCode protocol facilitates authentication for devices lacking keyboards, streamlining user access without manual credential entry. However, attackers can exploit this by phishing users to capture access tokens, enabling unauthorized access. The detection rule identifies new instances of this protocol use, flagging potential misuse by monitoring successful authentications within a 14-day window, thus aiding in early threat detection.

**Possible investigation steps**

* Review the event logs to confirm the presence of the deviceCode protocol in the authentication process by checking the fields azure.signinlogs.properties.authentication_protocol or azure.activitylogs.properties.authentication_protocol.
* Verify the event outcome by examining the event.outcome field to ensure the authentication was successful.
* Identify the user associated with the authentication attempt and review their recent activity for any anomalies or signs of compromise.
* Check the device information to determine if the authentication was performed on a device that typically lacks a keyboard, which would justify the use of the deviceCode protocol.
* Investigate any recent phishing attempts or suspicious communications that could have targeted the user to capture their access tokens.
* Assess the risk score and severity to prioritize the investigation and determine if immediate action is required to mitigate potential threats.

**False positive analysis**

* Legitimate device setup activities may trigger alerts when new devices without keyboards are being configured. To manage this, maintain a list of known devices and exclude their initial setup from triggering alerts.
* Regular use of shared devices in environments like conference rooms or kiosks can result in repeated alerts. Implement a policy to track and whitelist these shared devices to prevent unnecessary alerts.
* Automated scripts or applications using the deviceCode protocol for legitimate purposes might be flagged. Identify and document these scripts, then create exceptions for their activity to avoid false positives.
* Users who frequently travel and use different devices may trigger alerts. Monitor and verify these users' travel patterns and device usage, and consider excluding their known travel-related activities from the rule.

**Response and remediation**

* Immediately revoke the access tokens associated with the suspicious deviceCode authentication to prevent further unauthorized access.
* Conduct a thorough review of the affected user’s account activity to identify any unauthorized actions or data access that may have occurred.
* Reset the credentials of the affected user and enforce multi-factor authentication (MFA) to enhance account security.
* Isolate any devices that were authenticated using the deviceCode protocol to prevent potential lateral movement within the network.
* Notify the security operations team and escalate the incident to ensure a coordinated response and further investigation into potential phishing attempts.
* Implement additional monitoring for anomalous deviceCode protocol usage across the organization to detect similar threats in the future.
* Review and update access policies to restrict the use of the deviceCode protocol to only those devices and scenarios where it is absolutely necessary.


## Setup [_setup_973]

This rule optionally requires Azure Sign-In logs from the Azure integration. Ensure that the Azure integration is correctly set up and that the required data is being collected.


## Rule query [_rule_query_5103]

```js
 event.dataset:(azure.activitylogs or azure.signinlogs) and
     (azure.signinlogs.properties.authentication_protocol:deviceCode or azure.activitylogs.properties.authentication_protocol:deviceCode) and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal Application Access Token
    * ID: T1528
    * Reference URL: [https://attack.mitre.org/techniques/T1528/](https://attack.mitre.org/techniques/T1528/)



