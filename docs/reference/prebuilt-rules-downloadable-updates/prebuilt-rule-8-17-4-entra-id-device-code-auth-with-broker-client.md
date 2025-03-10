---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-entra-id-device-code-auth-with-broker-client.html
---

# Entra ID Device Code Auth with Broker Client [prebuilt-rule-8-17-4-entra-id-device-code-auth-with-broker-client]

Identifies device code authentication with an Azure broker client for Entra ID. Adversaries abuse Primary Refresh Tokens (PRTs) to bypass multi-factor authentication (MFA) and gain unauthorized access to Azure resources. PRTs are used in Conditional Access policies to enforce device-based controls. Compromising PRTs allows attackers to bypass these policies and gain unauthorized access. This rule detects successful sign-ins using device code authentication with the Entra ID broker client application ID (29d9ed98-a469-4536-ade2-f981bc1d605e).

**Rule type**: query

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

* [https://dirkjanm.io/assets/raw/Phishing%20the%20Phishing%20Resistant.pdf](https://dirkjanm.io/assets/raw/Phishing%20the%20Phishing%20Resistant.pdf)
* [https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in](https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in)
* [https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)

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

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4083]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Entra ID Device Code Auth with Broker Client**

Entra ID Device Code Authentication allows users to authenticate devices using a code, facilitating seamless access to Azure resources. Adversaries exploit this by compromising Primary Refresh Tokens (PRTs) to bypass multi-factor authentication and Conditional Access policies. The detection rule identifies unauthorized access attempts by monitoring successful sign-ins using device code authentication linked to a specific broker client application ID, flagging potential misuse.

**Possible investigation steps**

* Review the sign-in logs to confirm the use of device code authentication by checking the field azure.signinlogs.properties.authentication_protocol for the value deviceCode.
* Verify the application ID involved in the sign-in attempt by examining azure.signinlogs.properties.conditional_access_audiences.application_id and ensure it matches 29d9ed98-a469-4536-ade2-f981bc1d605e.
* Investigate the user account associated with the successful sign-in to determine if the activity aligns with expected behavior or if it appears suspicious.
* Check for any recent changes or anomalies in the user’s account settings or permissions that could indicate compromise.
* Review the history of sign-ins for the user to identify any patterns or unusual access times that could suggest unauthorized access.
* Assess the device from which the sign-in was attempted to ensure it is a recognized and authorized device for the user.

**False positive analysis**

* Legitimate device code authentication by trusted applications or users may trigger the rule. Review the application ID and user context to confirm legitimacy.
* Frequent access by automated scripts or services using device code authentication can be mistaken for unauthorized access. Identify and document these services, then create exceptions for known application IDs.
* Shared devices in environments with multiple users may cause false positives if device code authentication is used regularly. Implement user-specific logging to differentiate between legitimate and suspicious activities.
* Regular maintenance or updates by IT teams using device code authentication might be flagged. Coordinate with IT to schedule these activities and temporarily adjust monitoring rules if necessary.
* Ensure that any exceptions or exclusions are regularly reviewed and updated to reflect changes in the environment or application usage patterns.

**Response and remediation**

* Immediately revoke the compromised Primary Refresh Tokens (PRTs) to prevent further unauthorized access. This can be done through the Azure portal by navigating to the user’s account and invalidating all active sessions.
* Enforce a password reset for the affected user accounts to ensure that any credentials potentially compromised during the attack are no longer valid.
* Implement additional Conditional Access policies that require device compliance checks and restrict access to trusted locations or devices only, to mitigate the risk of future PRT abuse.
* Conduct a thorough review of the affected accounts' recent activity logs to identify any unauthorized actions or data access that may have occurred during the compromise.
* Escalate the incident to the security operations team for further investigation and to determine if there are any broader implications or additional compromised accounts.
* Enhance monitoring by configuring alerts for unusual sign-in patterns or device code authentication attempts from unexpected locations or devices, to improve early detection of similar threats.
* Coordinate with the incident response team to perform a post-incident analysis and update the incident response plan with lessons learned from this event.


## Setup [_setup_972]

This rule optionally requires Azure Sign-In logs from the Azure integration. Ensure that the Azure integration is correctly set up and that the required data is being collected.


## Rule query [_rule_query_5100]

```js
 event.dataset:(azure.activitylogs or azure.signinlogs)
    and azure.signinlogs.properties.authentication_protocol:deviceCode
    and azure.signinlogs.properties.conditional_access_audiences.application_id:29d9ed98-a469-4536-ade2-f981bc1d605e
    and event.outcome:success or (
        azure.activitylogs.properties.appId:29d9ed98-a469-4536-ade2-f981bc1d605e
        and azure.activitylogs.properties.authentication_protocol:deviceCode)
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



