---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-stolen-credentials-used-to-login-to-okta-account-after-mfa-reset.html
---

# Stolen Credentials Used to Login to Okta Account After MFA Reset [prebuilt-rule-8-17-4-stolen-credentials-used-to-login-to-okta-account-after-mfa-reset]

Detects a sequence of suspicious activities on Windows hosts indicative of credential compromise, followed by efforts to undermine multi-factor authentication (MFA) and single sign-on (SSO) mechanisms for an Okta user account.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-okta*
* .alerts-security.*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 6h

**Searches indices from**: now-12h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection](https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Tactic: Persistence
* Use Case: Identity and Access Audit
* Data Source: Okta
* Data Source: Elastic Defend
* Rule Type: Higher-Order Rule
* Domain: Endpoint
* Domain: Cloud
* Resources: Investigation Guide

**Version**: 206

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4290]

**Triage and analysis**

**Investigating Stolen Credentials Used to Login to Okta Account After MFA Reset**

This rule detects a sequence of suspicious activities on Windows hosts indicative of credential compromise, followed by efforts to undermine multi-factor authentication (MFA) and single sign-on (SSO) mechanisms for an Okta user account.

Typically, adversaries initially extract credentials from targeted endpoints through various means. Subsequently, leveraging social engineering, they may seek to reset the MFA credentials associated with an Okta account, especially in scenarios where Active Directory (AD) services are integrated with Okta. Successfully resetting MFA allows the unauthorized use of stolen credentials to gain access to the compromised Okta account. The attacker can then register their own device for MFA, paving the way for unfettered access to the user’s Okta account and any associated SaaS applications. This is particularly alarming if the compromised account has administrative rights, as it could lead to widespread access to organizational resources and configurations.

**Possible investigation steps:**

* Identify the user account associated with the Okta login attempt by examining the `user.name` field.
* Identify the endpoint for the Credential Access alert for this user by examining the `host.name` and `host.id` fields from the alert document.
* Cross-examine the Okta user and endpoint user to confirm that they are the same person.
* Reach out to the user to confirm if they have intentionally reset their MFA credentials recently or asked for help in doing so.
* If the user is unaware of the MFA reset, incident response may be required immediately to prevent further compromise.

**False positive analysis:**

* A Windows administrator may have triggered a low-fidelity credential access alert during a legitimate administrative action. Following this, the administrator may have reset the MFA credentials for themselves and then logged into the Okta console for AD directory services integration management.

**Response and remediation:**

* If confirmed that the user did not intentionally have their MFA factor reset, deactivate the user account.
* After deactivation, reset the user’s password and MFA factor to regain control of the account.
* Ensure that all user sessions are stopped during this process.
* Immediately reset the user’s AD password as well if Okta does not sync back to AD.
* Forensic analysis on the user’s endpoint may be required to determine the root cause of the compromise and identify the scope of the compromise.
* Review Okta system logs to identify any other suspicious activity associated with the user account, such as creation of a backup account.
* With the device ID captured from the MFA factor reset, search across all Okta logs for any other activity associated with the device ID.

**Setup**


## Setup [_setup_1147]

The Okta and Elastic Defend fleet integration structured data is required to be compatible with this rule. Directory services integration in Okta with AD synced is also required for this rule to be effective as it relies on triaging `user.name` from Okta and Elastic Defend events.


## Rule query [_rule_query_5288]

```js
sequence by user.name with maxspan=12h
    [any where host.os.type == "windows" and signal.rule.threat.tactic.name == "Credential Access"]
    [any where event.dataset == "okta.system" and okta.event_type == "user.mfa.factor.update"]
    [any where event.dataset == "okta.system" and okta.event_type: ("user.session.start", "user.authentication*")]
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



