---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-attempt-to-create-okta-api-token.html
---

# Attempt to Create Okta API Token [prebuilt-rule-8-17-4-attempt-to-create-okta-api-token]

Detects attempts to create an Okta API token. An adversary may create an Okta API token to maintain access to an organization’s network while they work to achieve their objectives. An attacker may abuse an API token to execute techniques such as creating user accounts or disabling security rules or policies.

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
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 410

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4285]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Attempt to Create Okta API Token**

Okta API tokens are crucial for automating and managing identity and access tasks within an organization. However, if compromised, these tokens can be exploited by adversaries to gain persistent access, manipulate user accounts, or alter security settings. The detection rule identifies suspicious token creation activities by monitoring specific Okta system events, helping to thwart unauthorized access attempts.

**Possible investigation steps**

* Review the event logs for entries with event.dataset:okta.system and event.action:system.api_token.create to identify the specific instance of API token creation.
* Identify the user account associated with the token creation event to determine if the action aligns with their typical behavior or role within the organization.
* Check the timestamp of the event to correlate with other security events or anomalies that occurred around the same time.
* Investigate the IP address and location from which the API token creation request originated to assess if it matches the user’s usual access patterns.
* Examine any recent changes to user accounts or security settings that may have been executed using the newly created API token.
* Review the organization’s policy on API token creation to ensure compliance and determine if the action was authorized.

**False positive analysis**

* Routine administrative tasks may trigger the rule when legitimate IT staff create API tokens for automation or integration purposes. To manage this, maintain a list of authorized personnel and their expected activities, and create exceptions for these known users.
* Scheduled system maintenance or updates might involve creating API tokens, leading to false positives. Document these events and adjust the monitoring window or create temporary exceptions during these periods.
* Third-party integrations that require API tokens for functionality can also trigger alerts. Identify and whitelist these integrations by verifying their necessity and security compliance.
* Development and testing environments often involve frequent token creation for testing purposes. Exclude these environments from the rule or set up separate monitoring with adjusted thresholds to avoid unnecessary alerts.

**Response and remediation**

* Immediately revoke the suspicious Okta API token to prevent any unauthorized access or actions within the organization’s network.
* Conduct a thorough review of recent activities associated with the compromised token to identify any unauthorized changes or access attempts.
* Reset credentials and enforce multi-factor authentication for any accounts that were accessed or potentially compromised using the API token.
* Notify the security team and relevant stakeholders about the incident to ensure awareness and coordination for further investigation and response.
* Implement additional monitoring on Okta API token creation events to detect and respond to any further unauthorized attempts promptly.
* Review and update access controls and permissions related to API token creation to ensure they align with the principle of least privilege.
* Escalate the incident to senior security management if there is evidence of broader compromise or if the threat actor’s objectives are unclear.


## Setup [_setup_1142]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5283]

```js
event.dataset:okta.system and event.action:system.api_token.create
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create Account
    * ID: T1136
    * Reference URL: [https://attack.mitre.org/techniques/T1136/](https://attack.mitre.org/techniques/T1136/)



