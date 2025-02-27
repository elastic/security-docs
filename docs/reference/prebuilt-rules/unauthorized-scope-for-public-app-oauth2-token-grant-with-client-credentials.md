---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unauthorized-scope-for-public-app-oauth2-token-grant-with-client-credentials.html
---

# Unauthorized Scope for Public App OAuth2 Token Grant with Client Credentials [unauthorized-scope-for-public-app-oauth2-token-grant-with-client-credentials]

Identifies a failed OAuth 2.0 token grant attempt for a public client app using client credentials. This event is generated when a public client app attempts to exchange a client credentials grant for an OAuth 2.0 access token, but the request is denied due to the lack of required scopes. This could indicate compromised client credentials in which an adversary is attempting to obtain an access token for unauthorized scopes. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule where the `okta.actor.display_name` field value has not been seen in the last 14 days regarding this event.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.blog/news-insights/company-news/security-alert-stolen-oauth-user-tokens/](https://github.blog/news-insights/company-news/security-alert-stolen-oauth-user-tokens/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Domain: SaaS
* Data Source: Okta
* Use Case: Threat Detection
* Use Case: Identity and Access Audit
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 206

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1090]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unauthorized Scope for Public App OAuth2 Token Grant with Client Credentials**

OAuth 2.0 is a protocol for authorization, allowing apps to access resources on behalf of users. Public client apps, lacking secure storage, use client credentials for token grants. Adversaries may exploit compromised credentials to request unauthorized scopes. The detection rule identifies failed token grants due to scope mismatches, signaling potential misuse of client credentials.

**Possible investigation steps**

* Review the `okta.actor.display_name` field to identify the public client app involved in the failed token grant attempt and determine if it is a known or expected application.
* Examine the `okta.debug_context.debug_data.flattened.requestedScopes` field to understand which unauthorized scopes were requested and assess their potential impact if accessed.
* Investigate the `okta.actor.type` field to confirm that the actor is indeed a public client app, which lacks secure storage, and evaluate the risk of compromised credentials.
* Check the `okta.outcome.reason` field for "no_matching_scope" to verify that the failure was due to a scope mismatch, indicating an attempt to access unauthorized resources.
* Analyze the `okta.client.user_agent.raw_user_agent` field to ensure the request did not originate from known Okta integrations, which are excluded from the rule, to rule out false positives.
* Correlate the event with other security logs or alerts to identify any patterns or additional suspicious activities related to the same client credentials or IP address.

**False positive analysis**

* Frequent legitimate access attempts by known public client apps may trigger false positives. To manage this, consider creating exceptions for specific `okta.actor.display_name` values that are known to frequently request scopes without malicious intent.
* Automated processes or integrations that use client credentials might occasionally request scopes not typically associated with their function. Review these processes and, if deemed non-threatening, exclude their `okta.client.user_agent.raw_user_agent` from triggering the rule.
* Development or testing environments often simulate various OAuth 2.0 token grant scenarios, which can result in false positives. Identify and exclude these environments by their `okta.actor.display_name` or other distinguishing attributes.
* Regularly review and update the list of non-threatening scopes in `okta.debug_context.debug_data.flattened.requestedScopes` to ensure that legitimate scope requests are not flagged as unauthorized.

**Response and remediation**

* Immediately revoke the compromised client credentials to prevent further unauthorized access attempts.
* Conduct a thorough review of the affected public client app’s access logs to identify any successful unauthorized access or data exfiltration attempts.
* Notify the application owner and relevant security teams about the incident to ensure coordinated response efforts.
* Implement additional monitoring on the affected app and associated user accounts to detect any further suspicious activities.
* Update and enforce stricter access controls and scope permissions for public client apps to minimize the risk of unauthorized scope requests.
* Consider implementing multi-factor authentication (MFA) for accessing sensitive resources to add an additional layer of security.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if broader organizational impacts exist.


## Rule query [_rule_query_1146]

```js
event.dataset: okta.system
    and event.action: "app.oauth2.as.token.grant"
    and okta.actor.type: "PublicClientApp"
    and okta.debug_context.debug_data.flattened.grantType: "client_credentials"
    and okta.outcome.result: "FAILURE"
    and not okta.client.user_agent.raw_user_agent: "Okta-Integrations"
    and not okta.actor.display_name: (Okta* or Datadog)
    and not okta.debug_context.debug_data.flattened.requestedScopes: ("okta.logs.read" or "okta.eventHooks.read" or "okta.inlineHooks.read")
    and okta.outcome.reason: "no_matching_scope"
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



