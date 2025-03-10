---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-azure-active-directory-high-risk-sign-in.html
---

# Azure Active Directory High Risk Sign-in [prebuilt-rule-8-4-1-azure-active-directory-high-risk-sign-in]

Identifies high risk Azure Active Directory (AD) sign-ins by leveraging Microsoft’s Identity Protection machine learning and heuristics. Identity Protection categorizes risk into three tiers: low, medium, and high. While Microsoft does not provide specific details about how risk is calculated, each level brings higher confidence that the user or sign-in is compromised.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk)
* [https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection)
* [https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-investigate-risk](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-investigate-risk)

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Identity and Access
* Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic
* Willem D’Haese

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2610]

## Triage and analysis

## Investigating Azure Active Directory High Risk Sign-in

Microsoft Identity Protection is an Azure AD security tool that detects various types of identity risks and attacks.

This rule identifies events produced by Microsoft Identity Protection with high risk levels or high aggregated risk level.

### Possible investigation steps

- Identify the Risk Detection that triggered the event. A list with descriptions can be found [here](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks#risk-types-and-detection).
- Identify the user account involved and validate whether the suspicious activity is normal for that user.
  - Consider the source IP address and geolocation for the involved user account. Do they look normal?
  - Consider the device used to sign in. Is it registered and compliant?
- Investigate other alerts associated with the user account during the past 48 hours.
- Contact the account owner and confirm whether they are aware of this activity.
- Check if this operation was approved and performed according to the organization's change management policy.
- If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services,
and data accessed by the account in the last 24 hours.

## False positive analysis

If this rule is noisy in your environment due to expected activity, consider adding exceptions — preferably with a
combination of user and device conditions.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Disable or limit the account during the investigation and response.
- Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
    - Identify the account role in the cloud environment.
    - Assess the criticality of affected services and servers.
    - Work with your IT team to identify and minimize the impact on users.
    - Identify if the attacker is moving laterally and compromising other accounts, servers, or services.
    - Identify any regulatory or legal ramifications related to this activity.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords or delete API keys as needed to revoke the attacker's access to the environment. Work with
your IT teams to minimize the impact on business operations during these actions.
- Check if unauthorized new users were created, remove unauthorized new accounts, and request password resets for other
IAM users.
- Consider enabling multi-factor authentication for users.
- Follow security best practices [outlined](https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices) by Microsoft.
- Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2996]

```js
event.dataset:azure.signinlogs and
  (azure.signinlogs.properties.risk_level_during_signin:high or azure.signinlogs.properties.risk_level_aggregated:high) and
  event.outcome:(success or Success)
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



