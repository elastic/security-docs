---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-azure-active-directory-powershell-sign-in.html
---

# Azure Active Directory PowerShell Sign-in [prebuilt-rule-8-4-2-azure-active-directory-powershell-sign-in]

Identifies a sign-in using the Azure Active Directory PowerShell module. PowerShell for Azure Active Directory allows for managing settings from the command line, which is intended for users who are members of an admin role.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/)
* [https://docs.microsoft.com/en-us/microsoft-365/enterprise/connect-to-microsoft-365-powershell?view=o365-worldwide](https://docs.microsoft.com/en-us/microsoft-365/enterprise/connect-to-microsoft-365-powershell?view=o365-worldwide)

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Identity and Access
* Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3270]

## Triage and analysis

## Investigating Azure Active Directory PowerShell Sign-in

Azure Active Directory PowerShell for Graph (Azure AD PowerShell) is a module IT professionals commonly use to manage their Azure Active Directory. The cmdlets in the Azure AD PowerShell module enable you to retrieve data from the directory, create new objects in the directory, update existing objects, remove objects, as well as configure the directory and its features.

This rule identifies sign-ins that use the Azure Active Directory PowerShell module, which can indicate unauthorized access if done outside of IT or engineering.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Evaluate whether the user needs to access Azure AD using PowerShell to complete its tasks.
- Investigate other alerts associated with the user account during the past 48 hours.
- Consider the source IP address and geolocation for the involved user account. Do they look normal?
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate suspicious actions taken by the user using the module, for example, modifications in security settings that weakens the security policy, persistence-related tasks, and data access.
- If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services, and data accessed by the account in the last 24 hours.

## False positive analysis

- If this activity is expected and noisy in your environment, consider adding IT, Engineering, and other authorized users as exceptions — preferably with a combination of user and device conditions.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Disable or limit the account during the investigation and response.
- Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
    - Identify the account role in the cloud environment.
    - Assess the criticality of affected services and servers.
    - Work with your IT team to identify and minimize the impact on users.
    - Identify if the attacker is moving laterally and compromising other accounts, servers, or services.
    - Identify any regulatory or legal ramifications related to this activity.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords or delete API keys as needed to revoke the attacker's access to the environment. Work with your IT teams to minimize the impact on business operations during these actions.
- Check if unauthorized new users were created, remove unauthorized new accounts, and request password resets for other IAM users.
- Consider enabling multi-factor authentication for users.
- Follow security best practices [outlined](https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices) by Microsoft.
- Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_3833]

```js
event.dataset:azure.signinlogs and
  azure.signinlogs.properties.app_display_name:"Azure Active Directory PowerShell" and
  azure.signinlogs.properties.token_issuer_type:AzureAD and event.outcome:(success or Success)
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



