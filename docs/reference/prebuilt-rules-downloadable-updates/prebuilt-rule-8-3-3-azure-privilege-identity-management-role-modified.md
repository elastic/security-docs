---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-azure-privilege-identity-management-role-modified.html
---

# Azure Privilege Identity Management Role Modified [prebuilt-rule-8-3-3-azure-privilege-identity-management-role-modified]

Azure Active Directory (AD) Privileged Identity Management (PIM) is a service that enables you to manage, control, and monitor access to important resources in an organization. PIM can be used to manage the built-in Azure resource roles such as Global Administrator and Application Administrator. An adversary may add a user to a PIM role in order to maintain persistence in their target’s environment or modify a PIM role to weaken their target’s security controls.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-resource-roles-assign-roles](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-resource-roles-assign-roles)
* [https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure](https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure)

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

## Investigation guide [_investigation_guide_2909]

## Triage and analysis

## Investigating Azure Privilege Identity Management Role Modified

Azure Active Directory (AD) Privileged Identity Management (PIM) is a service that enables you to manage, control, and monitor access to important resources in an organization. PIM can be used to manage the built-in Azure resource roles such as Global Administrator and Application Administrator.

This rule identifies the update of PIM role settings, which can indicate that an attacker has already gained enough access to modify role assignment settings.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate other alerts associated with the user account during the past 48 hours.
- Consider the source IP address and geolocation for the user who issued the command. Do they look normal for the user?
- Consider the time of day. If the user is a human, not a program or script, did the activity take place during a normal time of day?
- Check if this operation was approved and performed according to the organization's change management policy.
- Contact the account owner and confirm whether they are aware of this activity.
- Examine the account's commands, API calls, and data management actions in the last 24 hours.
- If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services, and data accessed by the account in the last 24 hours.

## False positive analysis

- If this activity didn't follow your organization's change management policies, it should be reviewed by the security team.

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
- Restore the PIM roles to the desired state.
- Consider enabling multi-factor authentication for users.
- Follow security best practices [outlined](https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices) by Microsoft.
- Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_3329]

```js
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Update role setting in PIM" and event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



