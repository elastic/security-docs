---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-multi-factor-authentication-disabled-for-an-azure-user.html
---

# Multi-Factor Authentication Disabled for an Azure User [prebuilt-rule-8-2-1-multi-factor-authentication-disabled-for-an-azure-user]

Identifies when multi-factor authentication (MFA) is disabled for an Azure user account. An adversary may disable MFA for a user account in order to weaken the authentication requirements for the account.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-azure*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-25m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Cloud
* Azure
* Continuous Monitoring
* SecOps
* Identity and Access

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1921]

## Triage and analysis

## Investigating Multi-Factor Authentication Disabled for an Azure User

Multi-factor authentication is a process in which users are prompted during the sign-in process for an additional form
of identification, such as a code on their cellphone or a fingerprint scan.

If you only use a password to authenticate a user, it leaves an insecure vector for attack. If the password is weak or
has been exposed elsewhere, an attacker could be using it to gain access. When you require a second form of authentication,
security is increased because this additional factor isn't something that's easy for an attacker to obtain or duplicate.

For more information about using MFA in Azure AD, access the [official documentation](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks#how-to-enable-and-use-azure-ad-multi-factor-authentication).

This rule identifies the deactivation of MFA for an Azure user account. This modification weakens account security
and can lead to the compromise of accounts and other assets.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate other alerts associated with the user account during the past 48 hours.
- Contact the account and resource owners and confirm whether they are aware of this activity.
- Check if this operation was approved and performed according to the organization's change management policy.
- If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services,
and data accessed by the account in the last 24 hours.

## False positive analysis

- While this activity can be done by administrators, all users must use MFA. The security team should address any
potential benign true positive (B-TP), as this configuration can risk the user and domain.

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
- Reactivate multi-factor authentication for the user.
- Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
- Implement security defaults [provided by Microsoft](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults).
- Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2206]

```js
event.dataset:azure.auditlogs and azure.auditlogs.operation_name:"Disable Strong Authentication" and event.outcome:(Success or success)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



