---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-user-account-exposed-to-kerberoasting.html
---

# User account exposed to Kerberoasting [prebuilt-rule-8-7-1-user-account-exposed-to-kerberoasting]

Detects when a user account has the servicePrincipalName attribute modified. Attackers can abuse write privileges over a user to configure Service Principle Names (SPNs) so that they can perform Kerberoasting. Administrators can also configure this for legitimate purposes, exposing the account to Kerberoasting.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.thehacker.recipes/ad/movement/access-controls/targeted-kerberoasting](https://www.thehacker.recipes/ad/movement/access-controls/targeted-kerberoasting)
* [https://www.qomplx.com/qomplx-knowledge-kerberoasting-attacks-explained/](https://www.qomplx.com/qomplx-knowledge-kerberoasting-attacks-explained/)
* [https://www.thehacker.recipes/ad/movement/kerberos/kerberoast](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast)
* [https://attack.stealthbits.com/cracking-kerberos-tgs-tickets-using-kerberoasting](https://attack.stealthbits.com/cracking-kerberos-tgs-tickets-using-kerberoasting)
* [https://adsecurity.org/?p=280](https://adsecurity.org/?p=280)
* [https://github.com/OTRF/Set-AuditRule](https://github.com/OTRF/Set-AuditRule)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access
* Active Directory
* Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3853]

## Triage and analysis

## Investigating User account exposed to Kerberoasting

Service Principal Names (SPNs) are names by which Kerberos clients uniquely identify service instances for Kerberos target computers.

By default, only computer accounts have SPNs, which creates no significant risk, since machine accounts have a default domain policy that rotates their passwords every 30 days, and the password is composed of 120 random characters, making them invulnerable to Kerberoasting.

A user account with an SPN assigned is considered a service account, and is accessible to the entire domain. If any user in the directory requests a ticket-granting service (TGS), the domain controller will encrypt it with the secret key of the account executing the service. An attacker can potentially perform a Kerberoasting attack with this information, as the human-defined password is likely to be less complex.

For scenarios where SPNs cannot be avoided on user accounts, Microsoft provides the Group Managed Service Accounts (gMSA) feature, which ensures that account passwords are robust and changed regularly and automatically. More information can be found [here](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview).

Attackers can also perform "Targeted Kerberoasting", which consists of adding fake SPNs to user accounts that they have write privileges to, making them potentially vulnerable to Kerberoasting.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate if the target account is a member of privileged groups (Domain Admins, Enterprise Admins, etc.).
- Investigate if tickets have been requested for the target account.
- Investigate other alerts associated with the user/host during the past 48 hours.

## False positive analysis

- The use of user accounts as service accounts is a bad security practice and should not be allowed in the domain. The security team should map and monitor any potential benign true positive (B-TP), especially if the account is privileged. Domain Administrators that define this kind of setting can put the domain at risk as user accounts don't have the same security standards as computer accounts (which have long, complex, random passwords that change frequently), exposing them to credential cracking attacks (Kerberoasting, brute force, etc.).

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services. Prioritize privileged accounts.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4732]

```js
event.action:"Directory Service Changes" and event.code:5136 and winlog.event_data.ObjectClass:"user"
and winlog.event_data.AttributeLDAPDisplayName:"servicePrincipalName"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal or Forge Kerberos Tickets
    * ID: T1558
    * Reference URL: [https://attack.mitre.org/techniques/T1558/](https://attack.mitre.org/techniques/T1558/)

* Sub-technique:

    * Name: Kerberoasting
    * ID: T1558.003
    * Reference URL: [https://attack.mitre.org/techniques/T1558/003/](https://attack.mitre.org/techniques/T1558/003/)



