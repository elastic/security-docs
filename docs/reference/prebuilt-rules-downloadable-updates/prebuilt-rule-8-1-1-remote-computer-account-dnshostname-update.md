---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-remote-computer-account-dnshostname-update.html
---

# Remote Computer Account DnsHostName Update [prebuilt-rule-8-1-1-remote-computer-account-dnshostname-update]

Identifies the remote update to a computer account’s DnsHostName attribute. If the new value set is a valid domain controller DNS hostname and the subject computer name is not a domain controller, then it’s highly likely a preparation step to exploit CVE-2022-26923 in an attempt to elevate privileges from a standard domain user to domain admin privileges.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)
* [https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2022-26923](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2022-26923)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation
* Active Directory

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1961]

```js
sequence by host.id with maxspan=5m

  [authentication where event.action == "logged-in" and
   winlog.logon.type == "Network" and event.outcome == "success" and
   not user.name == "ANONYMOUS LOGON" and not winlog.event_data.SubjectUserName : "*$" and
   not user.domain == "NT AUTHORITY" and source.ip != "127.0.0.1" and source.ip !="::1"] by winlog.event_data.TargetLogonId

  [iam where event.action == "changed-computer-account" and

   /* if DnsHostName value equal a DC DNS hostname then it's highly suspicious */
    winlog.event_data.DnsHostName : "??*"] by winlog.event_data.SubjectLogonId
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Domain Accounts
    * ID: T1078.002
    * Reference URL: [https://attack.mitre.org/techniques/T1078/002/](https://attack.mitre.org/techniques/T1078/002/)



