---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-powershell-kerberos-ticket-request.html
---

# PowerShell Kerberos Ticket Request [prebuilt-rule-1-0-2-powershell-kerberos-ticket-request]

Detects PowerShell scripts that have the capability of requesting Kerberos tickets, which is a common step in Kerberoasting toolkits to crack service accounts.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cobalt.io/blog/kerberoast-attack-techniques](https://cobalt.io/blog/kerberoast-attack-techniques)
* [https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1364]

## Triage and analysis

## Investigating Explicit PowerShell Kerberos Ticket Request

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks, making
it available for use in various environments, creating an attractive way for attackers to execute code.

Accounts associated with a service principal name (SPN) are viable targets for Kerberoasting attacks, which use brute
force to crack the user password, which is used to encrypt a Kerberos TGS ticket.

Attackers can use PowerShell to request these Kerberos tickets, with the intent of extracting them from memory to
perform Kerberoasting.

### Possible investigation steps

- Retrieve the script contents.
- Investigate the script execution chain (parent process tree).
- Investigate if the script was executed, and if so, which account was targeted.
- Check whether this user should be doing this kind of activity.
- Contact the account owner and confirm whether they are aware of this activity.
- Check if the script has any other functionality that can be potentially malicious.
- Investigate other alerts related to the host and user in the last 48 hours.
- Review event ID [4769](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
related to this account and service name for additional information.

## False positive analysis

- A possible false positive can be identified if the script content is not malicious/harmful or does not request
Kerberos tickets for user accounts, as computer accounts are not vulnerable to Kerberoasting due to complex password
requirements and policy.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Reset the password of the involved accounts. Priority should be given to privileged accounts.
- Quarantine the involved host for forensic investigation, as well as eradication and recovery activities.

## Rule query [_rule_query_1593]

```js
event.category:process and
  powershell.file.script_block_text : (
    KerberosRequestorSecurityToken
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Technique:

    * Name: Steal or Forge Kerberos Tickets
    * ID: T1558
    * Reference URL: [https://attack.mitre.org/techniques/T1558/](https://attack.mitre.org/techniques/T1558/)

* Sub-technique:

    * Name: Kerberoasting
    * ID: T1558.003
    * Reference URL: [https://attack.mitre.org/techniques/T1558/003/](https://attack.mitre.org/techniques/T1558/003/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)



