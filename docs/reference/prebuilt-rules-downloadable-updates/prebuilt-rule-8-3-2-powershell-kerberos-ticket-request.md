---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-powershell-kerberos-ticket-request.html
---

# PowerShell Kerberos Ticket Request [prebuilt-rule-8-3-2-powershell-kerberos-ticket-request]

Detects PowerShell scripts that have the capability of requesting kerberos tickets, which is a common step in Kerberoasting toolkits to crack service accounts.

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
* has_guide

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2426]

## Triage and analysis

## Investigating Explicit PowerShell Kerberos Ticket Request

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks, making
it available for use in various environments, creating an attractive way for attackers to execute code.

Accounts associated with a service principal name (SPN) are viable targets for Kerberoasting attacks, which use brute
force to crack the user password, which is used to encrypt a Kerberos TGS ticket.

Attackers can use PowerShell to request these Kerberos tickets, with the intent of extracting them from memory to
perform Kerberoasting.

### Possible investigation steps

- Examine the script content that triggered the detection; look for suspicious DLL imports, collection or exfiltration
capabilities, suspicious functions, encoded or compressed data, and other potentially malicious characteristics.
- Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for
prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate if the script was executed, and if so, which account was targeted.
- Validate if the account has an SPN associated with it.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Check if the script has any other functionality that can be potentially malicious.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Review event ID [4769](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
related to this account and service name for additional information.

## False positive analysis

- A possible false positive can be identified if the script content is not malicious/harmful or does not request
Kerberos tickets for user accounts, as computer accounts are not vulnerable to Kerberoasting due to complex password
requirements and policy.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services. Prioritize privileged accounts.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2792]

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



