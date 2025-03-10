---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-disabling-windows-defender-security-settings-via-powershell.html
---

# Disabling Windows Defender Security Settings via PowerShell [prebuilt-rule-8-3-2-disabling-windows-defender-security-settings-via-powershell]

Identifies use of the Set-MpPreference PowerShell command to disable or weaken certain Windows Defender settings.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps](https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* has_guide

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2444]

## Triage and analysis

## Investigating Disabling Windows Defender Security Settings via PowerShell

Microsoft Windows Defender is an antivirus product built into Microsoft Windows, which makes it popular across multiple
environments. Disabling it is a common step in threat actor playbooks.

This rule monitors the execution of commands that can tamper the Windows Defender antivirus features.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Validate the activity is not related to planned patches, updates, network administrator activity, or legitimate
software installations.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Examine the command line to determine which action was executed. Based on that, examine exceptions, antivirus state,
sample submission, etc.

## False positive analysis

- This mechanism can be used legitimately. Analysts can dismiss the alert if the administrator is aware of the activity,
the configuration is justified (for example, it is being used to deploy other security solutions or troubleshooting),
and no other suspicious activity has been observed.

## Related rules

- Windows Defender Disabled via Registry Modification - 2ffa1f1e-b6db-47fa-994b-1512743847eb
- Microsoft Windows Defender Tampering - fe794edd-487f-4a90-b285-3ee54f2af2d3

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Based on the command line, take actions to restore the appropriate Windows Defender antivirus configurations.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Review the privileges assigned to the user to ensure that the least privilege principle is being followed.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2811]

```js
process where event.type == "start" and
 (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name in ("powershell.exe", "pwsh.dll", "powershell_ise.exe")) and
 process.args : "Set-MpPreference" and process.args : ("-Disable*", "Disabled", "NeverSend", "-Exclusion*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



