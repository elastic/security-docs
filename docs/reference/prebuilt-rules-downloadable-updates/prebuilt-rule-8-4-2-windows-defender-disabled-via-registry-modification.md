---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-windows-defender-disabled-via-registry-modification.html
---

# Windows Defender Disabled via Registry Modification [prebuilt-rule-8-4-2-windows-defender-disabled-via-registry-modification]

Identifies modifications to the Windows Defender registry settings to disable the service or set the service to be started manually.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://thedfirreport.com/2020/12/13/defender-control/](https://thedfirreport.com/2020/12/13/defender-control/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* Investigation Guide
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3392]

## Triage and analysis

## Investigating Windows Defender Disabled via Registry Modification

Microsoft Windows Defender is an antivirus product built into Microsoft Windows, which makes it popular across multiple environments. Disabling it is a common step in threat actor playbooks.

This rule monitors the registry for configurations that disable Windows Defender or the start of its service.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Validate the activity is not related to planned patches, updates, network administrator activity, or legitimate software installations.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Check if this operation was approved and performed according to the organization's change management policy.

## False positive analysis

- This mechanism can be used legitimately. Analysts can dismiss the alert if the administrator is aware of the activity, the configuration is justified (for example, it is being used to deploy other security solutions or troubleshooting), and no other suspicious activity has been observed.

## Related rules

- Disabling Windows Defender Security Settings via PowerShell - c8cccb06-faf2-4cd5-886e-2c9636cfcb87
- Microsoft Windows Defender Tampering - fe794edd-487f-4a90-b285-3ee54f2af2d3

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Re-enable Windows Defender and restore the service configurations to automatic start.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Review the privileges assigned to the user to ensure that the least privilege principle is being followed.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4034]

```js
registry where event.type in ("creation", "change") and
  (
    (
      registry.path: (
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware"
      ) and
      registry.data.strings: ("1", "0x00000001")
   ) or
   (
      registry.path: (
        "HKLM\\System\\*ControlSet*\\Services\\WinDefend\\Start",
        "\\REGISTRY\\MACHINE\\System\\*ControlSet*\\Services\\WinDefend\\Start"
      ) and
      registry.data.strings in ("3", "4", "0x00000003", "0x00000004")
   )
  ) and

  not process.executable :
           ("?:\\WINDOWS\\system32\\services.exe",
            "?:\\Windows\\System32\\svchost.exe",
            "?:\\Program Files (x86)\\Trend Micro\\Security Agent\\NTRmv.exe")
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

* Sub-technique:

    * Name: Indicator Blocking
    * ID: T1562.006
    * Reference URL: [https://attack.mitre.org/techniques/T1562/006/](https://attack.mitre.org/techniques/T1562/006/)



