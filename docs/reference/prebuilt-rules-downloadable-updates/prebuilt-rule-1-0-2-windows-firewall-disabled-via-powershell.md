---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-windows-firewall-disabled-via-powershell.html
---

# Windows Firewall Disabled via PowerShell [prebuilt-rule-1-0-2-windows-firewall-disabled-via-powershell]

Identifies when the Windows Firewall is disabled using PowerShell cmdlets, which can help attackers evade network constraints like internet and network lateral communication restrictions.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2019-ps](https://docs.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2019-ps)
* [https://www.tutorialspoint.com/how-to-get-windows-firewall-profile-settings-using-powershell](https://www.tutorialspoint.com/how-to-get-windows-firewall-profile-settings-using-powershell)
* [http://powershellhelp.space/commands/set-netfirewallrule-psv5.php](http://powershellhelp.space/commands/set-netfirewallrule-psv5.php)
* [http://woshub.com/manage-windows-firewall-powershell/](http://woshub.com/manage-windows-firewall-powershell/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 4

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1559]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1800]

```js
process where event.action == "start" and
  (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name == "PowerShell.EXE") and
   process.args : "*Set-NetFirewallProfile*" and
  (process.args : "*-Enabled*" and process.args : "*False*") and
  (process.args : "*-All*" or process.args : ("*Public*", "*Domain*", "*Private*"))
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

    * Name: Disable or Modify System Firewall
    * ID: T1562.004
    * Reference URL: [https://attack.mitre.org/techniques/T1562/004/](https://attack.mitre.org/techniques/T1562/004/)



