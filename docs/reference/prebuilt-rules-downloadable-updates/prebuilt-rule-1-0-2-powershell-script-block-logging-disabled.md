---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-powershell-script-block-logging-disabled.html
---

# PowerShell Script Block Logging Disabled [prebuilt-rule-1-0-2-powershell-script-block-logging-disabled]

Identifies attempts to disable PowerShell Script Block Logging via registry modification. Attackers may disable this logging to conceal their activities in the host and evade detection.

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

* [https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PowerShell::EnableScriptBlockLogging](https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PowerShell::EnableScriptBlockLogging)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1370]

## Triage and analysis

## Investigating PowerShell Script Block Logging Disabled

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks, making
it available in various environments and creating an attractive way for attackers to execute code.

PowerShell Script Block Logging is a feature of PowerShell that records the content of all script blocks that it
processes, giving defenders visibility of PowerShell scripts and sequences of executed commands.

### Possible investigation steps

- Identify the user account which performed the action.
- Check whether the account should perform this kind of action.
- Investigate the script execution chain (parent process tree).
- Investigate other alerts related to the user/host in the last 48 hours.
- Check whether it makes sense for the user to use PowerShell to complete its tasks.
- Investigate if PowerShell scripts were run after logging was disabled.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Related rules

- PowerShell Suspicious Discovery Related Windows API Functions - 61ac3638-40a3-44b2-855a-985636ca985e
- PowerShell Keylogging Script - bd2c86a0-8b61-4457-ab38-96943984e889
- PowerShell Suspicious Script with Audio Capture Capabilities - 2f2f4939-0b34-40c2-a0a3-844eb7889f43
- Potential Process Injection via PowerShell - 2e29e96a-b67c-455a-afe4-de6183431d0d
- PowerShell Reflection Assembly Load - e26f042e-c590-4e82-8e05-41e81bd822ad
- PowerShell Suspicious Payload Encoded and Compressed - 81fe9dc6-a2d7-4192-a2d8-eed98afc766a
- PowerShell Suspicious Script with Screenshot Capabilities - 959a7353-1129-4aa7-9084-30746b256a70

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Quarantine the involved host to prevent further post-compromise behavior.
- Review the implicated user account's privileges.
- Configure AppLocker or equivalent software to restrict access to PowerShell for regular users.

## Config

The 'PowerShell Script Block Logging' logging policy must be configured (Enable).

Steps to implement the logging policy with with Advanced Audit Configuration:

```
Computer Configuration >
Administrative Templates >
Windows PowerShell >
Turn on PowerShell Script Block Logging (Enable)
```

Steps to implement the logging policy via registry:

```
reg add "hklm\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1
```

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1599]

```js
registry where event.type == "change" and
    registry.path :
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging"
    and registry.data.strings : ("0", "0x00000000")
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

    * Name: Disable Windows Event Logging
    * ID: T1562.002
    * Reference URL: [https://attack.mitre.org/techniques/T1562/002/](https://attack.mitre.org/techniques/T1562/002/)



