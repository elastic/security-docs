---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-execution-from-unusual-directory-command-line.html
---

# Execution from Unusual Directory - Command Line [prebuilt-rule-8-3-2-execution-from-unusual-directory-command-line]

Identifies process execution from suspicious default Windows directories. This may be abused by adversaries to hide malware in trusted paths.

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

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution
* Defense Evasion

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2496]

## Triage and analysis

## Investigating Execution from Unusual Directory - Command Line

This rule looks for the execution of scripts from unusual directories. Attackers can use system or application paths to
hide malware and make the execution less suspicious.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Examine the command line to determine which commands or scripts were executed.
- Retrieve the script and determine if it is malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled task creation.
  - Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- If this activity is expected and noisy in your environment, consider adding exceptions — preferably with a combination
of parent process executable and command line conditions.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that
  attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).


This is related to the `Process Execution from an Unusual Directory rule`.

## Rule query [_rule_query_2869]

```js
process where event.type == "start" and
  process.name : ("wscript.exe",
                  "cscript.exe",
                  "rundll32.exe",
                  "regsvr32.exe",
                  "cmstp.exe",
                  "RegAsm.exe",
                  "installutil.exe",
                  "mshta.exe",
                  "RegSvcs.exe",
                  "powershell.exe",
                  "pwsh.exe",
                  "cmd.exe") and

  /* add suspicious execution paths here */
  process.args : ("C:\\PerfLogs\\*",
                  "C:\\Users\\Public\\*",
                  "C:\\Windows\\Tasks\\*",
                  "C:\\Intel\\*",
                  "C:\\AMD\\Temp\\*",
                  "C:\\Windows\\AppReadiness\\*",
                  "C:\\Windows\\ServiceState\\*",
                  "C:\\Windows\\security\\*",
                  "C:\\Windows\\IdentityCRL\\*",
                  "C:\\Windows\\Branding\\*",
                  "C:\\Windows\\csc\\*",
                  "C:\\Windows\\DigitalLocker\\*",
                  "C:\\Windows\\en-US\\*",
                  "C:\\Windows\\wlansvc\\*",
                  "C:\\Windows\\Prefetch\\*",
                  "C:\\Windows\\Fonts\\*",
                  "C:\\Windows\\diagnostics\\*",
                  "C:\\Windows\\TAPI\\*",
                  "C:\\Windows\\INF\\*",
                  "C:\\Windows\\System32\\Speech\\*",
                  "C:\\windows\\tracing\\*",
                  "c:\\windows\\IME\\*",
                  "c:\\Windows\\Performance\\*",
                  "c:\\windows\\intel\\*",
                  "c:\\windows\\ms\\*",
                  "C:\\Windows\\dot3svc\\*",
                  "C:\\Windows\\panther\\*",
                  "C:\\Windows\\RemotePackages\\*",
                  "C:\\Windows\\OCR\\*",
                  "C:\\Windows\\appcompat\\*",
                  "C:\\Windows\\apppatch\\*",
                  "C:\\Windows\\addins\\*",
                  "C:\\Windows\\Setup\\*",
                  "C:\\Windows\\Help\\*",
                  "C:\\Windows\\SKB\\*",
                  "C:\\Windows\\Vss\\*",
                  "C:\\Windows\\servicing\\*",
                  "C:\\Windows\\CbsTemp\\*",
                  "C:\\Windows\\Logs\\*",
                  "C:\\Windows\\WaaS\\*",
                  "C:\\Windows\\twain_32\\*",
                  "C:\\Windows\\ShellExperiences\\*",
                  "C:\\Windows\\ShellComponents\\*",
                  "C:\\Windows\\PLA\\*",
                  "C:\\Windows\\Migration\\*",
                  "C:\\Windows\\debug\\*",
                  "C:\\Windows\\Cursors\\*",
                  "C:\\Windows\\Containers\\*",
                  "C:\\Windows\\Boot\\*",
                  "C:\\Windows\\bcastdvr\\*",
                  "C:\\Windows\\TextInput\\*",
                  "C:\\Windows\\security\\*",
                  "C:\\Windows\\schemas\\*",
                  "C:\\Windows\\SchCache\\*",
                  "C:\\Windows\\Resources\\*",
                  "C:\\Windows\\rescache\\*",
                  "C:\\Windows\\Provisioning\\*",
                  "C:\\Windows\\PrintDialog\\*",
                  "C:\\Windows\\PolicyDefinitions\\*",
                  "C:\\Windows\\media\\*",
                  "C:\\Windows\\Globalization\\*",
                  "C:\\Windows\\L2Schemas\\*",
                  "C:\\Windows\\LiveKernelReports\\*",
                  "C:\\Windows\\ModemLogs\\*",
                  "C:\\Windows\\ImmersiveControlPanel\\*",
                  "C:\\$Recycle.Bin\\*") and

  /* noisy FP patterns */

  not process.parent.executable : ("C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\*\\igfxCUIService*.exe",
                                   "C:\\Windows\\System32\\spacedeskService.exe",
                                   "C:\\Program Files\\Dell\\SupportAssistAgent\\SRE\\SRE.exe") and
  not (process.name : "rundll32.exe" and
       process.args : ("uxtheme.dll,#64",
                       "PRINTUI.DLL,PrintUIEntry",
                       "?:\\Windows\\System32\\FirewallControlPanel.dll,ShowNotificationDialog",
                       "?:\\WINDOWS\\system32\\Speech\\SpeechUX\\sapi.cpl",
                       "?:\\Windows\\system32\\shell32.dll,OpenAs_RunDLL")) and

  not (process.name : "cscript.exe" and process.args : "?:\\WINDOWS\\system32\\calluxxprovider.vbs") and

  not (process.name : "cmd.exe" and process.args : "?:\\WINDOWS\\system32\\powercfg.exe" and process.args : "?:\\WINDOWS\\inf\\PowerPlan.log") and

  not (process.name : "regsvr32.exe" and process.args : "?:\\Windows\\Help\\OEM\\scripts\\checkmui.dll") and

  not (process.name : "cmd.exe" and
       process.parent.executable : ("?:\\Windows\\System32\\oobe\\windeploy.exe",
                                    "?:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe",
                                    "?:\\Windows\\System32\\igfxCUIService.exe",
                                    "?:\\Windows\\Temp\\IE*.tmp\\IE*-support\\ienrcore.exe"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Match Legitimate Name or Location
    * ID: T1036.005
    * Reference URL: [https://attack.mitre.org/techniques/T1036/005/](https://attack.mitre.org/techniques/T1036/005/)



