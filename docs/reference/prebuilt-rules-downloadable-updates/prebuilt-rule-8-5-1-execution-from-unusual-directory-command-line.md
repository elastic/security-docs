---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-5-1-execution-from-unusual-directory-command-line.html
---

# Execution from Unusual Directory - Command Line [prebuilt-rule-8-5-1-execution-from-unusual-directory-command-line]

Identifies process execution from suspicious default Windows directories. This may be abused by adversaries to hide malware in trusted paths.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

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
* Investigation Guide
* Elastic Endgame

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3710]

## Triage and analysis

## Investigating Execution from Unusual Directory - Command Line

This rule looks for the execution of scripts from unusual directories. Attackers can use system or application paths to hide malware and make the execution less suspicious.

> **Note**:
> This investigation guide uses the [Osquery Markdown Plugin](docs-content://solutions/security/investigate/run-osquery-from-investigation-guides.md) introduced in Elastic stack version 8.5.0. Older Elastic stacks versions will see unrendered markdown in this guide.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Examine the command line to determine which commands or scripts were executed.
- Examine the host for derived artifacts that indicates suspicious activities:
  - Analyze the script using a private sandboxed analysis system.
  - Observe and collect information about the following activities in both the sandbox and the alert subject host:
    - Attempts to contact external domains and addresses.
      - Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by filtering by the process' `process.entity_id`.
      - Examine the DNS cache for suspicious or anomalous entries.
        - !{osquery{"query":"SELECT * FROM dns_cache", "label":"Osquery - Retrieve DNS Cache"}}
    - Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related processes in the process tree.
    - Examine the host services for suspicious or anomalous entries.
      - !{osquery{"query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services","label":"Osquery - Retrieve All Services"}}
      - !{osquery{"query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE NOT (user_account LIKE '%LocalSystem' OR user_account LIKE '%LocalService' OR user_account LIKE '%NetworkService' OR user_account == null)","label":"Osquery - Retrieve Services Running on User Accounts"}}
      - !{osquery{"query":"SELECT concat('https://www.virustotal.com/gui/file/', sha1) AS VtLink, name, description, start_type, status, pid, services.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path = authenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != 'trusted'","label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link"}}
  - Retrieve the files' SHA-256 hash values using the PowerShell `Get-FileHash` cmdlet and search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
- Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the target host after the registry modification.

## False positive analysis

- If this activity is expected and noisy in your environment, consider adding exceptions — preferably with a combination of parent process executable and command line conditions.

## Related rules

- Process Execution from an Unusual Directory - ebfe1448-7fac-4d59-acea-181bd89b1f7f

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4492]

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

* Sub-technique:

    * Name: Windows Command Shell
    * ID: T1059.003
    * Reference URL: [https://attack.mitre.org/techniques/T1059/003/](https://attack.mitre.org/techniques/T1059/003/)

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



