---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-svchost-spawning-cmd.html
---

# Svchost spawning Cmd [prebuilt-rule-8-4-2-svchost-spawning-cmd]

Identifies a suspicious parent child process relationship with cmd.exe descending from svchost.exe

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

* [https://nasbench.medium.com/demystifying-the-svchost-exe-process-and-its-command-line-options-508e9114e747](https://nasbench.medium.com/demystifying-the-svchost-exe-process-and-its-command-line-options-508e9114e747)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution
* Investigation Guide
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3460]

## Triage and analysis

## Investigating Svchost spawning Cmd

The Service Host process (SvcHost) is a system process that can host one, or multiple, Windows services in the Windows NT family of operating systems. Note that `Svchost.exe` is reserved for use by the operating system and should not be used by non-Windows services.

This rule looks for the creation of the `cmd.exe` process with `svchost.exe` as its parent process. This is an unusual behavior that can indicate the masquerading of a malicious process as `svchost.exe` or exploitation for privilege escalation.

> **Note**:
> This investigation guide uses the [Osquery Markdown Plugin](docs-content://solutions/security/investigate/run-osquery-from-investigation-guides.md) introduced in Elastic stack version 8.5.0. Older Elastic stacks versions will see unrendered markdown in this guide.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Investigate any abnormal behavior by the subject process such as network connections, registry or file modifications, and any spawned child processes.
- Examine the host for derived artifacts that indicates suspicious activities:
  - Analyze the process executable using a private sandboxed analysis system.
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

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

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

## Rule query [_rule_query_4122]

```js
process where event.type == "start" and

  process.parent.name : "svchost.exe" and process.name : "cmd.exe" and

  not process.args :
         ("??:\\Program Files\\Npcap\\CheckStatus.bat?",
          "?:\\Program Files\\Npcap\\CheckStatus.bat",
          "\\system32\\cleanmgr.exe",
          "?:\\Windows\\system32\\silcollector.cmd",
          "\\system32\\AppHostRegistrationVerifier.exe",
          "\\system32\\ServerManagerLauncher.exe",
          "dir",
          "?:\\Program Files\\*",
          "?:\\Program Files (x86)\\*",
          "?:\\Windows\\LSDeployment\\Lspush.exe",
          "(x86)\\FMAuditOnsite\\watchdog.bat",
          "?:\\ProgramData\\chocolatey\\bin\\choco-upgrade-all.bat",
          "Files\\Npcap\\CheckStatus.bat") and

   /* very noisy pattern - bat or cmd script executed via scheduled tasks */
  not (process.parent.args : "netsvcs" and process.args : ("?:\\*.bat", "?:\\*.cmd"))
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



