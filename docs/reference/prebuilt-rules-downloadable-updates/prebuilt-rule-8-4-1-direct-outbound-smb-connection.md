---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-direct-outbound-smb-connection.html
---

# Direct Outbound SMB Connection [prebuilt-rule-8-4-1-direct-outbound-smb-connection]

Identifies unexpected processes making network connections over port 445. Windows File Sharing is typically implemented over Server Message Block (SMB), which communicates between hosts using port 445. When legitimate, these network connections are established by the kernel. Processes making 445/tcp connections may be port scanners, exploits, or suspicious user-level processes moving laterally.

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
* Lateral Movement
* Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2816]

## Triage and analysis

## Investigating Direct Outbound SMB Connection

This rule looks for unexpected processes making network connections over port 445. Windows file sharing is typically
implemented over Server Message Block (SMB), which communicates between hosts using port 445. When legitimate, these
network connections are established by the kernel (PID 4). Occurrences of non-system processes using this port can indicate
port scanners, exploits, and tools used to move laterally on the environment.

> **Note**:
> This investigation guide uses the [Osquery Markdown Plugin](docs-content://solutions/security/investigate/run-osquery-from-investigation-guides.md) introduced in Elastic stack version 8.5.0. Older Elastic stacks versions will see unrendered markdown in this guide.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate any abnormal behavior by the subject process such as network connections, registry or file modifications,
and any spawned child processes.
- Examine the host for derived artifacts that indicates suspicious activities:
  - Analyze the process executable using a private sandboxed analysis system.
  - Observe and collect information about the following activities in both the sandbox and the alert subject host:
    - Attempts to contact external domains and addresses.
      - Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by
      filtering by the process' `process.entity_id`.
      - Examine the DNS cache for suspicious or anomalous entries.
        - !{osquery{"query":"SELECT * FROM dns_cache", "label":"Osquery - Retrieve DNS Cache"}}
    - Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related
    processes in the process tree.
    - Examine the host services for suspicious or anomalous entries.
      - !{osquery{"query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services","label":"Osquery - Retrieve All Services"}}
      - !{osquery{"query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE NOT (user_account LIKE "%LocalSystem" OR user_account LIKE "%LocalService" OR user_account LIKE "%NetworkService" OR user_account == null)","label":"Osquery - Retrieve Services Running on User Accounts"}}
      - !{osquery{"query":"SELECT concat('https://www.virustotal.com/gui/file/', sha1) AS VtLink, name, description, start_type, status, pid, services.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path = authenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != "trusted"","label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link"}}
  - Retrieve the files' SHA-256 hash values using the PowerShell `Get-FileHash` cmdlet and search for the existence and
  reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.


## False positive analysis

- If this rule is noisy in your environment due to expected activity, consider adding exceptions — preferably with a combination
of user and command line conditions.

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

## Rule query [_rule_query_3215]

```js
sequence by process.entity_id
  [process where event.type == "start" and host.os.name == "Windows" and process.pid != 4 and
   not (process.executable : "D:\\EnterpriseCare\\tools\\jre.1\\bin\\java.exe" and process.args : "com.emeraldcube.prism.launcher.Invoker") and
   not (process.executable : "C:\\Docusnap 11\\Tools\\nmap\\nmap.exe" and process.args : "smb-os-discovery.nse") and
   not process.executable :
              ("?:\\Program Files\\SentinelOne\\Sentinel Agent *\\Ranger\\SentinelRanger.exe",
               "?:\\Program Files\\Ivanti\\Security Controls\\ST.EngineHost.exe",
               "?:\\Program Files (x86)\\Fortinet\\FSAE\\collectoragent.exe",
               "?:\\Program Files (x86)\\Nmap\\nmap.exe",
               "?:\\Program Files\\Azure Advanced Threat Protection Sensor\\*\\Microsoft.Tri.Sensor.exe",
               "?:\\Program Files\\CloudMatters\\auvik\\AuvikService-release-*\\AuvikService.exe",
               "?:\\Program Files\\uptime software\\uptime\\UptimeDataCollector.exe",
               "?:\\Program Files\\CloudMatters\\auvik\\AuvikAgentService.exe",
               "?:\\Program Files\\Rumble\\rumble-agent-*.exe")]
  [network where destination.port == 445 and process.pid != 4 and
     not cidrmatch(destination.ip, "127.0.0.1", "::1")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SMB/Windows Admin Shares
    * ID: T1021.002
    * Reference URL: [https://attack.mitre.org/techniques/T1021/002/](https://attack.mitre.org/techniques/T1021/002/)



