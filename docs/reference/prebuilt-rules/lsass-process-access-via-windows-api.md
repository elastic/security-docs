---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/lsass-process-access-via-windows-api.html
---

# LSASS Process Access via Windows API [lsass-process-access-via-windows-api]

Identifies access attempts to the LSASS handle, which may indicate an attempt to dump credentials from LSASS memory.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.api-*
* logs-m365_defender.event-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Microsoft Defender for Endpoint
* Resources: Investigation Guide

**Version**: 11

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_469]

**Triage and analysis**

**Investigating LSASS Process Access via Windows API**

The Local Security Authority Subsystem Service (LSASS) is a critical Windows component responsible for managing user authentication and security policies. Adversaries may attempt to access the LSASS handle to dump credentials from its memory, which can be used for lateral movement and privilege escalation.

This rule identifies attempts to access LSASS by monitoring for specific API calls (OpenProcess, OpenThread) targeting the "lsass.exe" process.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate other alerts associated with the user/host during the past 48 hours.
* Investigate the process execution chain (parent process tree) of the process that accessed the LSASS handle.
* Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Determine the first time the process executable was seen in the environment and if this behavior happened in the past.
* Validate the activity is not related to planned patches, updates, network administrator activity, or legitimate software installations.
* Investigate any abnormal behavior by the subject process, such as network connections, DLLs loaded, registry or file modifications, and any spawned child processes.
* Assess the access rights (`process.Ext.api.parameters.desired_access`field) requested by the process. This [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) may be useful to help the interpretation.
* If there are traces of LSASS memory being successfully dumped, investigate potentially compromised accounts. Analysts can do this by searching for login events (e.g., 4624) to the target host.
* Examine the host for derived artifacts that indicate suspicious activities:
* Analyze the executables of the processes using a private sandboxed analysis system.
* Observe and collect information about the following activities in both the sandbox and the alert subject host:
* Attempts to contact external domains and addresses.
* Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by filtering by the process’s `process.entity_id`.
* Examine the DNS cache for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve DNS Cache","query":"SELECT * FROM dns_cache"}}
* Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related processes in the process tree.
* Examine the host services for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve All Services","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"}}
* !{osquery{"label":"Osquery - Retrieve Services Running on User Accounts","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\nNOT (user_account LIKE *%LocalSystem* OR user_account LIKE *%LocalService* OR user_account LIKE *%NetworkService* OR\nuser_account == null)\n"}}
* !{osquery{"label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, name, description, start_type, status, pid,\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != *trusted*\n"}}
* Retrieve the files' SHA-256 hash values using the PowerShell `Get-FileHash` cmdlet and search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

**False positive analysis**

* If this rule is noisy in your environment due to expected activity, consider adding exceptions — preferably with a combination of `process.executable`, `process.code_signature.subject_name` and `process.Ext.api.parameters.desired_access_numeric` conditions.

**Related Rules**

* Suspicious Lsass Process Access - 128468bf-cab1-4637-99ea-fdf3780a4609
* Potential Credential Access via DuplicateHandle in LSASS - 02a4576a-7480-4284-9327-548a806b5e48
* LSASS Memory Dump Handle Access - 208dbe77-01ed-4954-8d44-1e5751cb20de

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* If malicious activity is confirmed, perform a broader investigation to identify the scope of the compromise and determine the appropriate remediation steps.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Reimage the host operating system or restore the compromised files to clean versions.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_504]

```js
api where host.os.type == "windows" and
  process.Ext.api.name in ("OpenProcess", "OpenThread") and Target.process.name : "lsass.exe" and
  not
  (
    process.executable : (
        "?:\\ProgramData\\GetSupportService*\\Updates\\Update_*.exe",
        "?:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
        "?:\\Program Files (x86)\\Asiainfo Security\\OfficeScan Client\\NTRTScan.exe",
        "?:\\Program Files (x86)\\Blackpoint\\SnapAgent\\SnapAgent.exe",
        "?:\\Program Files (x86)\\CheckPoint\\Endpoint Security\\EFR\\EFRService.exe",
        "?:\\Program Files (x86)\\CyberCNSAgent\\osqueryi.exe",
        "?:\\Program Files (x86)\\cisco\\cisco anyconnect secure mobility client\\vpnagent.exe",
        "?:\\Program Files (x86)\\cisco\\cisco anyconnect secure mobility client\\aciseagent.exe",
        "?:\\Program Files (x86)\\cisco\\cisco anyconnect secure mobility client\\vpndownloader.exe",
        "?:\\Program Files (x86)\\eScan\\reload.exe",
        "?:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",
        "?:\\Program Files (x86)\\Kaspersky Lab\\*\\avp.exe",
        "?:\\Program Files (x86)\\microsoft intune management extension\\microsoft.management.services.intunewindowsagent.exe",
        "?:\\Program Files (x86)\\N-able Technologies\\Reactive\\bin\\NableReactiveManagement.exe",
        "?:\\Program Files (x86)\\N-able Technologies\\Windows Agent\\bin\\agent.exe",
        "?:\\Program Files (x86)\\Tanium\\Tanium Client\\TaniumClient.exe",
        "?:\\Program Files (x86)\\Trend Micro\\*\\CCSF\\TmCCSF.exe",
        "?:\\Program Files (x86)\\Trend Micro\\Security Agent\\TMASutility.exe",
        "?:\\Program Files*\\Windows Defender\\MsMpEng.exe",
        "?:\\Program Files\\Bitdefender\\Endpoint Security\\EPSecurityService.exe",
        "?:\\Program Files\\Cisco\\AMP\\*\\sfc.exe",
        "?:\\Program Files\\Common Files\\McAfee\\AVSolution\\mcshield.exe",
        "?:\\Program Files\\EA\\AC\\EAAntiCheat.GameService.exe",
        "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\agentbeat.exe",
        "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\metricbeat.exe",
        "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\osqueryd.exe",
        "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\packetbeat.exe",
        "?:\\Program Files\\ESET\\ESET Security\\ekrn.exe",
        "?:\\Program Files\\Fortinet\\FortiClient\\FortiProxy.exe",
        "?:\\Program Files\\Fortinet\\FortiClient\\FortiSSLVPNdaemon.exe",
        "?:\\Program Files\\Goverlan Inc\\GoverlanAgent\\GovAgentx64.exe",
        "?:\\Program Files\\Huntress\\HuntressAgent.exe",
        "?:\\Program Files\\LogicMonitor\\Agent\\bin\\sbshutdown.exe",
        "?:\\Program Files\\Malwarebytes\\Anti-Malware\\MBAMService.exe",
        "?:\\Program Files\\Microsoft Monitoring Agent\\Agent\\Health Service State\\*\\pmfexe.exe",
        "?:\\Program Files\\Microsoft Security Client\\MsMpEng.exe",
        "?:\\Program Files\\Qualys\\QualysAgent\\QualysAgent.exe",
        "?:\\Program Files\\smart-x\\controlupagent\\version*\\cuagent.exe",
        "?:\\Program Files\\TDAgent\\ossec-agent\\ossec-agent.exe",
        "?:\\Program Files\\Topaz OFD\\Warsaw\\core.exe",
        "?:\\Program Files\\Trend Micro\\Deep Security Agent\\netagent\\tm_netagent.exe",
        "?:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
        "?:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe",
        "?:\\Program Files\\Wise\\Wise Memory Optimizer\\WiseMemoryOptimzer.exe",
        "?:\\Windows\\AdminArsenal\\PDQDeployRunner\\*\\exec\\Sysmon64.exe",
        "?:\\Windows\\Sysmon.exe",
        "?:\\Windows\\Sysmon64.exe",
        "?:\\Windows\\System32\\csrss.exe",
        "?:\\Windows\\System32\\MRT.exe",
        "?:\\Windows\\System32\\msiexec.exe",
        "?:\\Windows\\System32\\taskhostw.exe",
        "?:\\Windows\\System32\\RtkAudUService64.exe",
        "?:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
        "?:\\Windows\\SysWOW64\\wbem\\WmiPrvSE.exe",
        "?:\\Windows\\tenable_mw_scan_142a90001fb65e0beb1751cc8c63edd0.exe"
    ) and not ?process.code_signature.trusted == false
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

* Sub-technique:

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Native API
    * ID: T1106
    * Reference URL: [https://attack.mitre.org/techniques/T1106/](https://attack.mitre.org/techniques/T1106/)



