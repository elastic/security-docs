---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-remote-execution-via-file-shares.html
---

# Remote Execution via File Shares [prebuilt-rule-8-17-4-remote-execution-via-file-shares]

Identifies the execution of a file that was created by the virtual system process. This may indicate lateral movement via network file shares.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.file-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [http://web.archive.org/web/20230329172636/https://blog.menasec.net/2020/08/new-trick-to-detect-lateral-movement.html](http://web.archive.org/web/20230329172636/https://blog.menasec.net/2020/08/new-trick-to-detect-lateral-movement.md)
* [https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language](https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Resources: Investigation Guide
* Data Source: Elastic Endgame
* Data Source: Elastic Defend

**Version**: 116

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4887]

**Triage and analysis**

**Investigating Remote Execution via File Shares**

Adversaries can use network shares to host tooling to support the compromise of other hosts in the environment. These tools can include discovery utilities, credential dumpers, malware, etc.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Review adjacent login events (e.g., 4624) in the alert timeframe to identify the account used to perform this action.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Examine the host for derived artifacts that indicate suspicious activities:
* Analyze the process executable using a private sandboxed analysis system.
* Observe and collect information about the following activities in both the sandbox and the alert subject host:
* Attempts to contact external domains and addresses.
* Use the Elastic Defend network events to determine domains and addresses contacted by the subject process by filtering by the process' `process.entity_id`.
* Examine the DNS cache for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve DNS Cache","query":"SELECT * FROM dns_cache"}}
* Use the Elastic Defend registry events to examine registry keys accessed, modified, or created by the related processes in the process tree.
* Examine the host services for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve All Services","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"}}
* !{osquery{"label":"Osquery - Retrieve Services Running on User Accounts","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\nNOT (user_account LIKE *%LocalSystem* OR user_account LIKE *%LocalService* OR user_account LIKE *%NetworkService* OR\nuser_account == null)\n"}}
* !{osquery{"label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, name, description, start_type, status, pid,\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != *trusted*\n"}}
* Retrieve the files' SHA-256 hash values using the PowerShell `Get-FileHash` cmdlet and search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
* Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the target host after the registry modification.

**False positive analysis**

* This activity can happen legitimately. Consider adding exceptions if it is expected and noisy in your environment.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Review the privileges needed to write to the network share and restrict write access as needed.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_5842]

```js
sequence with maxspan=1m
  [file where host.os.type == "windows" and event.type in ("creation", "change") and
   process.pid == 4 and (file.extension : "exe" or file.Ext.header_bytes : "4d5a*")] by host.id, file.path
  [process where host.os.type == "windows" and event.type == "start" and
    not (
      /* Veeam related processes */
      (
        process.name : (
          "VeeamGuestHelper.exe", "VeeamGuestIndexer.exe", "VeeamAgent.exe", "VeeamLogShipper.exe", "Veeam.VSS.Sharepoint20??.exe"
        ) and process.code_signature.trusted == true and process.code_signature.subject_name : "Veeam Software Group GmbH"
      ) or
      /* PDQ related processes */
      (
        process.name : (
          "PDQInventoryScanner.exe", "PDQInventoryMonitor.exe", "PDQInventory-Scanner-?.exe",
          "PDQInventoryWakeCommand-?.exe", "PDQDeployRunner-?.exe"
        ) and process.code_signature.trusted == true and process.code_signature.subject_name : "PDQ.com Corporation"
      ) or
      /* CrowdStrike related processes */
      (
        (process.executable : "?:\\Windows\\System32\\drivers\\CrowdStrike\\*-WindowsSensor.*.exe" and
         process.code_signature.trusted == true and process.code_signature.subject_name : "CrowdStrike, Inc.") or
        (process.executable : "?:\\Windows\\System32\\drivers\\CrowdStrike\\*-CsInstallerService.exe" and
         process.code_signature.trusted == true and process.code_signature.subject_name : "Microsoft Windows Hardware Compatibility Publisher")
      ) or
      /* MS related processes */
      (
        process.executable == "System" or
        (process.executable : "?:\\Windows\\ccmsetup\\ccmsetup.exe" and
         process.code_signature.trusted == true and process.code_signature.subject_name : "Microsoft Corporation")
      ) or
      /* CyberArk processes */
      (
        process.executable : "?:\\Windows\\CAInvokerService.exe" and
        process.code_signature.trusted == true and process.code_signature.subject_name : "CyberArk Software Ltd."
      )  or
      /* Sophos processes */
      (
        process.executable : "?:\\ProgramData\\Sophos\\AutoUpdate\\Cache\\sophos_autoupdate1.dir\\SophosUpdate.exe" and
        process.code_signature.trusted == true and process.code_signature.subject_name : "Sophos Ltd"
      )  or
      /* Elastic processes */
      (
        process.executable : (
          "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\previous\\elastic-endpoint.exe",
          "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\elastic-agent.exe",
          "?:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-*\\components\\agentbeat.exe"
        ) and
        process.code_signature.trusted == true and process.code_signature.subject_name : "Elasticsearch, Inc."
      )
    )
  ] by host.id, process.executable
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



