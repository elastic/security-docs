---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-execution-from-inet-cache.html
---

# Suspicious Execution from INET Cache [prebuilt-rule-8-17-4-suspicious-execution-from-inet-cache]

Identifies the execution of a process with arguments pointing to the INetCache Folder. Adversaries may deliver malicious content via WININET during initial access.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.trendmicro.com/en_us/research/24/b/cve202421412-water-hydra-targets-traders-with-windows-defender-s.html](https://www.trendmicro.com/en_us/research/24/b/cve202421412-water-hydra-targets-traders-with-windows-defender-s.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Initial Access
* Tactic: Command and Control
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 205

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4864]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Execution from INET Cache**

The INetCache folder stores temporary internet files, which can be exploited by adversaries to execute malicious payloads delivered via WININET. Attackers may disguise malware as legitimate files cached during browsing. The detection rule identifies suspicious processes initiated from this cache, especially when launched by common file explorers, signaling potential initial access or command and control activities.

**Possible investigation steps**

* Review the process details to confirm the executable path and arguments match the INetCache folder pattern specified in the query.
* Identify the parent process, such as explorer.exe, winrar.exe, 7zFM.exe, or Bandizip.exe, to determine if the process launch is consistent with typical user behavior or potentially malicious activity.
* Check the user account associated with the process to assess if the activity aligns with the user’s normal behavior or if the account may be compromised.
* Investigate the file in the INetCache directory for known malware signatures or anomalies using antivirus or endpoint detection tools.
* Analyze network activity from the host to identify any suspicious connections that may indicate command and control communication.
* Correlate the event with other security alerts or logs to identify patterns or additional indicators of compromise related to the initial access or command and control tactics.

**False positive analysis**

* Legitimate software updates or installations may temporarily use the INetCache folder for storing executable files. Users can create exceptions for known update processes by identifying their specific executable paths and excluding them from the rule.
* Some browser extensions or plugins might cache executable files in the INetCache folder during normal operations. Users should monitor and whitelist these extensions if they are verified as safe and frequently trigger alerts.
* Automated scripts or tools that interact with web content might inadvertently store executables in the INetCache folder. Users can adjust the rule to exclude these scripts by specifying their parent process names or paths.
* Certain enterprise applications may use the INetCache folder for legitimate purposes. Users should collaborate with IT departments to identify these applications and configure exceptions based on their unique process signatures.
* Regularly review and update the list of excluded processes to ensure that only verified and non-threatening activities are exempt from triggering alerts.

**Response and remediation**

* Isolate the affected system from the network to prevent further communication with potential command and control servers.
* Terminate any suspicious processes identified as originating from the INetCache folder to halt any ongoing malicious activity.
* Delete any malicious files found within the INetCache directory to remove the immediate threat.
* Conduct a full antivirus and antimalware scan on the affected system to identify and remove any additional threats.
* Review and analyze recent email logs and web browsing history to identify potential phishing attempts or malicious downloads that may have led to the initial compromise.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for the INetCache directory and related processes to detect similar threats in the future.


## Rule query [_rule_query_5819]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("explorer.exe", "winrar.exe", "7zFM.exe", "Bandizip.exe") and
  (
    process.args : "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*" or
    process.executable : (
      "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*",
      "\\Device\\HarddiskVolume?\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Attachment
    * ID: T1566.001
    * Reference URL: [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)



