---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-print-spooler-point-and-print-dll.html
---

# Suspicious Print Spooler Point and Print DLL [prebuilt-rule-8-17-4-suspicious-print-spooler-point-and-print-dll]

Detects attempts to exploit a privilege escalation vulnerability (CVE-2020-1030) related to the print spooler service. Exploitation involves chaining multiple primitives to load an arbitrary DLL into the print spooler process running as SYSTEM.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-windows.sysmon_operational-*
* winlogbeat-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.accenture.com/us-en/blogs/cyber-defense/discovering-exploiting-shutting-down-dangerous-windows-print-spooler-vulnerability](https://www.accenture.com/us-en/blogs/cyber-defense/discovering-exploiting-shutting-down-dangerous-windows-print-spooler-vulnerability)
* [https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Privilege%20Escalation/privesc_sysmon_cve_20201030_spooler.evtx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Privilege%20Escalation/privesc_sysmon_cve_20201030_spooler.evtx)
* [https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1030](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1030)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4969]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Print Spooler Point and Print DLL**

The Windows Print Spooler service manages print jobs and is integral to printing operations. Adversaries exploit vulnerabilities like CVE-2020-1030 to escalate privileges by loading malicious DLLs into the spooler process, which runs with SYSTEM-level permissions. The detection rule identifies suspicious registry modifications linked to the Print Spooler, indicating potential exploitation attempts by monitoring specific registry paths and data patterns.

**Possible investigation steps**

* Review the registry paths specified in the alert to confirm any unauthorized modifications, focusing on the paths: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers*\SpoolDirectory and HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\*\CopyFiles\Payload\Module.
* Check the registry data strings for any unexpected or suspicious DLLs located in C:\Windows\System32\spool\drivers\x64\4, which may indicate a malicious payload.
* Investigate the host identified by host.id to determine if there are any other signs of compromise or unusual activity, such as unexpected processes or network connections.
* Correlate the alert with other security events or logs from the same host to identify any related activities or patterns that could suggest a broader attack.
* Assess the system’s patch level and update status to ensure that all known vulnerabilities, including CVE-2020-1030, have been addressed and mitigated.
* If a malicious DLL is confirmed, isolate the affected system to prevent further exploitation and begin remediation efforts, such as removing the malicious files and restoring the system to a known good state.

**False positive analysis**

* Legitimate printer driver updates or installations may trigger the rule due to registry modifications in the specified paths. Users can create exceptions for known and trusted driver update processes to prevent false alerts.
* Custom print configurations by IT departments that modify the SpoolDirectory or CopyFiles registry paths might be flagged. Document and exclude these configurations if they are verified as safe and necessary for business operations.
* Automated scripts or software that manage printer settings and inadvertently modify the monitored registry paths can cause false positives. Identify and whitelist these scripts or applications after confirming their legitimacy.
* Third-party print management solutions that interact with the Print Spooler service may lead to false detections. Evaluate these solutions and exclude their known benign activities from the detection rule.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further exploitation or lateral movement by the adversary.
* Terminate the Print Spooler service on the compromised system to stop any ongoing malicious activity and prevent further DLL loading.
* Conduct a thorough scan of the system using updated antivirus and anti-malware tools to identify and remove any malicious DLLs or related files.
* Review and restore the registry paths identified in the detection query to their default values to ensure no malicious configurations remain.
* Apply the latest security patches and updates from Microsoft to address CVE-2020-1030 and other known vulnerabilities in the Print Spooler service.
* Monitor the network for any signs of similar exploitation attempts, focusing on the registry paths and data patterns specified in the detection rule.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on other systems within the network.


## Rule query [_rule_query_5924]

```js
sequence by host.id with maxspan=30s
[registry where host.os.type == "windows" and
 registry.path : (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\SpoolDirectory",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\SpoolDirectory"
    ) and
 registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4"]
[registry where host.os.type == "windows" and
 registry.path : (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\CopyFiles\\Payload\\Module",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers\\*\\CopyFiles\\Payload\\Module"
    ) and
 registry.data.strings : "C:\\Windows\\System32\\spool\\drivers\\x64\\4\\*"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



