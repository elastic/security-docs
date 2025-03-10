---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unsigned-dll-loaded-by-dns-service.html
---

# Unsigned DLL loaded by DNS Service [unsigned-dll-loaded-by-dns-service]

Identifies unusual DLLs loaded by the DNS Server process, potentially indicating the abuse of the ServerLevelPluginDll functionality. This can lead to privilege escalation and remote code execution with SYSTEM privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.library-*
* logs-windows.sysmon_operational-*
* winlogbeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cube0x0.github.io/Pocing-Beyond-DA/](https://cube0x0.github.io/Pocing-Beyond-DA/)
* [https://adsecurity.org/?p=4064](https://adsecurity.org/?p=4064)
* [https://github.com/gtworek/PSBits/tree/master/ServerLevelPluginDll](https://github.com/gtworek/PSBits/tree/master/ServerLevelPluginDll)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1097]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unsigned DLL loaded by DNS Service**

The DNS service in Windows environments is crucial for resolving domain names to IP addresses. It can be extended via DLLs, which, if unsigned, may indicate tampering. Adversaries exploit this by loading malicious DLLs to gain elevated privileges or execute code with SYSTEM rights. The detection rule identifies such threats by monitoring the DNS process for loading untrusted DLLs, flagging potential privilege escalation attempts.

**Possible investigation steps**

* Review the alert details to identify the specific DLL file that was loaded by the DNS service and check its file path and name for any known malicious indicators.
* Examine the file’s code signature status and metadata to determine why it is not trusted or valid, and cross-reference with known trusted sources or databases.
* Investigate the process tree of dns.exe to identify any parent or child processes that may indicate how the unsigned DLL was introduced or executed.
* Check the system’s event logs for any recent changes or anomalies around the time the DLL was loaded, focusing on events related to process creation, file modification, or user account activity.
* Analyze network traffic logs for any unusual DNS queries or outbound connections that could suggest communication with a command and control server.
* Assess the system for other signs of compromise, such as unauthorized user accounts, scheduled tasks, or registry changes that could indicate further exploitation or persistence mechanisms.
* If possible, isolate the affected system to prevent further potential malicious activity and begin remediation steps based on the findings.

**False positive analysis**

* Legitimate software updates or patches may introduce new DLLs that are unsigned. Verify the source of the update and, if trusted, create an exception for these DLLs to prevent future alerts.
* Custom or in-house applications might use unsigned DLLs for specific functionalities. Confirm the legitimacy of these applications and add them to an allowlist to avoid unnecessary alerts.
* Some third-party security or monitoring tools may load unsigned DLLs as part of their operation. Validate these tools with your security team and configure exceptions for known, safe DLLs.
* Development or testing environments often use unsigned DLLs during the software development lifecycle. Ensure these environments are properly segmented and consider excluding them from this rule to reduce noise.
* Legacy systems might rely on older, unsigned DLLs that are still in use. Conduct a risk assessment and, if deemed safe, exclude these DLLs from triggering alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further exploitation or lateral movement by the adversary.
* Terminate the DNS service process (dns.exe) to stop the execution of the malicious DLL and prevent further potential damage.
* Conduct a thorough scan of the system using updated antivirus and anti-malware tools to identify and remove any additional malicious files or software.
* Restore the DNS service to its original state by replacing the compromised DLL with a legitimate, signed version from a trusted source or backup.
* Review and update the system’s security patches and configurations to address any vulnerabilities that may have been exploited, particularly those related to privilege escalation.
* Monitor the system and network for any signs of continued or repeated unauthorized activity, focusing on similar indicators of compromise.
* Report the incident to the appropriate internal security team or external authorities if required, providing details of the threat and actions taken for further investigation and response.


## Rule query [_rule_query_1155]

```js
any where host.os.type == "windows" and event.category : ("library", "process") and
  event.type : ("start", "change") and event.action : ("load", "Image loaded*") and
  process.executable : "?:\\windows\\system32\\dns.exe" and
  not ?dll.code_signature.trusted == true and
  not file.code_signature.status == "Valid"
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



