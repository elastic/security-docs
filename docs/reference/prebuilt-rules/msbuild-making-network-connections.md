---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/msbuild-making-network-connections.html
---

# MsBuild Making Network Connections [msbuild-making-network-connections]

Identifies MsBuild.exe making outbound network connections. This may indicate adversarial activity as MsBuild is often leveraged by adversaries to execute code and evade detection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-endpoint.events.network-*
* logs-windows.sysmon_operational-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://riccardoancarani.github.io/2019-10-19-hunting-covenant-msbuild/](https://riccardoancarani.github.io/2019-10-19-hunting-covenant-msbuild/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: Sysmon

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_551]

**Triage and analysis**

**Performance**

The performance impact of this rule is expected to be low to medium because of the first sequence, which looks for MsBuild.exe process execution. The events for this first sequence may be noisy, consider adding exceptions.

**Investigating MsBuild Making Network Connections**

By examining the specific traits of Windows binaries (such as process trees, command lines, network connections, registry modifications, and so on) it’s possible to establish a baseline of normal activity. Deviations from this baseline can indicate malicious activity, such as masquerading and deserve further investigation.

The Microsoft Build Engine, also known as MSBuild, is a platform for building applications. This engine provides an XML schema for a project file that controls how the build platform processes and builds software, and can be abused to proxy code execution.

This rule looks for the `Msbuild.exe` utility execution, followed by a network connection to an external address. Attackers can abuse MsBuild to execute malicious files or masquerade as those utilities in order to bypass detections and evade defenses.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate other alerts associated with the user/host during the past 48 hours.
* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate any abnormal behavior by the subject process such as network connections, registry or file modifications, and any spawned child processes.
* Investigate the file digital signature and process original filename, if suspicious, treat it as potential malware.
* Investigate the target host that the signed binary is communicating with.
* Check if the domain is newly registered or unexpected.
* Check the reputation of the domain or IP address.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
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

**False positive analysis**

* If this activity is expected and noisy in your environment, consider adding exceptions — preferably with a combination of destination IP address and command line conditions.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_592]

```js
sequence by process.entity_id with maxspan=30s

  /* Look for MSBuild.exe process execution */
  /* The events for this first sequence may be noisy, consider adding exceptions */
  [process where host.os.type == "windows"
    and (
          process.pe.original_file_name: "MSBuild.exe" or
          process.name: "MSBuild.exe"
        )
    and event.type == "start" and user.id != "S-1-5-18"]

  /* Followed by a network connection to an external address */
  /* Exclude domains that are known to be benign */
  [network where host.os.type == "windows"
    and event.action: ("connection_attempted", "lookup_requested")
    and (
          process.pe.original_file_name: "MSBuild.exe" or
          process.name: "MSBuild.exe"
        )
    and not user.id != "S-1-5-18" and
    not cidrmatch(destination.ip, "127.0.0.1", "::1") and
    not dns.question.name : (
      "localhost",
      "dc.services.visualstudio.com",
      "vortex.data.microsoft.com",
      "api.nuget.org")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Trusted Developer Utilities Proxy Execution
    * ID: T1127
    * Reference URL: [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)

* Sub-technique:

    * Name: MSBuild
    * ID: T1127.001
    * Reference URL: [https://attack.mitre.org/techniques/T1127/001/](https://attack.mitre.org/techniques/T1127/001/)



