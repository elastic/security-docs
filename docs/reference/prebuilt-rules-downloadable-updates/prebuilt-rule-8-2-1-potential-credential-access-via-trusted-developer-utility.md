---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-potential-credential-access-via-trusted-developer-utility.html
---

# Potential Credential Access via Trusted Developer Utility [prebuilt-rule-8-2-1-potential-credential-access-via-trusted-developer-utility]

An instance of MSBuild, the Microsoft Build Engine, loaded DLLs (dynamically linked libraries) responsible for Windows credential management. This technique is sometimes used for credential dumping.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 11

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2267]

## Triage and analysis

## Investigating Potential Credential Access via Trusted Developer Utility

The Microsoft Build Engine is a platform for building applications. This engine, also known as MSBuild, provides an XML
schema for a project file that controls how the build platform processes and builds software.

Adversaries can abuse MSBuild to proxy the execution of malicious code. The inline task capability of MSBuild that was
introduced in .NET version 4 allows for C# or Visual Basic code to be inserted into an XML project file. MSBuild will
compile and execute the inline task. `MSBuild.exe` is a signed Microsoft binary, and the execution of code using it can bypass
application control defenses that are configured to allow `MSBuild.exe` execution.

This rule looks for the MSBuild process loading `vaultcli.dll` or `SAMLib.DLL`, which indicates the execution of
credential access activities.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate abnormal behaviors observed by the subject process, such as network connections, registry or file
modifications, and any spawned child processes.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Examine the command line to identify the `.csproj` file location.
- Retrieve the file and determine if it is malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled tasks creation.
  - Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.
- Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the target
host after the registry modification.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that
  attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2581]

```js
sequence by process.entity_id
 [process where event.type == "start" and (process.name : "MSBuild.exe" or process.pe.original_file_name == "MSBuild.exe")]
 [any where (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
  (dll.name : ("vaultcli.dll", "SAMLib.DLL") or file.name : ("vaultcli.dll", "SAMLib.DLL"))]
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



