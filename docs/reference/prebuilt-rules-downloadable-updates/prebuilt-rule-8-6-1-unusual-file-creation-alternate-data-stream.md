---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-unusual-file-creation-alternate-data-stream.html
---

# Unusual File Creation - Alternate Data Stream [prebuilt-rule-8-6-1-unusual-file-creation-alternate-data-stream]

Identifies suspicious creation of Alternate Data Streams on highly targeted files. This is uncommon for legitimate files and sometimes done by adversaries to hide malware.

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
* Defense Evasion
* Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3780]

## Triage and analysis

## Investigating Unusual File Creation - Alternate Data Stream

Alternate Data Streams (ADS) are file attributes only found on the NTFS file system. In this file system, files are built up from a couple of attributes; one of them is $Data, also known as the data attribute.

The regular data stream, also referred to as the unnamed data stream since the name string of this attribute is empty, contains the data inside the file. So any data stream that has a name is considered an alternate data stream.

Attackers can abuse these alternate data streams to hide malicious files, string payloads, etc. This rule detects the creation of alternate data streams on highly targeted file types.

> **Note**:
> This investigation guide uses the [Osquery Markdown Plugin](docs-content://solutions/security/investigate/run-osquery-from-investigation-guides.md) introduced in Elastic stack version 8.5.0. Older Elastic stacks versions will see unrendered markdown in this guide.

### Possible investigation steps

- Retrieve the contents of the alternate data stream, and analyze it for potential maliciousness. Analysts can use the following PowerShell cmdlet to accomplish this:
  - `Get-Content C:\Path\To\file.exe -stream SampleAlternateDataStreamName`
- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate any abnormal behavior by the subject process such as network connections, registry or file modifications, and any spawned child processes.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
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

- If this activity is expected and noisy in your environment, consider adding exceptions — preferably with a combination of process executable and file conditions.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4611]

```js
file where event.type == "creation" and

  file.path : "C:\\*:*" and
  not file.path : "C:\\*:zone.identifier*" and

  not process.executable :
          ("?:\\windows\\System32\\svchost.exe",
           "?:\\Windows\\System32\\inetsrv\\w3wp.exe",
           "?:\\Windows\\explorer.exe",
           "?:\\Windows\\System32\\sihost.exe",
           "?:\\Windows\\System32\\PickerHost.exe",
           "?:\\Windows\\System32\\SearchProtocolHost.exe",
           "?:\\Program Files (x86)\\Dropbox\\Client\\Dropbox.exe",
           "?:\\Program Files\\Rivet Networks\\SmartByte\\SmartByteNetworkService.exe",
           "?:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
           "?:\\Program Files\\ExpressConnect\\ExpressConnectNetworkService.exe",
           "?:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
           "?:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
           "?:\\Program Files\\Mozilla Firefox\\firefox.exe") and

  file.extension :
    (
      "pdf",
      "dll",
      "png",
      "exe",
      "dat",
      "com",
      "bat",
      "cmd",
      "sys",
      "vbs",
      "ps1",
      "hta",
      "txt",
      "vbe",
      "js",
      "wsh",
      "docx",
      "doc",
      "xlsx",
      "xls",
      "pptx",
      "ppt",
      "rtf",
      "gif",
      "jpg",
      "png",
      "bmp",
      "img",
      "iso"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)

* Sub-technique:

    * Name: NTFS File Attributes
    * ID: T1564.004
    * Reference URL: [https://attack.mitre.org/techniques/T1564/004/](https://attack.mitre.org/techniques/T1564/004/)



