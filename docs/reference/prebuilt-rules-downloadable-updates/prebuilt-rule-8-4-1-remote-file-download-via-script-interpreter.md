---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-remote-file-download-via-script-interpreter.html
---

# Remote File Download via Script Interpreter [prebuilt-rule-8-4-1-remote-file-download-via-script-interpreter]

Identifies built-in Windows script interpreters (cscript.exe or wscript.exe) being used to download an executable file from a remote destination.

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
* Command and Control
* Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2678]

## Triage and analysis

## Investigating Remote File Download via Script Interpreter

The Windows Script Host (WSH) is a Windows automation technology, which is ideal for non-interactive scripting needs,
such as logon scripting, administrative scripting, and machine automation.

Attackers commonly use WSH scripts as their initial access method, acting like droppers for second stage payloads, but
can also use them to download tools and utilities needed to accomplish their goals.

This rule looks for DLLs and executables downloaded using `cscript.exe` or `wscript.exe`.

> **Note**:
> This investigation guide uses the [Osquery Markdown Plugin](docs-content://solutions/security/investigate/run-osquery-from-investigation-guides.md) introduced in Elastic stack version 8.5.0. Older Elastic stacks versions will see unrendered markdown in this guide.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Examine the host for derived artifacts that indicates suspicious activities:
  - Analyze both the script and the executable involved using a private sandboxed analysis system.
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

- The usage of these script engines by regular users is unlikely. In the case of authorized benign true positives
(B-TPs), exceptions can be added.

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
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_3068]

```js
sequence by host.id, process.entity_id
  [network where process.name : ("wscript.exe", "cscript.exe") and network.protocol != "dns" and
   network.direction : ("outgoing", "egress") and network.type == "ipv4" and destination.ip != "127.0.0.1"
  ]
  [file where event.type == "creation" and file.extension : ("exe", "dll")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)



