---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-remote-file-copy-via-teamviewer.html
---

# Remote File Copy via TeamViewer [prebuilt-rule-8-17-4-remote-file-copy-via-teamviewer]

Identifies an executable or script file remotely downloaded via a TeamViewer transfer session.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [http://web.archive.org/web/20230329160957/https://blog.menasec.net/2019/11/hunting-for-suspicious-use-of.html](http://web.archive.org/web/20230329160957/https://blog.menasec.net/2019/11/hunting-for-suspicious-use-of.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Command and Control
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: SentinelOne

**Version**: 213

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4698]

**Triage and analysis**

**Investigating Remote File Copy via TeamViewer**

Attackers commonly transfer tooling or malware from external systems into a compromised environment using the command and control channel. However, they can also abuse legitimate utilities to drop these files.

TeamViewer is a remote access and remote control tool used by helpdesks and system administrators to perform various support activities. It is also frequently used by attackers and scammers to deploy malware interactively and other malicious activities. This rule looks for the TeamViewer process creating files with suspicious extensions.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Contact the user to gather information about who and why was conducting the remote access.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Check whether the company uses TeamViewer for the support activities and if there is a support ticket related to this access.
* Examine the host for derived artifacts that indicate suspicious activities:
* Analyze the file using a private sandboxed analysis system.
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

* This mechanism can be used legitimately. Analysts can dismiss the alert if the company relies on TeamViewer to conduct remote access and the triage has not identified suspicious or malicious files.

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
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_5653]

```js
file where host.os.type == "windows" and event.type == "creation" and process.name : "TeamViewer.exe" and
  file.extension : ("exe", "dll", "scr", "com", "bat", "ps1", "vbs", "vbe", "js", "wsh", "hta") and
  not
  (
    file.path : (
      "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*.js",
      "?:\\Users\\*\\AppData\\Local\\Temp\\TeamViewer\\update.exe",
      "?:\\Users\\*\\AppData\\Local\\Temp\\?\\TeamViewer\\update.exe",
      "?:\\Users\\*\\AppData\\Local\\TeamViewer\\CustomConfigs\\???????\\TeamViewer_Resource_??.dll",
      "?:\\Users\\*\\AppData\\Local\\TeamViewer\\CustomConfigs\\???????\\TeamViewer*.exe"
    ) and process.code_signature.trusted == true
  )
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

* Technique:

    * Name: Remote Access Software
    * ID: T1219
    * Reference URL: [https://attack.mitre.org/techniques/T1219/](https://attack.mitre.org/techniques/T1219/)



