---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/kerberos-traffic-from-unusual-process.html
---

# Kerberos Traffic from Unusual Process [kerberos-traffic-from-unusual-process]

Identifies network connections to the standard Kerberos port from an unusual process. On Windows, the only process that normally performs Kerberos traffic from a domain joined host is lsass.exe.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.network-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: SentinelOne

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_444]

**Triage and analysis**

**Investigating Kerberos Traffic from Unusual Process**

Kerberos is the default authentication protocol in Active Directory, designed to provide strong authentication for client/server applications by using secret-key cryptography.

Domain-joined hosts usually perform Kerberos traffic using the `lsass.exe` process. This rule detects the occurrence of traffic on the Kerberos port (88) by processes other than `lsass.exe` to detect the unusual request and usage of Kerberos tickets.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Check if the Destination IP is related to a Domain Controller.
* Review event ID 4769 for suspicious ticket requests.
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

* This rule uses a Kerberos-related port but does not identify the protocol used on that port. HTTP traffic on a non-standard port or destination IP address unrelated to Domain controllers can create false positives.
* Exceptions can be added for noisy/frequent connections.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Ticket requests can be used to investigate potentially compromised accounts.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_479]

```js
network where host.os.type == "windows" and event.type == "start" and network.direction == "egress" and
  destination.port == 88 and source.port >= 49152 and process.pid != 4 and destination.address : "*" and
  not
  (
    process.executable : (
        "\\device\\harddiskvolume?\\program files (x86)\\nmap\\nmap.exe",
        "\\device\\harddiskvolume?\\program files (x86)\\nmap oem\\nmap.exe",
        "\\device\\harddiskvolume?\\windows\\system32\\lsass.exe",
        "?:\\Program Files\\Amazon Corretto\\jdk1*\\bin\\java.exe",
        "?:\\Program Files\\BlackBerry\\UEM\\Proxy Server\\bin\\prunsrv.exe",
        "?:\\Program Files\\BlackBerry\\UEM\\Core\\tomcat-core\\bin\\tomcat9.exe",
        "?:\\Program Files\\DBeaver\\dbeaver.exe",
        "?:\\Program Files\\Docker\\Docker\\resources\\com.docker.backend.exe",
        "?:\\Program Files\\Docker\\Docker\\resources\\com.docker.vpnkit.exe",
        "?:\\Program Files\\Docker\\Docker\\resources\\vpnkit.exe",
        "?:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "?:\\Program Files\\Internet Explorer\\iexplore.exe",
        "?:\\Program Files\\JetBrains\\PyCharm Community Edition*\\bin\\pycharm64.exe",
        "?:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "?:\\Program Files\\Oracle\\VirtualBox\\VirtualBoxVM.exe",
        "?:\\Program Files\\Puppet Labs\\Puppet\\puppet\\bin\\ruby.exe",
        "?:\\Program Files\\rapid7\\nexpose\\nse\\.DLLCACHE\\nseserv.exe",
        "?:\\Program Files\\Silverfort\\Silverfort AD Adapter\\SilverfortServer.exe",
        "?:\\Program Files\\Tenable\\Nessus\\nessusd.exe",
        "?:\\Program Files\\VMware\\VMware View\\Server\\bin\\ws_TomcatService.exe",
        "?:\\Program Files (x86)\\Advanced Port Scanner\\advanced_port_scanner.exe",
        "?:\\Program Files (x86)\\DesktopCentral_Agent\\bin\\dcpatchscan.exe",
        "?:\\Program Files (x86)\\GFI\\LanGuard 12 Agent\\lnsscomm.exe",
        "?:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        "?:\\Program Files (x86)\\Internet Explorer\\iexplore.exe",
        "?:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "?:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        "?:\\Program Files (x86)\\Microsoft Silverlight\\sllauncher.exe",
        "?:\\Program Files (x86)\\Nmap\\nmap.exe",
        "?:\\Program Files (x86)\\Nmap OEM\\nmap.exe",
        "?:\\Program Files (x86)\\nwps\\NetScanTools Pro\\NSTPRO.exe",
        "?:\\Program Files (x86)\\SAP BusinessObjects\\tomcat\\bin\\tomcat9.exe",
        "?:\\Program Files (x86)\\SuperScan\\scanner.exe",
        "?:\\Program Files (x86)\\Zscaler\\ZSATunnel\\ZSATunnel.exe",
        "?:\\Windows\\System32\\lsass.exe",
        "?:\\Windows\\System32\\MicrosoftEdgeCP.exe",
        "?:\\Windows\\System32\\svchost.exe",
        "?:\\Windows\\SysWOW64\\vmnat.exe",
        "?:\\Windows\\SystemApps\\Microsoft.MicrosoftEdge_*\\MicrosoftEdge.exe",
        "System"
    ) and process.code_signature.trusted == true
  ) and
 destination.address != "127.0.0.1" and destination.address != "::1"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal or Forge Kerberos Tickets
    * ID: T1558
    * Reference URL: [https://attack.mitre.org/techniques/T1558/](https://attack.mitre.org/techniques/T1558/)



