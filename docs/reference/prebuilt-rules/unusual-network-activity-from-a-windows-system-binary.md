---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-network-activity-from-a-windows-system-binary.html
---

# Unusual Network Activity from a Windows System Binary [unusual-network-activity-from-a-windows-system-binary]

Identifies network activity from unexpected system applications. This may indicate adversarial activity as these applications are often leveraged by adversaries to execute code and evade detection.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.network-*
* winlogbeat-*
* logs-windows.sysmon_operational-*

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
* Tactic: Defense Evasion
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: Sysmon

**Version**: 214

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1134]

**Triage and analysis**

**Investigating Unusual Network Activity from a Windows System Binary**

Attackers can abuse certain trusted developer utilities to proxy the execution of malicious payloads. Since these utilities are usually signed, they can bypass the security controls that were put in place to prevent or detect direct execution.

This rule identifies network connections established by trusted developer utilities, which can indicate abuse to execute payloads or process masquerading.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate abnormal behaviors observed by the subject process, such as registry or file modifications, and any spawned child processes.
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

**False positive analysis**

* As trusted developer utilities have dual-use purposes, alerts derived from this rule are not essentially malicious. If these utilities are contacting internal or known trusted domains, review their security and consider creating exceptions if the domain is safe.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* If the malicious file was delivered via phishing:
* Block the email sender from sending future emails.
* Block the malicious web pages.
* Remove emails from the sender from mailboxes.
* Consider improvements to the security awareness program.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_1177]

```js
sequence by process.entity_id with maxspan=5m
  [process where host.os.type == "windows" and event.type == "start" and

     /* known applocker bypasses */
     (process.name : "bginfo.exe" or
      process.name : "cdb.exe" or
      process.name : "control.exe" or
      process.name : "cmstp.exe" or
      process.name : "csi.exe" or
      process.name : "dnx.exe" or
      process.name : "fsi.exe" or
      process.name : "ieexec.exe" or
      process.name : "iexpress.exe" or
      process.name : "installutil.exe" or
      process.name : "Microsoft.Workflow.Compiler.exe" or
      process.name : "MSBuild.exe" or
      process.name : "msdt.exe" or
      process.name : "mshta.exe" or
      process.name : "wscript.exe" or
      process.name : "msiexec.exe" or
      process.name : "msxsl.exe" or
      process.name : "odbcconf.exe" or
      process.name : "rcsi.exe" or
      process.name : "regsvr32.exe" or
      process.name : "xwizard.exe")]
  [network where
     (process.name : "bginfo.exe" or
      process.name : "cdb.exe" or
      process.name : "control.exe" or
      process.name : "cmstp.exe" or
      process.name : "csi.exe" or
      process.name : "dnx.exe" or
      process.name : "fsi.exe" or
      process.name : "ieexec.exe" or
      process.name : "iexpress.exe" or
      process.name : "installutil.exe" or
      process.name : "Microsoft.Workflow.Compiler.exe" or
      (
        process.name : "msbuild.exe" and
          destination.ip != "127.0.0.1"
      ) or
      process.name : "msdt.exe" or
      process.name : "mshta.exe" or
      (
        process.name : "msiexec.exe" and not
        dns.question.name : (
           "ocsp.digicert.com", "ocsp.verisign.com", "ocsp.comodoca.com", "ocsp.entrust.net", "ocsp.usertrust.com",
           "ocsp.godaddy.com", "ocsp.camerfirma.com", "ocsp.globalsign.com", "ocsp.sectigo.com", "*.local"
        ) and
        /* Localhost, DigiCert and Comodo CA IP addresses */
        not cidrmatch(destination.ip, "127.0.0.1", "192.229.211.108/32", "192.229.221.95/32",
                      "152.195.38.76/32", "104.18.14.101/32")
      ) or
      process.name : "msxsl.exe" or
      process.name : "odbcconf.exe" or
      process.name : "rcsi.exe" or
      process.name : "regsvr32.exe" or
      process.name : "xwizard.exe") and

      not dns.question.name : ("localhost", "setup.officetimeline.com", "us.deployment.endpoint.ingress.rapid7.com",
        "ctldl.windowsupdate.com", "crl?.digicert.com", "ocsp.digicert.com", "addon-cms-asl.eu.goskope.com", "crls.ssl.com",
        "evcs-ocsp.ws.symantec.com", "s.symcd.com", "s?.symcb.com", "crl.verisign.com", "oneocsp.microsoft.com", "crl.verisign.com",
        "aka.ms", "crl.comodoca.com", "acroipm2.adobe.com", "sv.symcd.com") and

      /* host query itself */
      not startswith~(dns.question.name, host.name)
      ]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Match Legitimate Name or Location
    * ID: T1036.005
    * Reference URL: [https://attack.mitre.org/techniques/T1036/005/](https://attack.mitre.org/techniques/T1036/005/)

* Technique:

    * Name: Trusted Developer Utilities Proxy Execution
    * ID: T1127
    * Reference URL: [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)

* Sub-technique:

    * Name: MSBuild
    * ID: T1127.001
    * Reference URL: [https://attack.mitre.org/techniques/T1127/001/](https://attack.mitre.org/techniques/T1127/001/)

* Sub-technique:

    * Name: Mshta
    * ID: T1218.005
    * Reference URL: [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)



