---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/remote-windows-service-installed.html
---

# Remote Windows Service Installed [remote-windows-service-installed]

Identifies a network logon followed by Windows service creation with same LogonId. This could be indicative of lateral movement, but will be noisy if commonly done by administrators."

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

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
* Tactic: Lateral Movement
* Tactic: Persistence
* Data Source: System
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_878]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Remote Windows Service Installed**

Windows services are crucial for running background processes. Adversaries exploit this by installing services remotely to maintain persistence or move laterally within a network. The detection rule identifies suspicious service installations following a network logon, excluding known legitimate services, to flag potential unauthorized activities. This helps in identifying and mitigating threats early.

**Possible investigation steps**

* Review the source IP address from the authentication event to determine if it is from a known or trusted network segment. Investigate any unfamiliar or suspicious IP addresses.
* Check the winlog.logon.id to correlate the logon session with the service installation event, ensuring they are part of the same session.
* Investigate the user account associated with the logon session to determine if the activity aligns with their typical behavior or role within the organization.
* Examine the service file path from the service-installed event to identify if it is a known or legitimate application. Pay special attention to any paths not excluded in the query.
* Look into the history of the computer where the service was installed (winlog.computer_name) for any previous suspicious activities or alerts.
* Assess the timing and frequency of similar events to determine if this is an isolated incident or part of a broader pattern of suspicious behavior.

**False positive analysis**

* Administrative activities can trigger false positives when administrators frequently install or update services remotely. To manage this, create exceptions for known administrative accounts or specific IP addresses used by IT staff.
* Legitimate software installations or updates may appear as suspicious service installations. Maintain an updated list of authorized software paths and exclude these from the detection rule.
* Automated deployment tools like PDQ Deploy or Veeam Backup can cause false positives. Identify and exclude the service paths associated with these tools to reduce noise.
* Scheduled tasks that install or update services as part of routine maintenance can be mistaken for threats. Document and exclude these tasks from the rule to prevent unnecessary alerts.
* Internal security tools that perform regular checks or updates may also trigger alerts. Ensure these tools are recognized and their service paths are excluded from the detection criteria.

**Response and remediation**

* Isolate the affected system from the network to prevent further lateral movement by the adversary. This can be done by disabling network interfaces or using network segmentation tools.
* Terminate any unauthorized services identified by the alert to stop any malicious processes from running. Use task management tools or command-line utilities to stop and disable these services.
* Conduct a thorough review of recent logon events and service installations on the affected system to identify any additional unauthorized activities or compromised accounts.
* Change passwords for any accounts that were used in the unauthorized service installation, especially if they have administrative privileges, to prevent further unauthorized access.
* Restore the affected system from a known good backup if any malicious changes or persistence mechanisms are detected that cannot be easily remediated.
* Implement network monitoring and alerting for similar suspicious activities, such as unexpected service installations or network logons, to enhance detection and response capabilities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems or accounts have been compromised.


## Rule query [_rule_query_934]

```js
sequence by winlog.logon.id, winlog.computer_name with maxspan=1m
[authentication where event.action == "logged-in" and winlog.logon.type : "Network" and
event.outcome=="success" and source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1"]
[iam where event.action == "service-installed" and
 not winlog.event_data.SubjectLogonId : "0x3e7" and
 not winlog.event_data.ServiceFileName :
               ("?:\\Windows\\ADCR_Agent\\adcrsvc.exe",
                "?:\\Windows\\System32\\VSSVC.exe",
                "?:\\Windows\\servicing\\TrustedInstaller.exe",
                "?:\\Windows\\System32\\svchost.exe",
                "?:\\Program Files (x86)\\*.exe",
                "?:\\Program Files\\*.exe",
                "?:\\Windows\\PSEXESVC.EXE",
                "?:\\Windows\\System32\\sppsvc.exe",
                "?:\\Windows\\System32\\wbem\\WmiApSrv.exe",
                "?:\\WINDOWS\\RemoteAuditService.exe",
                "?:\\Windows\\VeeamVssSupport\\VeeamGuestHelper.exe",
                "?:\\Windows\\VeeamLogShipper\\VeeamLogShipper.exe",
                "?:\\Windows\\CAInvokerService.exe",
                "?:\\Windows\\System32\\upfc.exe",
                "?:\\Windows\\AdminArsenal\\PDQ*.exe",
                "?:\\Windows\\System32\\vds.exe",
                "?:\\Windows\\Veeam\\Backup\\VeeamDeploymentSvc.exe",
                "?:\\Windows\\ProPatches\\Scheduler\\STSchedEx.exe",
                "?:\\Windows\\System32\\certsrv.exe",
                "?:\\Windows\\eset-remote-install-service.exe",
                "?:\\Pella Corporation\\Pella Order Management\\GPAutoSvc.exe",
                "?:\\Pella Corporation\\OSCToGPAutoService\\OSCToGPAutoSvc.exe",
                "?:\\Pella Corporation\\Pella Order Management\\GPAutoSvc.exe",
                "?:\\Windows\\SysWOW64\\NwxExeSvc\\NwxExeSvc.exe",
                "?:\\Windows\\System32\\taskhostex.exe")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)



