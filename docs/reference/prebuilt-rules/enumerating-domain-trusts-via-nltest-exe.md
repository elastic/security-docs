---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/enumerating-domain-trusts-via-nltest-exe.html
---

# Enumerating Domain Trusts via NLTEST.EXE [enumerating-domain-trusts-via-nltest-exe]

Identifies the use of nltest.exe for domain trust discovery purposes. Adversaries may use this command-line utility to enumerate domain trusts and gain insight into trust relationships, as well as the state of Domain Controller (DC) replication in a Microsoft Windows NT Domain.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-crowdstrike.fdr*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11))
* [https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/](https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Endgame
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: Crowdstrike

**Version**: 214

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_297]

**Triage and analysis**

**Investigating Enumerating Domain Trusts via NLTEST.EXE**

Active Directory (AD) domain trusts define relationships between domains within a Windows AD environment. In this setup, a "trusting" domain permits users from a "trusted" domain to access resources. These trust relationships can be configurable as one-way, two-way, transitive, or non-transitive, enabling controlled access and resource sharing across domains.

This rule identifies the usage of the `nltest.exe` utility to enumerate domain trusts. Attackers can use this information to enable the next actions in a target environment, such as lateral movement.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Investigate other alerts associated with the user/host during the past 48 hours.

**False positive analysis**

* Discovery activities are not inherently malicious if they occur in isolation and are done within the user business context (e.g., an administrator in this context). As long as the analyst did not identify suspicious activity related to the user or host, such alerts can be dismissed.

**Related rules**

* Enumerating Domain Trusts via DSQUERY.EXE - 06a7a03c-c735-47a6-a313-51c354aef6c3

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Restrict PowerShell usage outside of IT and engineering business units using GPOs, AppLocker, Intune, or similar software.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_310]

```js
process where host.os.type == "windows" and event.type == "start" and
    process.name : "nltest.exe" and process.args : (
        "/DCLIST:*", "/DCNAME:*", "/DSGET*",
        "/LSAQUERYFTI:*", "/PARENTDOMAIN",
        "/DOMAIN_TRUSTS", "/BDC_QUERY:*"
        ) and
not process.parent.name : "PDQInventoryScanner.exe" and
not user.id in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Remote System Discovery
    * ID: T1018
    * Reference URL: [https://attack.mitre.org/techniques/T1018/](https://attack.mitre.org/techniques/T1018/)

* Technique:

    * Name: Domain Trust Discovery
    * ID: T1482
    * Reference URL: [https://attack.mitre.org/techniques/T1482/](https://attack.mitre.org/techniques/T1482/)



