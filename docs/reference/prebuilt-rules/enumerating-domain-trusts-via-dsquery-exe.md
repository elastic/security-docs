---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/enumerating-domain-trusts-via-dsquery-exe.html
---

# Enumerating Domain Trusts via DSQUERY.EXE [enumerating-domain-trusts-via-dsquery-exe]

Identifies the use of dsquery.exe for domain trust discovery purposes. Adversaries may use this command-line utility to enumerate trust relationships that may be used for Lateral Movement opportunities in Windows multi-domain forest environments.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11))
* [https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944](https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944)

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
* Data Source: SentinelOne
* Data Source: Crowdstrike

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_296]

**Triage and analysis**

**Investigating Enumerating Domain Trusts via DSQUERY.EXE**

Active Directory (AD) domain trusts define relationships between domains within a Windows AD environment. In this setup, a "trusting" domain permits users from a "trusted" domain to access resources. These trust relationships can be configurable as one-way, two-way, transitive, or non-transitive, enabling controlled access and resource sharing across domains.

This rule identifies the usage of the `dsquery.exe` utility to enumerate domain trusts. Attackers can use this information to enable the next actions in a target environment, such as lateral movement.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Investigate other alerts associated with the user/host during the past 48 hours.

**False positive analysis**

* Discovery activities are not inherently malicious if they occur in isolation and are done within the user business context (e.g., an administrator in this context). As long as the analyst did not identify suspicious activity related to the user or host, such alerts can be dismissed.

**Related rules**

* Enumerating Domain Trusts via NLTEST.EXE - 84da2554-e12a-11ec-b896-f661ea17fbcd

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Restrict PowerShell usage outside of IT and engineering business units using GPOs, AppLocker, Intune, or similar software.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_309]

```js
process where host.os.type == "windows" and event.type == "start" and
    (process.name : "dsquery.exe" or ?process.pe.original_file_name: "dsquery.exe") and
    process.args : "*objectClass=trustedDomain*"
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



