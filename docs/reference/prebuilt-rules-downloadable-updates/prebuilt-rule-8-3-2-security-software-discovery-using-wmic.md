---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-security-software-discovery-using-wmic.html
---

# Security Software Discovery using WMIC [prebuilt-rule-8-3-2-security-software-discovery-using-wmic]

Identifies the use of Windows Management Instrumentation Command (WMIC) to discover certain System Security Settings such as AntiVirus or Host Firewall details.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
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
* Discovery
* has_guide

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2488]

## Triage and analysis

## Investigating Security Software Discovery using WMIC

After successfully compromising an environment, attackers may try to gain situational awareness to plan their next steps.
This can happen by running commands to enumerate network resources, users, connections, files, and installed security
software.

This rule looks for the execution of the `wmic` utility with arguments compatible to the enumeration of the security
software installed on the host. Attackers can use this information to decide whether or not to infect a system, disable
protections, use bypasses, etc.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Investigate any abnormal account behavior, such as command executions, file creations or modifications, and network
connections.

## False positive analysis

- Discovery activities are not inherently malicious if they occur in isolation. As long as the analyst did not identify
suspicious activity related to the user or host, such alerts can be dismissed.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2861]

```js
process where event.type == "start" and
   (process.name:"wmic.exe" or process.pe.original_file_name:"wmic.exe") and
    process.args:"/namespace:\\\\root\\SecurityCenter2" and process.args:"Get"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Software Discovery
    * ID: T1518
    * Reference URL: [https://attack.mitre.org/techniques/T1518/](https://attack.mitre.org/techniques/T1518/)

* Sub-technique:

    * Name: Security Software Discovery
    * ID: T1518.001
    * Reference URL: [https://attack.mitre.org/techniques/T1518/001/](https://attack.mitre.org/techniques/T1518/001/)



