---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-account-discovery-command-via-system-account.html
---

# Account Discovery Command via SYSTEM Account [prebuilt-rule-8-3-2-account-discovery-command-via-system-account]

Identifies when the SYSTEM account uses an account discovery utility. This could be a sign of discovery activity after an adversary has achieved privilege escalation.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: low

**Risk score**: 21

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

## Investigation guide [_investigation_guide_2480]

## Triage and analysis

## Investigating Account Discovery Command via SYSTEM Account

After successfully compromising an environment, attackers may try to gain situational awareness to plan their next steps.
This can happen by running commands to enumerate network resources, users, connections, files, and installed security
software.

This rule looks for the execution of account discovery utilities using the SYSTEM account, which is commonly observed
after attackers successfully perform privilege escalation or exploit web applications.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
  - If the process tree includes a web-application server process such as w3wp, httpd.exe, nginx.exe and alike,
  investigate any suspicious file creation or modification in the last 48 hours to assess the presence of any potential
  webshell backdoor.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Determine how the SYSTEM account is being used. For example, users with administrator privileges can spawn a system
shell using Windows services, scheduled tasks or other third party utilities.

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
- Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).
- Use the data collected through the analysis to investigate other machines affected in the environment.

## Rule query [_rule_query_2853]

```js
process where event.type == "start" and
  (?process.Ext.token.integrity_level_name : "System" or
  ?winlog.event_data.IntegrityLevel : "System") and
  (process.name : "whoami.exe" or
  (process.name : "net1.exe" and not process.parent.name : "net.exe"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Owner/User Discovery
    * ID: T1033
    * Reference URL: [https://attack.mitre.org/techniques/T1033/](https://attack.mitre.org/techniques/T1033/)



