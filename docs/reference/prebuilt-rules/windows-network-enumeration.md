---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/windows-network-enumeration.html
---

# Windows Network Enumeration [windows-network-enumeration]

Identifies attempts to enumerate hosts in a network using the built-in Windows net.exe tool.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
* logs-windows.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry](https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Tactic: Collection
* Resources: Investigation Guide
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 214

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1203]

**Triage and analysis**

**Investigating Windows Network Enumeration**

After successfully compromising an environment, attackers may try to gain situational awareness to plan their next steps. This can happen by running commands to enumerate network resources, users, connections, files, and installed security software.

This rule looks for the execution of the `net` utility to enumerate servers in the environment that hosts shared drives or printers. This information is useful to attackers as they can identify targets for lateral movements and search for valuable shared data.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Investigate any abnormal account behavior, such as command executions, file creations or modifications, and network connections.

**False positive analysis**

* Discovery activities are not inherently malicious if they occur in isolation. As long as the analyst did not identify suspicious activity related to the user or host, such alerts can be dismissed.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_757]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_1231]

```js
process where host.os.type == "windows" and event.type == "start" and
  ((process.name : "net.exe" or process.pe.original_file_name == "net.exe") or
   ((process.name : "net1.exe" or process.pe.original_file_name == "net1.exe") and
       not process.parent.name : "net.exe")) and
  (process.args : "view" or (process.args : "time" and process.args : "\\\\*")) and
  not process.command_line : "net  view \\\\localhost "


  /* expand when ancestry is available
  and not descendant of [process where event.type == "start" and process.name : "cmd.exe" and
                           ((process.parent.name : "userinit.exe") or
                            (process.parent.name : "gpscript.exe") or
                            (process.parent.name : "explorer.exe" and
                               process.args : "C:\\*\\Start Menu\\Programs\\Startup\\*.bat*"))]
  */
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

    * Name: Network Share Discovery
    * ID: T1135
    * Reference URL: [https://attack.mitre.org/techniques/T1135/](https://attack.mitre.org/techniques/T1135/)

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Network Shared Drive
    * ID: T1039
    * Reference URL: [https://attack.mitre.org/techniques/T1039/](https://attack.mitre.org/techniques/T1039/)



