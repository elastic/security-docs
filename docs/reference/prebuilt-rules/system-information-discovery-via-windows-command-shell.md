---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/system-information-discovery-via-windows-command-shell.html
---

# System Information Discovery via Windows Command Shell [system-information-discovery-via-windows-command-shell]

Identifies the execution of discovery commands to enumerate system information, files, and folders using the Windows Command Shell.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*
* logs-endpoint.events.process-*
* endgame-*
* logs-system.security*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Tactic: Execution
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 115

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1059]

**Triage and analysis**

**Investigating System Information Discovery via Windows Command Shell**

After successfully compromising an environment, attackers may try to gain situational awareness to plan their next steps. This can happen by running commands to enumerate network resources, users, connections, files, and installed security software.

This rule identifies commands to enumerate system information, files, and folders using the Windows Command Shell.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
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


## Setup [_setup_666]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_1110]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.name : "cmd.exe" and process.args : "/c" and process.args : ("set", "dir") and
  not process.parent.executable : (
    "?:\\Program Files\\*",
    "?:\\Program Files (x86)\\*",
    "?:\\PROGRA~1\\*",
    "?:\\TeamCity\\jre\\bin\\java.exe"
  ) and
  not process.args : (
    "*\\db\\rabbit@*", "*/db/rabbit@*",
    "*rabbitmq/db/*", "*RabbitMQ\\db*"
  ) and
  not process.parent.args : "*C:\\Program Files (x86)\\Tanium\\Tanium Client\\TPython\\TPython.bat*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)

* Technique:

    * Name: File and Directory Discovery
    * ID: T1083
    * Reference URL: [https://attack.mitre.org/techniques/T1083/](https://attack.mitre.org/techniques/T1083/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Windows Command Shell
    * ID: T1059.003
    * Reference URL: [https://attack.mitre.org/techniques/T1059/003/](https://attack.mitre.org/techniques/T1059/003/)



