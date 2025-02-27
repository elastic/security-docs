---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-which-enumeration.html
---

# Suspicious which Enumeration [prebuilt-rule-8-17-4-suspicious-which-enumeration]

This rule monitors for the usage of the which command with an unusual amount of process arguments. Attackers may leverage the which command to enumerate the system for useful installed utilities that may be used after compromising a system to escalate privileges or move latteraly across the network.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4382]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious which Enumeration**

The `which` command in Linux environments is typically used to locate the executable path of a command. Adversaries may exploit this utility to identify installed software that can aid in privilege escalation or lateral movement. The detection rule flags unusual usage patterns, such as excessive arguments, which may indicate malicious enumeration. It filters out benign scenarios, focusing on potential threats by examining process attributes and parent-child relationships.

**Possible investigation steps**

* Review the process details to confirm the command line arguments used with the which command, focusing on whether the args_count is unusually high and if the arguments are related to known enumeration or exploitation tools.
* Examine the parent process of the which command to determine if it is a legitimate process or if it is associated with suspicious activity, especially if it is not one of the excluded parent names or paths.
* Investigate the user account associated with the process to determine if it is a legitimate user or if there are signs of compromise, such as unusual login times or locations.
* Check for any other recent alerts or logs related to the same host or user that might indicate a broader attack pattern or ongoing compromise.
* Assess the network activity from the host to identify any connections to known malicious IP addresses or unusual outbound traffic that could suggest lateral movement or data exfiltration.

**False positive analysis**

* Processes initiated by the *jem* parent process may trigger false positives. To handle this, add *jem* to the list of exceptions in the rule configuration.
* Executions within containerized environments, such as those under */vz/root/* or */var/lib/docker/*, are often benign. Exclude these paths from the rule to reduce noise.
* The *--tty-only* argument is typically used in legitimate scenarios. Consider adding this argument to the exception list to prevent unnecessary alerts.
* If the rule is noisy due to common utilities like *nmap*, *nc*, *gcc*, or *socat* being used with shell interpreters like *bash* or *zsh*, refine the rule by excluding these combinations.
* Regularly review and update the list of exceptions based on the evolving environment and usage patterns to maintain an effective balance between detection and false positive reduction.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement by the adversary.
* Terminate any suspicious processes associated with the `which` command that have an unusually high number of arguments, as identified by the detection rule.
* Conduct a thorough review of the system’s installed software and utilities to identify any unauthorized or suspicious installations that could be leveraged for privilege escalation.
* Analyze the process tree and parent-child relationships of the flagged `which` command execution to identify potential malicious scripts or binaries that initiated the command.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems have been compromised.
* Implement enhanced monitoring and logging for the `which` command and similar enumeration tools to detect future misuse.
* Review and update access controls and permissions to ensure that only authorized users have the ability to execute potentially sensitive commands and utilities.


## Rule query [_rule_query_5374]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start") and
  process.name == "which" and process.args_count >= 10 and not (
    process.parent.name == "jem" or
    process.parent.executable like ("/vz/root/*", "/var/lib/docker/*") or
    process.args == "--tty-only"
  )

/* potential tuning if rule would turn out to be noisy
and process.args in ("nmap", "nc", "ncat", "netcat", nc.traditional", "gcc", "g++", "socat") and
process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
*/
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



