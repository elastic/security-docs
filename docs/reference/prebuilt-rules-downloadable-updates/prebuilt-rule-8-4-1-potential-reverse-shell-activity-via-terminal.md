---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-potential-reverse-shell-activity-via-terminal.html
---

# Potential Reverse Shell Activity via Terminal [prebuilt-rule-8-4-1-potential-reverse-shell-activity-via-terminal]

Identifies the execution of a shell process with suspicious arguments which may be indicative of reverse shell activity.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [https://github.com/WangYihang/Reverse-Shell-Manager](https://github.com/WangYihang/Reverse-Shell-Manager)
* [https://www.netsparker.com/blog/web-security/understanding-reverse-shells/](https://www.netsparker.com/blog/web-security/understanding-reverse-shells/)

**Tags**:

* Elastic
* Host
* Linux
* macOS
* Threat Detection
* Execution
* Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2581]

## Triage and analysis

## Investigating Potential Reverse Shell Activity via Terminal

A reverse shell is a mechanism that's abused to connect back to an attacker-controlled system. It effectively redirects
the system's input and output and delivers a fully functional remote shell to the attacker. Even private systems are
vulnerable since the connection is outgoing. This activity is typically the result of vulnerability exploitation,
malware infection, or penetration testing.

This rule identifies commands that are potentially related to reverse shell activities using shell applications.

### Possible investigation steps

- Examine the command line and extract the target domain or IP address information.
  - Check if the domain is newly registered or unexpected.
  - Check the reputation of the domain or IP address.
  - Scope other potentially compromised hosts in your environment by mapping hosts that also communicated with the
  domain or IP address.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Investigate any abnormal account behavior, such as command executions, file creations or modifications, and network
connections.
- Investigate any abnormal behavior by the subject process such as network connections, file modifications, and any
spawned child processes.

## False positive analysis

- This activity is unlikely to happen legitimately. Any activity that triggered the alert and is not inherently
malicious must be monitored by the security team.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Take actions to terminate processes and connections used by the attacker.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2971]

```js
process where event.type in ("start", "process_started") and
  process.name in ("sh", "bash", "zsh", "dash", "zmodload") and
  process.args : ("*/dev/tcp/*", "*/dev/udp/*", "*zsh/net/tcp*", "*zsh/net/udp*") and

  /* noisy FPs */
  not (process.parent.name : "timeout" and process.executable : "/var/lib/docker/overlay*") and
  not process.command_line : ("*/dev/tcp/sirh_db/*", "*/dev/tcp/remoteiot.com/*", "*dev/tcp/elk.stag.one/*", "*dev/tcp/kafka/*", "*/dev/tcp/$0/$1*", "*/dev/tcp/127.*", "*/dev/udp/127.*", "*/dev/tcp/localhost/*") and
  not process.parent.command_line : "runc init"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



