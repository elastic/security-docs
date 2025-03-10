---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potentially-suspicious-process-started-via-tmux-or-screen.html
---

# Potentially Suspicious Process Started via tmux or screen [potentially-suspicious-process-started-via-tmux-or-screen]

This rule monitors for the execution of suspicious commands via screen and tmux. When launching a command and detaching directly, the commands will be executed in the background via its parent process. Attackers may leverage screen or tmux to execute commands while attempting to evade detection.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_795]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potentially Suspicious Process Started via tmux or screen**

Tmux and screen are terminal multiplexers that allow users to manage multiple terminal sessions from a single window, facilitating multitasking and session persistence. Adversaries may exploit these tools to execute commands stealthily, detaching sessions to run processes in the background. The detection rule identifies suspicious processes initiated by tmux or screen, focusing on potentially malicious commands, to uncover attempts at evading security measures.

**Possible investigation steps**

* Review the process details to identify the specific command executed by tmux or screen, focusing on the process.name field to determine if it matches any known suspicious commands like "nmap", "nc", "wget", etc.
* Examine the user account associated with the process to determine if the activity aligns with their typical behavior or if it appears anomalous.
* Check the parent process information, specifically process.parent.name, to confirm that the process was indeed initiated by tmux or screen, and assess if this behavior is expected for the user or system.
* Investigate the network activity associated with the process, especially if the command involves network utilities like "curl" or "ping", to identify any unusual or unauthorized connections.
* Correlate the event with other security alerts or logs from the same host or user to identify any patterns or additional suspicious activities that might indicate a broader attack or compromise.

**False positive analysis**

* System administrators or developers may use tmux or screen to run legitimate maintenance scripts or development tools like Java, PHP, or Perl. To manage these, create exceptions for known scripts or processes that are regularly executed by trusted users.
* Automated monitoring or testing tools might utilize tmux or screen to execute network diagnostic commands such as ping or nmap. Identify and whitelist these tools if they are part of routine operations.
* Some backup or data transfer processes might use wget or curl to fetch resources. Verify the source and destination of these processes and exclude them if they are part of scheduled tasks.
* Developers might use tmux or screen to run interactive sessions with languages like Ruby or Lua for debugging purposes. Establish a list of trusted users and exclude their sessions from triggering alerts.
* In environments where remote management is common, tools like ngrok might be used for legitimate purposes. Ensure that these tools are configured securely and exclude them if they are part of authorized workflows.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes identified as being initiated by tmux or screen, especially those matching the query criteria.
* Conduct a thorough review of the affected system’s process tree and logs to identify any additional malicious activity or persistence mechanisms.
* Reset credentials and review access permissions for any accounts that were active on the affected system to prevent unauthorized access.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are compromised.
* Implement network monitoring to detect any unusual outbound connections or data exfiltration attempts from the affected host.
* Update and enhance detection rules to include additional suspicious command patterns or behaviors observed during the investigation.


## Rule query [_rule_query_843]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  process.parent.name in ("screen", "tmux") and process.name like (
    "nmap", "nc", "ncat", "netcat", "socat", "nc.openbsd", "ngrok", "ping", "java", "php*", "perl", "ruby", "lua*",
    "openssl", "telnet", "wget", "curl", "id"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)



