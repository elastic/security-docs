---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/linux-ssh-x11-forwarding.html
---

# Linux SSH X11 Forwarding [linux-ssh-x11-forwarding]

This rule monitors for X11 forwarding via SSH. X11 forwarding is a feature that allows users to run graphical applications on a remote server and display the application’s graphical user interface on their local machine. Attackers can abuse X11 forwarding for tunneling their GUI-based tools, pivot through compromised systems, and create covert communication channels, enabling lateral movement and facilitating remote control of systems within a network.

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

**References**:

* [https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding](https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Command and Control
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_477]

**Triage and analysis**

**Investigating Linux SSH X11 Forwarding**

Attackers can leverage SSH X11 forwarding to capture a user’s graphical desktop session and potentially execute unauthorized GUI applications remotely.

This rule looks for the execution of SSH in conjunction with command line arguments that are capable of setting up X11 forwarding.

[TBC: QUOTE]
**Possible investigation steps**

* Identify any signs of suspicious network activity or anomalies that may indicate network forwarding activity. This could include unexpected traffic patterns or unusual network behavior.
* Investigate listening ports and open sockets to look for potential protocol tunneling, reverse shells, or data exfiltration.
* !{osquery{"label":"Osquery - Retrieve Listening Ports","query":"SELECT pid, address, port, socket, protocol, path FROM listening_ports"}}
* !{osquery{"label":"Osquery - Retrieve Open Sockets","query":"SELECT pid, family, remote_address, remote_port, socket, state FROM process_open_sockets"}}
* Identify the user account that performed the action, analyze it, and check whether it should perform this kind of action.
* `!{osquery{"label":"Osquery - Retrieve Information for a Specific User","query":"SELECT * FROM users WHERE username = {user.name}"}}`
* Investigate whether the user is currently logged in and active.
* `!{osquery{"label":"Osquery - Investigate the Account Authentication Status","query":"SELECT * FROM logged_in_users WHERE user = {user.name}"}}`
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence and whether they are located in expected locations.
* !{osquery{"label":"Osquery - Retrieve Running Processes by User","query":"SELECT pid, username, name FROM processes p JOIN users u ON u.uid = p.uid ORDER BY username"}}
* !{osquery{"label":"Osquery - Retrieve Process Info","query":"SELECT name, cmdline, parent, path, uid FROM processes"}}
* Investigate other alerts associated with the user/host during the past 48 hours.
* If scripts or executables were dropped, retrieve the files and determine if they are malicious:
* Use a private sandboxed malware analysis system to perform analysis.
* Observe and collect information about the following activities:
* Attempts to contact external domains and addresses.
* Check if the domain is newly registered or unexpected.
* Check the reputation of the domain or IP address.
* File access, modification, and creation activities.

**Related rules**

* Potential Linux Tunneling and/or Port Forwarding - 6ee947e9-de7e-4281-a55d-09289bdf947e

**False positive analysis**

* If this activity is related to new benign software installation activity, consider adding exceptions — preferably with a combination of user and command line conditions.
* If this activity is related to a system administrator or developer who uses port tunneling/forwarding for benign purposes, consider adding exceptions for specific user accounts or hosts.
* Try to understand the context of the execution by thinking about the user, machine, or business purpose. A small number of endpoints, such as servers with unique software, might appear unusual but satisfy a specific business need.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors, such as reverse shells, reverse proxies, or droppers, that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Leverage the incident response data and logging to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_512]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
process.name in ("ssh", "sshd") and process.args in ("-X", "-Y") and process.args_count >= 3 and
process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Protocol Tunneling
    * ID: T1572
    * Reference URL: [https://attack.mitre.org/techniques/T1572/](https://attack.mitre.org/techniques/T1572/)



