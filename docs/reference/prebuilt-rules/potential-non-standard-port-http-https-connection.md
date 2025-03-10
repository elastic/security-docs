---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-non-standard-port-http-https-connection.html
---

# Potential Non-Standard Port HTTP/HTTPS connection [potential-non-standard-port-http-https-connection]

Identifies potentially malicious processes communicating via a port paring typically not associated with HTTP/HTTPS. For example, HTTP over port 8443 or port 440 as opposed to the traditional port 80 , 443. Adversaries may make changes to the standard port a protocol uses to bypass filtering or muddle analysis/parsing of network data.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Command and Control
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_715]

**Triage and analysis**

**Investigating Potential Non-Standard Port HTTP/HTTPS connection**

Attackers may alter standard protocol ports, like using HTTP on port 8443 instead of 80, to bypass network filtering and complicate network data analysis.

This rule looks for HTTP/HTTPS processes where the destination port is not any of the default 80/443 HTTP/HTTPS ports.

[TBC: QUOTE]
**Possible investigation steps**

* Identify any signs of suspicious network activity or anomalies that may indicate command and control activity or data exfiltration. This could include unexpected traffic patterns or unusual network behavior.
* Investigate listening ports and open sockets to look for potential suspicious network traffic, reverse shells or data exfiltration.
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

* Suspicious Network Activity to the Internet by Previously Unknown Executable - 53617418-17b4-4e9c-8a2c-8deb8086ca4b

**False positive analysis**

* If this activity is related to new benign software installation activity, consider adding exceptions — preferably with a combination of user and command line conditions.
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


## Rule query [_rule_query_761]

```js
network where process.name : ("http", "https") and destination.port not in (80, 443) and event.action in (
  "connection_attempted", "ipv4_connection_attempt_event", "connection_accepted", "ipv4_connection_accept_event"
) and destination.ip != "127.0.0.1"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)

* Sub-technique:

    * Name: Web Protocols
    * ID: T1071.001
    * Reference URL: [https://attack.mitre.org/techniques/T1071/001/](https://attack.mitre.org/techniques/T1071/001/)

* Technique:

    * Name: Non-Standard Port
    * ID: T1571
    * Reference URL: [https://attack.mitre.org/techniques/T1571/](https://attack.mitre.org/techniques/T1571/)

* Technique:

    * Name: Encrypted Channel
    * ID: T1573
    * Reference URL: [https://attack.mitre.org/techniques/T1573/](https://attack.mitre.org/techniques/T1573/)

* Sub-technique:

    * Name: Symmetric Cryptography
    * ID: T1573.001
    * Reference URL: [https://attack.mitre.org/techniques/T1573/001/](https://attack.mitre.org/techniques/T1573/001/)

* Sub-technique:

    * Name: Asymmetric Cryptography
    * ID: T1573.002
    * Reference URL: [https://attack.mitre.org/techniques/T1573/002/](https://attack.mitre.org/techniques/T1573/002/)



