---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-suspicious-utility-launched-via-proxychains.html
---

# Suspicious Utility Launched via ProxyChains [prebuilt-rule-8-17-3-suspicious-utility-launched-via-proxychains]

This rule monitors for the execution of suspicious linux tools through ProxyChains. ProxyChains is a command-line tool that enables the routing of network connections through intermediary proxies, enhancing anonymity and enabling access to restricted resources. Attackers can exploit the ProxyChains utility to hide their true source IP address, evade detection, and perform malicious activities through a chain of proxy servers, potentially masking their identity and intentions.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.bitsadmin.com/living-off-the-foreign-land-windows-as-offensive-platform](https://blog.bitsadmin.com/living-off-the-foreign-land-windows-as-offensive-platform)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Command and Control
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3920]

**Triage and analysis**

**Investigating Suspicious Utility Launched via ProxyChains**

Attackers can leverage `proxychains` to obfuscate their origin and bypass network defenses by routing their malicious traffic through multiple intermediary servers.

This rule looks for a list of suspicious processes spawned through `proxychains` by analyzing process command line arguments.

[TBC: QUOTE]
**Possible investigation steps**

* Identify any signs of suspicious network activity or anomalies that may indicate network obfuscation. This could include unexpected traffic patterns or unusual network behavior.
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

* ProxyChains Activity - 4b868f1f-15ff-4ba3-8c11-d5a7a6356d37
* Potential Protocol Tunneling via Chisel Client - 3f12325a-4cc6-410b-8d4c-9fbbeb744cfd
* Potential Protocol Tunneling via Chisel Server - ac8805f6-1e08-406c-962e-3937057fa86f
* Potential Linux Tunneling and/or Port Forwarding - 6ee947e9-de7e-4281-a55d-09289bdf947e
* Potential Protocol Tunneling via EarthWorm - 9f1c4ca3-44b5-481d-ba42-32dc215a2769

**False positive analysis**

* If this activity is related to new benign software installation activity, consider adding exceptions — preferably with a combination of user and command line conditions.
* If this activity is related to a system administrator or developer who uses this utility for benign purposes, consider adding exceptions for specific user accounts or hosts.
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


## Setup [_setup_815]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either "Traditional Endpoints" or "Cloud Workloads".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_4855]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started")
 and process.name == "proxychains" and process.args : (
  "ssh", "sshd", "sshuttle", "socat", "iodine", "iodined", "dnscat", "hans", "hans-ubuntu", "ptunnel-ng",
  "ssf", "3proxy", "ngrok", "gost", "pivotnacci", "chisel*", "nmap", "ping", "python*", "php*", "perl", "ruby",
  "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk", "java", "telnet", "ftp", "curl", "wget"
)
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



