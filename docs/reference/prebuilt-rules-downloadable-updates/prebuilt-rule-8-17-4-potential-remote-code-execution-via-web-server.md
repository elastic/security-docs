---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-remote-code-execution-via-web-server.html
---

# Potential Remote Code Execution via Web Server [prebuilt-rule-8-17-4-potential-remote-code-execution-via-web-server]

Identifies suspicious commands executed via a web server, which may suggest a vulnerability and remote shell access. Attackers may exploit a vulnerability in a web application to execute commands via a web server, or place a backdoor file that can be abused to gain code execution as a mechanism for persistence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://pentestlab.blog/tag/web-shell/](https://pentestlab.blog/tag/web-shell/)
* [https://www.elastic.co/security-labs/elastic-response-to-the-the-spring4shell-vulnerability-cve-2022-22965](https://www.elastic.co/security-labs/elastic-response-to-the-the-spring4shell-vulnerability-cve-2022-22965)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Initial Access
* Data Source: Elastic Endgame
* Use Case: Vulnerability
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: SentinelOne

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4467]

**Triage and analysis**

**Investigating Potential Remote Code Execution via Web Server**

Adversaries may backdoor web servers with web shells to establish persistent access to systems. A web shell is a malicious script, often embedded into a compromised web server, that grants an attacker remote access and control over the server. This enables the execution of arbitrary commands, data exfiltration, and further exploitation of the target network.

This rule detects a web server process spawning script and command line interface programs, potentially indicating attackers executing commands using the web shell.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate abnormal behaviors by the subject process such as network connections, file modifications, and any other spawned child processes.
* Investigate listening ports and open sockets to look for potential reverse shells or data exfiltration.
* !{osquery{"label":"Osquery - Retrieve Listening Ports","query":"SELECT pid, address, port, socket, protocol, path FROM listening_ports"}}
* !{osquery{"label":"Osquery - Retrieve Open Sockets","query":"SELECT pid, family, remote_address, remote_port, socket, state FROM process_open_sockets"}}
* Investigate the process information for malicious or uncommon processes/process trees.
* !{osquery{"label":"Osquery - Retrieve Process Info","query":"SELECT name, cmdline, parent, path, uid FROM processes"}}
* Investigate the process tree spawned from the user that is used to run the web application service. A user that is running a web application should not spawn other child processes.
* `!{osquery{"label":"Osquery - Retrieve Process Info for Webapp User","query":"SELECT name, cmdline, parent, path, uid FROM processes WHERE uid = {process.user.id}"}}`
* Examine the command line to determine which commands or scripts were executed.
* Investigate other alerts associated with the user/host during the past 48 hours.
* If scripts or executables were dropped, retrieve the files and determine if they are malicious:
* Use a private sandboxed malware analysis system to perform analysis.
* Observe and collect information about the following activities:
* Attempts to contact external domains and addresses.
* Check if the domain is newly registered or unexpected.
* Check the reputation of the domain or IP address.
* File access, modification, and creation activities.
* Cron jobs, services and other persistence mechanisms.
* !{osquery{"label":"Osquery - Retrieve Crontab Information","query":"SELECT * FROM crontab"}}

**False positive analysis**

* This activity is unlikely to happen legitimately. Any activity that triggered the alert and is not inherently malicious must be monitored by the security team.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Leverage the incident response data and logging to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_1310]

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


## Rule query [_rule_query_5459]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start") and process.parent.executable : (
  "/usr/sbin/nginx", "/usr/local/sbin/nginx",
  "/usr/sbin/apache", "/usr/local/sbin/apache",
  "/usr/sbin/apache2", "/usr/local/sbin/apache2",
  "/usr/sbin/php*", "/usr/local/sbin/php*",
  "/usr/sbin/lighttpd", "/usr/local/sbin/lighttpd",
  "/usr/sbin/hiawatha", "/usr/local/sbin/hiawatha",
  "/usr/local/bin/caddy",
  "/usr/local/lsws/bin/lswsctrl",
  "*/bin/catalina.sh"
) and
process.name : (
  "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "python*", "php*", "perl", "ruby", "lua*", "openssl", "nc",
  "netcat", "ncat", "telnet", "awk", "socat"
  ) and process.args : (
  "whoami", "id", "uname", "cat", "hostname", "ip", "curl", "wget", "pwd", "ls", "cd", "python*", "php*", "perl",
  "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk", "socat"
  ) and not process.name == "phpquery"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Server Software Component
    * ID: T1505
    * Reference URL: [https://attack.mitre.org/techniques/T1505/](https://attack.mitre.org/techniques/T1505/)

* Sub-technique:

    * Name: Web Shell
    * ID: T1505.003
    * Reference URL: [https://attack.mitre.org/techniques/T1505/003/](https://attack.mitre.org/techniques/T1505/003/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)



