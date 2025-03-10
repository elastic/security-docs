---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-reverse-shell-via-suspicious-child-process.html
---

# Potential Reverse Shell via Suspicious Child Process [prebuilt-rule-8-17-4-potential-reverse-shell-via-suspicious-child-process]

This detection rule detects the creation of a shell through a suspicious process chain. Any reverse shells spawned by the specified utilities that are initialized from a single process followed by a network connection attempt will be captured through this rule. Attackers may spawn reverse shells to establish persistence onto a target system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4413]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Reverse Shell via Suspicious Child Process**

Reverse shells are a common technique used by attackers to gain remote access to a compromised system. They exploit scripting languages and utilities like Python, Perl, and Netcat to execute commands remotely. The detection rule identifies suspicious process chains and network activities, such as unexpected shell spawns and outbound connections, to flag potential reverse shell attempts, leveraging process and network event analysis to detect anomalies.

**Possible investigation steps**

* Review the process chain to identify the parent process and determine if it is expected behavior for the system. Check the process.parent.name field for any unusual or unauthorized parent processes.
* Analyze the process arguments captured in the alert, such as process.args, to understand the command being executed and assess if it aligns with known reverse shell patterns.
* Investigate the network connection details, focusing on the destination.ip field, to determine if the connection is to a known malicious IP or an unexpected external address.
* Check the process.name field to identify the specific utility used (e.g., python, perl, nc) and verify if its usage is legitimate or if it indicates a potential compromise.
* Correlate the alert with other security events or logs from the same host.id to identify any additional suspicious activities or patterns that may indicate a broader attack.
* Consult threat intelligence sources to gather information on any identified IP addresses or domains involved in the network connection to assess their reputation and potential threat level.

**False positive analysis**

* Development and testing environments may frequently execute scripts using languages like Python, Perl, or Ruby, which can trigger the rule. To manage this, consider excluding specific host IDs or process names associated with known development activities.
* Automated scripts or cron jobs that utilize network connections for legitimate purposes, such as data backups or updates, might be flagged. Identify these processes and add them to an exception list based on their parent process names or specific arguments.
* System administrators might use tools like Netcat or OpenSSL for troubleshooting or monitoring network connections. If these activities are routine and verified, exclude them by specifying the administrator’s user ID or the specific command patterns used.
* Security tools or monitoring solutions that simulate attack scenarios for testing purposes can also trigger this rule. Ensure these tools are recognized and excluded by their process names or associated network activities.
* Custom scripts that use shell commands to interact with remote systems for maintenance tasks may appear suspicious. Review these scripts and exclude them by their unique process arguments or parent process names.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule, particularly those involving scripting languages or utilities like Python, Perl, or Netcat.
* Conduct a forensic analysis of the affected system to identify any additional indicators of compromise, such as unauthorized user accounts or modified system files.
* Review and reset credentials for any accounts that may have been accessed or compromised during the incident.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Monitor network traffic for any signs of further suspicious activity, focusing on outbound connections from the affected host.
* Escalate the incident to the security operations center (SOC) or relevant security team for further investigation and to ensure comprehensive remediation efforts.


## Setup [_setup_1257]

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


## Rule query [_rule_query_5405]

```js
sequence by host.id, process.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "fork") and (
    (process.name : "python*" and process.args : "-c" and process.args : (
     "*import*pty*spawn*", "*import*subprocess*call*"
    )) or
    (process.name : "perl*" and process.args : "-e" and process.args : "*socket*" and process.args : (
     "*exec*", "*system*"
    )) or
    (process.name : "ruby*" and process.args : ("-e", "-rsocket") and process.args : (
     "*TCPSocket.new*", "*TCPSocket.open*"
     )) or
    (process.name : "lua*" and process.args : "-e" and process.args : "*socket.tcp*" and process.args : (
     "*io.popen*", "*os.execute*"
    )) or
    (process.name : "php*" and process.args : "-r" and process.args : "*fsockopen*" and process.args : "*/bin/*sh*") or
    (process.name : ("awk", "gawk", "mawk", "nawk") and process.args : "*/inet/tcp/*") or
    (process.name : "openssl" and process.args : "-connect") or
    (process.name : ("nc", "ncat", "netcat") and process.args == "-e" and process.args_count >= 3 and
     not process.args == "-z") or
    (process.name : "telnet" and process.args_count >= 3)
  ) and process.parent.name : (
    "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "python*", "php*", "perl", "ruby", "lua*",
    "openssl", "nc", "netcat", "ncat", "telnet", "awk")]
  [network where host.os.type == "linux" and event.type == "start" and event.action in ("connection_attempted", "connection_accepted") and
    process.name : ("python*", "php*", "perl", "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk") and
    destination.ip != null and not cidrmatch(destination.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1")]
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

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)



