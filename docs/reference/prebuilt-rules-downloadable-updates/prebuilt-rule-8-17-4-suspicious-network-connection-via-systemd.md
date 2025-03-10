---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-network-connection-via-systemd.html
---

# Suspicious Network Connection via systemd [prebuilt-rule-8-17-4-suspicious-network-connection-via-systemd]

Detects suspicious network events executed by systemd, potentially indicating persistence through a systemd backdoor. Systemd is a system and service manager for Linux operating systems, used to initialize and manage system processes. Attackers can backdoor systemd for persistence by creating or modifying systemd unit files to execute malicious scripts or commands, or by replacing legitimate systemd binaries with compromised ones, ensuring that their malicious code is automatically executed at system startup or during certain system events.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Command and Control
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4498]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Network Connection via systemd**

Systemd is a critical component in Linux, managing system processes and services. Adversaries exploit it by altering unit files or replacing binaries to ensure malicious scripts run at startup, achieving persistence. The detection rule identifies unusual network activities initiated by systemd, flagging potential backdoor usage by monitoring specific processes and network attempts, thus aiding in early threat detection.

**Possible investigation steps**

* Review the process details to identify the specific script or command executed by systemd, focusing on the process names such as "python*", "php*", "perl", "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk".
* Examine the parent process information to confirm that the suspicious process was indeed initiated by systemd, ensuring the parent process name is "systemd".
* Investigate the network connection attempt details, including the destination IP address and port, to determine if the connection is to a known malicious or suspicious endpoint.
* Check the process executable path to ensure it is not a known legitimate path, especially looking for unusual paths that might indicate a compromised binary, excluding "/tmp/newroot/bin/curl".
* Analyze the systemd unit files on the host to identify any unauthorized modifications or additions that could indicate persistence mechanisms.
* Correlate the event with other security alerts or logs from the same host to identify any patterns or additional indicators of compromise.
* Consult threat intelligence sources to gather more context on the IP addresses or domains involved in the network connection attempt.

**False positive analysis**

* Legitimate administrative scripts or maintenance tasks that use scripting languages like Python, PHP, or Perl may trigger the rule. To handle this, identify and document these scripts, then create exceptions for their specific process names or paths.
* Automated system monitoring tools that perform network checks using utilities like netcat or telnet might be flagged. Review these tools and whitelist their process names or executable paths to prevent false alerts.
* Custom applications or services that are legitimately started by systemd and initiate network connections could be misidentified. Verify these applications and add them to an allowlist based on their process names or parent entity IDs.
* Development or testing environments where developers frequently use scripting languages for network operations may cause false positives. Consider excluding these environments from monitoring or creating specific rules that account for their unique behaviors.

**Response and remediation**

* Isolate the affected host immediately from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes identified in the alert, particularly those initiated by systemd that match the specified process names (e.g., python, php, perl).
* Review and restore any modified or suspicious systemd unit files to their original state, ensuring no unauthorized scripts or commands are set to execute at startup.
* Conduct a thorough scan of the affected system for additional indicators of compromise, focusing on persistence mechanisms and unauthorized network connections.
* Reinstall or verify the integrity of systemd binaries to ensure they have not been replaced or tampered with by malicious actors.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for systemd-related activities and network connections to detect similar threats in the future.


## Setup [_setup_1332]

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


## Rule query [_rule_query_5490]

```js
sequence by host.id with maxspan=5s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name == "systemd" and process.name in (
     "python*", "php*", "perl", "ruby", "lua*", "openssl", "nc", "netcat", "ncat", "telnet", "awk"
   )
  ] by process.entity_id
  [network where host.os.type == "linux" and event.action == "connection_attempted" and event.type == "start" and
   not process.executable == "/tmp/newroot/bin/curl"] by process.parent.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Systemd Service
    * ID: T1543.002
    * Reference URL: [https://attack.mitre.org/techniques/T1543/002/](https://attack.mitre.org/techniques/T1543/002/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



