---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-reverse-shell-via-suspicious-binary.html
---

# Potential Reverse Shell via Suspicious Binary [potential-reverse-shell-via-suspicious-binary]

This detection rule detects the creation of a shell through a chain consisting of the execution of a suspicious binary (located in a commonly abused location or executed manually) followed by a network event and ending with a shell being spawned. Stageless reverse tcp shells display this behaviour. Attackers may spawn reverse shells to establish persistence onto a target system.

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

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_765]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Reverse Shell via Suspicious Binary**

Reverse shells are a common technique used by attackers to gain persistent access to a compromised system. They exploit legitimate shell environments to execute commands remotely. Adversaries often deploy binaries in unusual directories to evade detection. The detection rule identifies suspicious binaries executed in these locations, followed by network activity and shell spawning, indicating potential reverse shell activity. This approach helps in identifying unauthorized access attempts on Linux systems.

**Possible investigation steps**

* Review the process execution details to identify the suspicious binary’s path and name, focusing on the directories specified in the query such as /tmp, /var/tmp, and /dev/shm.
* Examine the parent process of the suspicious binary to determine if it was spawned by a legitimate shell process like bash or sh, as indicated in the query.
* Analyze the network activity associated with the suspicious binary, paying attention to the destination IP address to identify any external connections that are not local (i.e., not 127.0.0.1 or ::1).
* Check the process tree to see if a new shell was spawned following the network activity, which could indicate a reverse shell attempt.
* Investigate the user account under which the suspicious process was executed to assess if it aligns with expected behavior or if it might be compromised.
* Correlate the event timestamps to understand the sequence of actions and verify if they align with typical reverse shell behavior patterns.

**False positive analysis**

* Legitimate administrative scripts or binaries may be executed from directories like /tmp or /var/tmp during maintenance tasks. To handle this, create exceptions for known scripts or binaries used by trusted administrators.
* Automated deployment tools might temporarily use directories such as /dev/shm or /run for staging files. Identify these tools and exclude their processes from triggering the rule.
* Custom monitoring or backup scripts could initiate network connections from non-standard directories. Review these scripts and whitelist their activities if they are verified as safe.
* Development or testing environments might involve executing binaries from unusual locations. Ensure these environments are well-documented and exclude their processes from the detection rule.
* Some legitimate applications may spawn shells as part of their normal operation. Identify these applications and add them to an exception list to prevent false alerts.

**Response and remediation**

* Isolate the affected system from the network immediately to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule, especially those originating from unusual directories or involving shell spawning.
* Conduct a thorough review of the system’s scheduled tasks, startup scripts, and cron jobs to identify and remove any unauthorized entries that may have been added by the attacker.
* Analyze network logs to identify any external IP addresses involved in the suspicious network activity and block these IPs at the firewall to prevent further connections.
* Restore the affected system from a known good backup to ensure that any malicious changes are reverted.
* Update and patch the system to the latest security standards to close any vulnerabilities that may have been exploited.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_492]

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


## Rule query [_rule_query_813]

```js
sequence by host.id, process.entity_id with maxspan=1s
[ process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
  process.executable : (
  "./*", "/tmp/*", "/var/tmp/*", "/var/www/*", "/dev/shm/*", "/etc/init.d/*", "/etc/rc*.d/*",
  "/etc/crontab", "/etc/cron.*", "/etc/update-motd.d/*", "/usr/lib/update-notifier/*",
  "/boot/*", "/srv/*", "/run/*", "/root/*", "/etc/rc.local"
   ) and
  process.parent.name : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and not
  process.name : ("curl", "wget", "ping", "apt", "dpkg", "yum", "rpm", "dnf", "dockerd") ]
[ network where host.os.type == "linux" and event.type == "start" and event.action in ("connection_attempted", "connection_accepted") and
  process.executable : (
  "./*", "/tmp/*", "/var/tmp/*", "/var/www/*", "/dev/shm/*", "/etc/init.d/*", "/etc/rc*.d/*",
  "/etc/crontab", "/etc/cron.*", "/etc/update-motd.d/*", "/usr/lib/update-notifier/*",
  "/boot/*", "/srv/*", "/run/*", "/root/*", "/etc/rc.local"
   ) and destination.ip != null and destination.ip != "127.0.0.1" and destination.ip != "::1" ]
[ process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
  process.name : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
  process.parent.name : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") ]
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



