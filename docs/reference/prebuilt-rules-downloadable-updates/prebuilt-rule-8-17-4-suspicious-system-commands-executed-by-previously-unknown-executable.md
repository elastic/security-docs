---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-system-commands-executed-by-previously-unknown-executable.html
---

# Suspicious System Commands Executed by Previously Unknown Executable [prebuilt-rule-8-17-4-suspicious-system-commands-executed-by-previously-unknown-executable]

This rule monitors for the execution of several commonly used system commands executed by a previously unknown executable located in commonly abused directories. An alert from this rule can indicate the presence of potentially malicious activity, such as the execution of unauthorized or suspicious processes attempting to run malicious code. Detecting and investigating such behavior can help identify and mitigate potential security threats, protecting the system and its data from potential compromise.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

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
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4419]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious System Commands Executed by Previously Unknown Executable**

In Linux environments, system commands are essential for managing processes and configurations. Adversaries exploit this by executing commands via unknown executables in vulnerable directories, aiming to run unauthorized code. The detection rule identifies such anomalies by monitoring command executions from unfamiliar sources, excluding known safe processes, thus highlighting potential threats for further investigation.

**Possible investigation steps**

* Review the process.executable path to determine if it is located in a commonly abused directory such as /tmp, /dev/shm, or /var/tmp, which may indicate malicious intent.
* Examine the process.args to identify which specific system command was executed (e.g., hostname, id, ifconfig) and assess whether its execution is typical for the system’s normal operations.
* Check the process.parent.executable to understand the parent process that initiated the suspicious command execution, ensuring it is not a known safe process or a legitimate system service.
* Investigate the user account associated with the process to determine if it has the necessary permissions and if the activity aligns with the user’s typical behavior.
* Correlate the event with other logs or alerts from the same host to identify any patterns or additional suspicious activities that may indicate a broader compromise.
* Assess the risk score and severity in the context of the environment to prioritize the investigation and response efforts accordingly.

**False positive analysis**

* System maintenance scripts or automated tasks may trigger alerts if they execute common system commands from directories like /tmp or /var/tmp. To handle this, identify these scripts and add their executables to the exclusion list.
* Custom user scripts that perform routine checks using commands like ls or ps might be flagged. Review these scripts and consider adding their paths to the known safe processes to prevent unnecessary alerts.
* Development or testing environments often use temporary executables in directories such as /dev/shm. If these are known and non-threatening, include their paths in the exception list to reduce false positives.
* Some monitoring tools or agents might execute commands like uptime or whoami from non-standard locations. Verify these tools and update the exclusion criteria to include their executables or parent processes.
* In environments with containerized applications, processes running from /run/containerd or similar paths might be incorrectly flagged. Ensure these paths are accounted for in the exclusion settings if they are part of legitimate operations.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified by the alert, especially those originating from unknown executables in commonly abused directories.
* Conduct a thorough review of the affected directories (e.g., /tmp, /var/tmp, /dev/shm) to identify and remove any unauthorized or malicious files or executables.
* Restore any altered system configurations or files from a known good backup to ensure system integrity.
* Implement stricter access controls and permissions on the directories identified in the alert to prevent unauthorized executable placement.
* Monitor the system for any signs of persistence mechanisms, such as cron jobs or startup scripts, and remove any that are unauthorized.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems may be compromised.


## Setup [_setup_1263]

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


## Rule query [_rule_query_5411]

```js
host.os.type:linux and event.category:process and event.action:(exec or exec_event or fork or fork_event) and
process.executable:(* and (
  /etc/crontab or /bin/* or /boot/* or /dev/shm/* or /etc/cron.*/* or /etc/init.d/* or /etc/rc*.d/* or /etc/update-motd.d/* or
  /home/*/.* or /tmp/* or /usr/bin/* or /usr/lib/update-notifier/* or /usr/share/* or /var/tmp/*
) and not /tmp/go-build*) and
process.args:(hostname or id or ifconfig or ls or netstat or ps or pwd or route or top or uptime or whoami) and
not (process.name:
  (apt or dnf or docker or dockerd or dpkg or hostname or id or ls or netstat or ps or pwd or rpm or snap or
  snapd or sudo or top or uptime or which or whoami or yum) or
process.parent.executable:(
  /opt/cassandra/bin/cassandra or /opt/nessus/sbin/nessusd or /opt/nessus_agent/sbin/nessus-agent-module or /opt/puppetlabs/puppet/bin/puppet or
  /opt/puppetlabs/puppet/bin/ruby or /usr/libexec/platform-python or /usr/local/cloudamize/bin/CCAgent or /usr/sbin/sshd or /bin/* or
  /etc/network/* or /opt/Elastic/* or /opt/TrendMicro* or /opt/aws/* or /opt/eset/* or /opt/rapid7/* or /run/containerd/* or /run/k3s/* or
  /snap/* or /tmp/dpkg-licenses* or /tmp/newroot/* or /usr/bin/* or /var/lib/amagent/* or /var/lib/docker/* or /vz/*
  ) or
  process.executable:(/run/containerd/* or /srv/snp/docker/* or /tmp/.criu*)
)
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



