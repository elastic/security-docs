---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-root-network-connection-via-gdb-cap-sys-ptrace.html
---

# Root Network Connection via GDB CAP_SYS_PTRACE [prebuilt-rule-8-17-4-root-network-connection-via-gdb-cap-sys-ptrace]

Identifies instances where GDB (granted the CAP_SYS_PTRACE capability) is executed, after which an outbound network connection is initiated by UID/GID 0 (root). In Linux, the CAP_SYS_PTRACE capability grants a process the ability to use the ptrace system call, which is typically used for debugging and allows the process to trace and control other processes. Attackers may leverage this capability to hook and inject into a process that is running with root permissions in order to execute shell code and gain a reverse shell with root privileges.

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
* Tactic: Privilege Escalation
* Tactic: Execution
* Tactic: Command and Control
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4519]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Root Network Connection via GDB CAP_SYS_PTRACE**

GDB, a debugger, can be granted the CAP_SYS_PTRACE capability, allowing it to trace and control processes, a feature often exploited by attackers. By injecting code into root processes, adversaries can execute malicious payloads, such as reverse shells. The detection rule identifies suspicious sequences where GDB is used with this capability, followed by a root-initiated network connection, signaling potential privilege escalation or command and control activities.

**Possible investigation steps**

* Review the process execution details to confirm the presence of GDB with CAP_SYS_PTRACE capability by examining the process name, capabilities, and user ID fields in the alert.
* Investigate the network connection attempt by analyzing the process name and user ID fields to determine if the connection was initiated by a root process.
* Check the timeline of events to ensure the sequence of GDB execution followed by a network connection attempt occurred within the specified maxspan of 30 seconds.
* Identify the destination IP address and port of the network connection to assess if it is known for malicious activity or associated with command and control servers.
* Examine the host system for any signs of compromise or unauthorized changes, focusing on processes and files that may have been affected by the potential privilege escalation.
* Correlate the alert with other security events or logs from the same host to identify any additional suspicious activities or patterns that may indicate a broader attack.

**False positive analysis**

* Development environments may trigger this rule when developers use GDB with CAP_SYS_PTRACE for legitimate debugging purposes. To mitigate, create exceptions for specific user IDs or processes known to be involved in development activities.
* Automated testing frameworks that utilize GDB for testing applications with root privileges can cause false positives. Identify and exclude these processes or testing environments from the rule.
* System maintenance scripts that require debugging of root processes might inadvertently match the rule criteria. Review and whitelist these scripts or the specific time frames they run to prevent unnecessary alerts.
* Security tools that perform legitimate process tracing as part of their monitoring activities could be mistaken for malicious behavior. Ensure these tools are recognized and excluded from the detection rule.
* Custom administrative scripts that use GDB for process management under root privileges should be documented and excluded to avoid false alarms.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further malicious activity and potential lateral movement.
* Terminate any suspicious processes associated with GDB that have been granted the CAP_SYS_PTRACE capability, especially those initiated by non-root users.
* Conduct a thorough review of the affected system’s logs to identify any unauthorized changes or additional malicious activities that may have occurred.
* Reset credentials and review permissions for any accounts that may have been compromised, particularly those with elevated privileges.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Implement network monitoring to detect and block any further unauthorized outbound connections from root processes.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_1351]

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


## Rule query [_rule_query_5511]

```js
sequence by host.id, process.entry_leader.entity_id with maxspan=30s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "gdb" and
   (process.thread.capabilities.effective : "CAP_SYS_PTRACE" or process.thread.capabilities.permitted : "CAP_SYS_PTRACE") and
   user.id != "0"]
  [network where host.os.type == "linux" and event.action == "connection_attempted" and event.type == "start" and
   process.name != null and user.id == "0"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Sub-technique:

    * Name: Ptrace System Calls
    * ID: T1055.008
    * Reference URL: [https://attack.mitre.org/techniques/T1055/008/](https://attack.mitre.org/techniques/T1055/008/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)

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



