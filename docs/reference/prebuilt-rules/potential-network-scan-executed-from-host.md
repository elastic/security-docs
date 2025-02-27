---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-network-scan-executed-from-host.html
---

# Potential Network Scan Executed From Host [potential-network-scan-executed-from-host]

This threshold rule monitors for the rapid execution of unix utilities that are capable of conducting network scans. Adversaries may leverage built-in tools such as ping, netcat or socat to execute ping sweeps across the network while attempting to evade detection or due to the lack of network mapping tools available on the compromised host.

**Rule type**: threshold

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*

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
* Tactic: Discovery
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_713]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Network Scan Executed From Host**

In Linux environments, utilities like ping, netcat, and socat are essential for network diagnostics and communication. However, adversaries can exploit these tools to perform network scans, identifying active hosts and services for further exploitation. The detection rule identifies rapid execution of these utilities, signaling potential misuse for network reconnaissance, by monitoring process initiation events linked to these tools.

**Possible investigation steps**

* Review the process initiation events to confirm the rapid execution of utilities like ping, netcat, or socat by examining the process.name field in the alert.
* Identify the user account associated with the process execution by checking the user information in the event data to determine if the activity aligns with expected behavior.
* Analyze the command line arguments used with the executed utilities by inspecting the process.command_line field to understand the scope and intent of the network scan.
* Correlate the alert with other recent events on the host by reviewing event timestamps and related process activities to identify any patterns or additional suspicious behavior.
* Check network logs or firewall logs for any unusual outbound connections or traffic patterns originating from the host to assess the potential impact of the network scan.
* Investigate the host’s recent login history and user activity to determine if there are signs of unauthorized access or compromise that could explain the network scan activity.

**False positive analysis**

* Routine network diagnostics by system administrators can trigger alerts. To manage this, create exceptions for known administrator accounts or specific IP addresses frequently used for legitimate network diagnostics.
* Automated monitoring scripts that use these utilities for health checks or performance monitoring may cause false positives. Identify and exclude these scripts by their process names or execution paths.
* Scheduled tasks or cron jobs that involve network utilities for maintenance purposes can be mistaken for network scans. Exclude these tasks by their specific scheduling patterns or associated user accounts.
* Security tools that perform regular network sweeps as part of their functionality might be flagged. Whitelist these tools by their process names or hash values to prevent unnecessary alerts.
* Development or testing environments where network utilities are used for testing purposes can generate false positives. Implement exclusions based on environment-specific identifiers or network segments.

**Response and remediation**

* Isolate the affected host from the network to prevent further reconnaissance or lateral movement by the adversary.
* Terminate any suspicious processes identified by the detection rule, such as those involving ping, netcat, or socat, to halt ongoing network scans.
* Conduct a thorough review of the host’s process logs and network activity to identify any additional indicators of compromise or related malicious activity.
* Reset credentials and review access permissions for accounts that were active on the compromised host to prevent unauthorized access.
* Apply patches and updates to the host’s operating system and installed software to mitigate vulnerabilities that could be exploited by adversaries.
* Enhance network monitoring and logging to detect similar reconnaissance activities in the future, ensuring that alerts are configured to notify security teams promptly.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional hosts or systems are affected.


## Setup [_setup_454]

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
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_758]

```js
event.category:process and host.os.type:linux and event.action:(exec or exec_event or executed or process_started) and
event.type:start and process.name:(ping or nping or hping or hping2 or hping3 or nc or ncat or netcat or socat)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Network Service Discovery
    * ID: T1046
    * Reference URL: [https://attack.mitre.org/techniques/T1046/](https://attack.mitre.org/techniques/T1046/)



