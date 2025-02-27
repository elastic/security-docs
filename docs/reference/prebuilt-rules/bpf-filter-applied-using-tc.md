---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/bpf-filter-applied-using-tc.html
---

# BPF filter applied using TC [bpf-filter-applied-using-tc]

Detects when the tc (transmission control) binary is utilized to set a BPF (Berkeley Packet Filter) on a network interface. Tc is used to configure Traffic Control in the Linux kernel. It can shape, schedule, police and drop traffic. A threat actor can utilize tc to set a bpf filter on an interface for the purpose of manipulating the incoming traffic. This technique is not at all common and should indicate abnormal, suspicious or malicious activity.

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

* [https://github.com/h3xduck/TripleCross/blob/master/src/helpers/deployer.sh](https://github.com/h3xduck/TripleCross/blob/master/src/helpers/deployer.sh)
* [https://man7.org/linux/man-pages/man8/tc.8.html](https://man7.org/linux/man-pages/man8/tc.8.md)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Threat: TripleCross
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_208]

**Triage and analysis**

[TBC: QUOTE]
**Investigating BPF filter applied using TC**

BPF (Berkeley Packet Filter) is a powerful tool for network traffic analysis and control, often used with the `tc` command to manage traffic on Linux systems. Adversaries may exploit this by setting BPF filters to manipulate or monitor network traffic covertly. The detection rule identifies suspicious use of `tc` to apply BPF filters, flagging potential misuse by checking for specific command patterns and excluding legitimate processes.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the `/usr/sbin/tc` command with arguments "filter", "add", and "bpf" to ensure the alert is not a false positive.
* Investigate the parent process of the `tc` command to determine if it is a known legitimate process or if it appears suspicious, especially since the rule excludes `/usr/sbin/libvirtd`.
* Check the user account associated with the process execution to assess if it is a privileged account and whether the activity aligns with the user’s typical behavior.
* Analyze network traffic logs around the time of the alert to identify any unusual patterns or connections that may indicate malicious activity.
* Correlate this event with other security alerts or logs to identify if this is part of a broader attack pattern or campaign, such as the use of the TripleCross threat.
* Review system logs for any other suspicious activities or anomalies that occurred before or after the alert to gather additional context.

**False positive analysis**

* Legitimate use of tc by virtualization software like libvirtd can trigger the rule. To handle this, exclude processes where the parent executable is /usr/sbin/libvirtd, as indicated in the rule.
* Network administrators may use tc with BPF filters for legitimate traffic management tasks. Identify and document these use cases, then create exceptions for specific command patterns or user accounts involved in these activities.
* Automated scripts or system management tools that configure network interfaces might use tc with BPF filters. Review these scripts and tools, and if they are verified as safe, exclude their process signatures from triggering the rule.
* Regular audits of network configurations can help distinguish between legitimate and suspicious use of BPF filters. Implement a process to regularly review and update exceptions based on these audits to minimize false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further manipulation or monitoring of network traffic by the adversary.
* Terminate the suspicious `tc` process to stop any ongoing malicious activity related to the BPF filter application.
* Conduct a thorough review of network traffic logs to identify any unauthorized data exfiltration or communication with known malicious IP addresses.
* Restore the affected system from a known good backup to ensure that no malicious configurations or software persist.
* Implement network segmentation to limit the potential impact of similar threats in the future, ensuring critical systems are isolated from less secure areas.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if additional systems are compromised.
* Update and enhance endpoint detection and response (EDR) solutions to improve monitoring and alerting for similar suspicious activities involving `tc` and BPF filters.


## Setup [_setup_143]

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


## Rule query [_rule_query_213]

```js
process where host.os.type == "linux" and event.type != "end" and process.executable == "/usr/sbin/tc" and
process.args == "filter" and process.args == "add" and process.args == "bpf" and
not process.parent.executable == "/usr/sbin/libvirtd"
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



