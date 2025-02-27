---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-termination-of-esxi-process.html
---

# Suspicious Termination of ESXI Process [prebuilt-rule-8-17-4-suspicious-termination-of-esxi-process]

Identifies instances where VMware processes, such as "vmware-vmx" or "vmx," are terminated on a Linux system by a "kill" command. The rule monitors for the "end" event type, which signifies the termination of a process. The presence of a "kill" command as the parent process for terminating VMware processes may indicate that a threat actor is attempting to interfere with the virtualized environment on the targeted system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.bleepingcomputer.com/news/security/massive-esxiargs-ransomware-attack-targets-vmware-esxi-servers-worldwide/](https://www.bleepingcomputer.com/news/security/massive-esxiargs-ransomware-attack-targets-vmware-esxi-servers-worldwide/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Impact
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4429]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Termination of ESXI Process**

VMware ESXi is a hypervisor used to create and manage virtual machines on a host system. Adversaries may target ESXi processes like "vmware-vmx" to disrupt virtual environments, often using the "kill" command to terminate these processes. The detection rule identifies such terminations by monitoring for specific process events, helping to uncover potential threats to virtualized infrastructures.

**Possible investigation steps**

* Review the alert details to confirm the process name is either "vmware-vmx" or "vmx" and that the parent process is "kill" on a Linux host.
* Check the timeline of events leading up to the termination to identify any preceding suspicious activities or commands executed by the same user or process.
* Investigate the user account associated with the "kill" command to determine if it is authorized to manage VMware processes and if there are any signs of compromise.
* Examine system logs and audit trails for any unauthorized access attempts or anomalies around the time of the process termination.
* Assess the impact on the virtual environment by verifying the status of affected virtual machines and any potential service disruptions.
* Correlate this event with other security alerts or incidents to identify if it is part of a larger attack pattern targeting the virtual infrastructure.

**False positive analysis**

* Routine maintenance or administrative tasks may involve terminating VMware processes using the kill command. To manage this, create exceptions for known maintenance scripts or administrative user accounts that regularly perform these actions.
* Automated scripts or monitoring tools might inadvertently terminate VMware processes as part of their operations. Identify and exclude these tools from the detection rule by specifying their process names or user accounts.
* System updates or patches could lead to the termination of VMware processes as part of the update procedure. Exclude these events by correlating them with known update schedules or specific update-related process names.
* Testing environments where VMware processes are frequently started and stopped for development purposes can trigger false positives. Implement exclusions for these environments by using hostnames or IP addresses associated with test systems.

**Response and remediation**

* Immediately isolate the affected host system from the network to prevent further malicious activity and potential spread to other systems.
* Terminate any unauthorized or suspicious processes that are still running on the affected host, especially those related to VMware ESXi, to halt any ongoing disruption.
* Conduct a forensic analysis of the affected system to identify any additional indicators of compromise or persistence mechanisms that may have been deployed by the threat actor.
* Restore any terminated VMware processes from a known good backup to ensure the virtual environment is returned to its operational state.
* Review and update access controls and permissions on the affected host to ensure that only authorized personnel can execute critical commands like "kill" on VMware processes.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat is part of a larger attack campaign.
* Implement enhanced monitoring and alerting for similar suspicious activities across the virtualized infrastructure to detect and respond to future threats more effectively.


## Setup [_setup_1272]

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


## Rule query [_rule_query_5421]

```js
process where host.os.type == "linux" and event.type == "end" and process.name in ("vmware-vmx", "vmx")
and process.parent.name == "kill"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Service Stop
    * ID: T1489
    * Reference URL: [https://attack.mitre.org/techniques/T1489/](https://attack.mitre.org/techniques/T1489/)



