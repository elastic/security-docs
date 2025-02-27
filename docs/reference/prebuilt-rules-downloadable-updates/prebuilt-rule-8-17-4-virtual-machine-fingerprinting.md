---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-virtual-machine-fingerprinting.html
---

# Virtual Machine Fingerprinting [prebuilt-rule-8-17-4-virtual-machine-fingerprinting]

An adversary may attempt to get detailed information about the operating system and hardware. This rule identifies common locations used to discover virtual machine hardware by a non-root user. This technique has been used by the Pupy RAT and other malware.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4384]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Virtual Machine Fingerprinting**

Virtual Machine Fingerprinting involves identifying characteristics of a virtual environment, often to tailor attacks or evade detection. Adversaries exploit this by querying system files for hardware details, a tactic seen in malware like Pupy RAT. The detection rule flags non-root users accessing specific Linux paths indicative of VM queries, signaling potential reconnaissance activities.

**Possible investigation steps**

* Review the process execution details to identify the non-root user involved in accessing the specified paths, focusing on the user.name field.
* Examine the process.args field to determine which specific file paths were accessed, as this can indicate the type of virtual machine information being targeted.
* Investigate the parent process and command line arguments to understand the context of the process initiation and whether it aligns with legitimate user activity.
* Check for any related alerts or logs around the same timeframe to identify potential patterns or repeated attempts at virtual machine fingerprinting.
* Assess the system for any signs of compromise or unauthorized access, particularly focusing on the presence of known malware like Pupy RAT or similar threats.
* Correlate the findings with MITRE ATT&CK framework references (TA0007, T1082) to understand the broader tactics and techniques potentially in use by the adversary.

**False positive analysis**

* Non-root users running legitimate scripts or applications that query system files for hardware information may trigger the rule. Review the context of the process and user activity to determine if it aligns with expected behavior.
* System administrators or developers using automated tools for inventory or monitoring purposes might access these paths. Consider creating exceptions for known tools or scripts that are verified as safe.
* Security or compliance audits conducted by non-root users could inadvertently match the rule’s criteria. Document and whitelist these activities if they are part of regular operations.
* Development environments where virtual machine detection is part of testing processes may cause false positives. Identify and exclude these environments from the rule’s scope if they are consistently flagged.
* Regularly review and update the list of exceptions to ensure that only verified and necessary exclusions are maintained, minimizing the risk of overlooking genuine threats.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further reconnaissance or potential lateral movement by the adversary.
* Terminate any suspicious processes identified in the alert that are attempting to access the specified system files, especially those not initiated by the root user.
* Conduct a thorough review of recent user activity and process logs to identify any unauthorized access or anomalies that may indicate further compromise.
* Reset credentials for any non-root users involved in the alert to prevent unauthorized access, and review user permissions to ensure least privilege principles are enforced.
* Deploy endpoint detection and response (EDR) tools to monitor for similar suspicious activities and enhance visibility into system processes and user actions.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement additional monitoring and alerting for the specific file paths and processes identified in the query to detect and respond to future attempts at virtual machine fingerprinting.


## Setup [_setup_1229]

**Setup**

This rule requires data coming in from one of the following integrations: - Elastic Defend - Auditbeat

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

**Auditbeat Setup**

Auditbeat is a lightweight shipper that you can install on your servers to audit the activities of users and processes on your systems. For example, you can use Auditbeat to collect and centralize audit events from the Linux Audit Framework. You can also use Auditbeat to detect changes to critical files, like binaries and configuration files, and identify potential security policy violations.

**The following steps should be executed in order to add the Auditbeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://docs/reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://docs/reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://docs/reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://docs/reference/auditbeat/setting-up-running.md).


## Rule query [_rule_query_5376]

```js
event.category:process and host.os.type:linux and event.type:(start or process_started) and
  process.args:("/sys/class/dmi/id/bios_version" or
                "/sys/class/dmi/id/product_name" or
                "/sys/class/dmi/id/chassis_vendor" or
                "/proc/scsi/scsi" or
                "/proc/ide/hd0/model") and
  not user.name:root
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



