---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-disabling-of-selinux.html
---

# Potential Disabling of SELinux [prebuilt-rule-8-17-4-potential-disabling-of-selinux]

Identifies potential attempts to disable Security-Enhanced Linux (SELinux), which is a Linux kernel security feature to support access control policies. Adversaries may disable security tools to avoid possible detection of their tools and activities.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

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
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4338]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Disabling of SELinux**

SELinux is a critical security feature in Linux environments, enforcing access control policies to protect against unauthorized access. Adversaries may attempt to disable SELinux to evade detection and carry out malicious activities undetected. The detection rule identifies such attempts by monitoring for the execution of the *setenforce 0* command, which switches SELinux to permissive mode, effectively disabling its enforcement capabilities. This rule leverages process monitoring to alert security teams of potential defense evasion tactics.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the *setenforce 0* command, ensuring that the process name is *setenforce* and the argument is *0*.
* Check the user account associated with the process execution to determine if it is a legitimate administrative user or a potential compromised account.
* Investigate the timeline of events leading up to and following the execution of the *setenforce 0* command to identify any related suspicious activities or processes.
* Examine system logs and audit logs for any other unusual or unauthorized changes to SELinux settings or other security configurations.
* Assess the system for any signs of compromise or malicious activity, such as unexpected network connections, file modifications, or the presence of known malware indicators.
* Verify the current SELinux status and configuration to ensure it has been restored to enforcing mode if it was indeed set to permissive mode.

**False positive analysis**

* System administrators may execute the *setenforce 0* command during routine maintenance or troubleshooting, leading to false positives. To manage this, create exceptions for known maintenance windows or specific administrator accounts.
* Some automated scripts or configuration management tools might temporarily set SELinux to permissive mode for deployment purposes. Identify these scripts and exclude their execution context from triggering alerts.
* Development environments might require SELinux to be set to permissive mode for testing purposes. Consider excluding specific development hosts or environments from the rule to prevent unnecessary alerts.
* In certain cases, SELinux might be disabled as part of a controlled security audit or penetration test. Coordinate with security teams to whitelist these activities during the audit period.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Verify the current SELinux status on the affected system using the command `sestatus` to confirm if it has been switched to permissive mode.
* If SELinux is in permissive mode, re-enable it by executing `setenforce 1` and ensure that the SELinux policy is correctly enforced.
* Conduct a thorough review of system logs and process execution history to identify any unauthorized changes or suspicious activities that occurred while SELinux was disabled.
* Scan the affected system for malware or unauthorized software installations using a trusted antivirus or endpoint detection and response (EDR) tool.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Implement additional monitoring and alerting for similar SELinux-related events to enhance detection capabilities and prevent recurrence.


## Setup [_setup_1186]

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
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://reference/auditbeat/setting-up-running.md).


## Rule query [_rule_query_5330]

```js
process where host.os.type == "linux" and event.type == "start" and
 event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
 process.name == "setenforce" and process.args == "0"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



