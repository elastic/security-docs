---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-privilege-escalation-via-container-misconfiguration.html
---

# Potential Privilege Escalation via Container Misconfiguration [potential-privilege-escalation-via-container-misconfiguration]

This rule monitors for the execution of processes that interact with Linux containers through an interactive shell without root permissions. Utilities such as runc and ctr are universal command-line utilities leveraged to interact with containers via root permissions. On systems where the access to these utilities are misconfigured, attackers might be able to create and run a container that mounts the root folder or spawn a privileged container vulnerable to a container escape attack, which might allow them to escalate privileges and gain further access onto the host file system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/runc-privilege-escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/runc-privilege-escalation)
* [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Domain: Container
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_734]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privilege Escalation via Container Misconfiguration**

Containers, managed by tools like runc and ctr, isolate applications for security and efficiency. Misconfigurations can allow attackers to exploit these tools, running containers with elevated privileges or accessing sensitive host resources. The detection rule identifies suspicious use of these utilities by non-root users in interactive sessions, flagging potential privilege escalation attempts.

**Possible investigation steps**

* Review the alert details to identify the specific non-root user and group involved in the suspicious activity, as indicated by the user.Ext.real.id and group.Ext.real.id fields.
* Examine the process tree to understand the parent-child relationship of the processes, focusing on the interactive nature of both the process and its parent, as indicated by process.interactive and process.parent.interactive fields.
* Investigate the command-line arguments used with the runc or ctr utilities, particularly looking for the use of "run" and any potentially dangerous flags like "--privileged" or "--mount" that could indicate an attempt to escalate privileges.
* Check the system logs and audit logs for any additional context around the time of the alert, focusing on any other suspicious activities or anomalies involving the same user or process.
* Assess the configuration and access controls of the container management tools on the host to identify any misconfigurations or vulnerabilities that could have been exploited.

**False positive analysis**

* Non-root users in development environments may frequently use runc or ctr for legitimate container management tasks. To mitigate this, consider creating exceptions for specific user IDs or groups known to perform these actions regularly.
* Automated scripts or CI/CD pipelines might execute container commands interactively without root permissions. Identify these scripts and exclude their associated user accounts or process names from triggering the rule.
* Some system administrators may operate with non-root accounts for security reasons but still require access to container management tools. Document these users and adjust the rule to exclude their activities by user ID or group ID.
* Training or testing environments where users are encouraged to experiment with container configurations might trigger false positives. Implement a separate monitoring policy for these environments to reduce noise in production alerts.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized access or potential lateral movement within the host system.
* Terminate any suspicious container processes identified by the detection rule to halt any ongoing privilege escalation attempts.
* Conduct a thorough review of container configurations and permissions, specifically focusing on the use of runc and ctr utilities, to identify and rectify any misconfigurations that allow non-root users to execute privileged operations.
* Implement strict access controls and enforce the principle of least privilege for container management utilities to ensure only authorized users can execute privileged commands.
* Monitor for any additional signs of compromise or unusual activity on the host system, particularly focusing on processes initiated by non-root users with elevated privileges.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on the broader environment.
* Update and enhance detection capabilities to include additional indicators of compromise related to container misconfigurations and privilege escalation attempts, ensuring timely alerts for similar threats in the future.


## Setup [_setup_469]

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

Session View uses process data collected by the Elastic Defend integration, but this data is not always collected by default. Session View is available on enterprise subscription for versions 8.3 and above.

**To confirm that Session View data is enabled:**

* Go to “Manage → Policies”, and edit one or more of your Elastic Defend integration policies.
* Select the” Policy settings” tab, then scroll down to the “Linux event collection” section near the bottom.
* Check the box for “Process events”, and turn on the “Include session data” toggle.
* If you want to include file and network alerts in Session View, check the boxes for “Network and File events”.
* If you want to enable terminal output capture, turn on the “Capture terminal output” toggle. For more information about the additional fields collected when this setting is enabled and the usage of Session View for Analysis refer to the [helper guide](docs-content://solutions/security/investigate/session-view.md).


## Rule query [_rule_query_781]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  (process.name == "runc" and process.args == "run") or
  (process.name == "ctr" and process.args == "run" and process.args in ("--privileged", "--mount"))
) and not user.Ext.real.id == "0" and not group.Ext.real.id == "0" and
process.interactive == true and process.parent.interactive == true
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Escape to Host
    * ID: T1611
    * Reference URL: [https://attack.mitre.org/techniques/T1611/](https://attack.mitre.org/techniques/T1611/)



