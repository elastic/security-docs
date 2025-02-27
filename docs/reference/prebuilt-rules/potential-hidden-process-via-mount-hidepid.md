---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-hidden-process-via-mount-hidepid.html
---

# Potential Hidden Process via Mount Hidepid [potential-hidden-process-via-mount-hidepid]

Identifies the execution of mount process with hidepid parameter, which can make processes invisible to other users from the system. Adversaries using Linux kernel version 3.2+ (or RHEL/CentOS v6.5+ above) can hide the process from other users. When hidepid=2 option is executed to mount the /proc filesystem, only the root user can see all processes and the logged-in user can only see their own process. This provides a defense evasion mechanism for the adversaries to hide their process executions from all other commands such as ps, top, pgrep and more. With the Linux kernel hardening hidepid option all the user has to do is remount the /proc filesystem with the option, which can now be monitored and detected.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.cyberciti.biz/faq/linux-hide-processes-from-other-users/](https://www.cyberciti.biz/faq/linux-hide-processes-from-other-users/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 110

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_690]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Hidden Process via Mount Hidepid**

The *hidepid* mount option in Linux allows users to restrict visibility of process information in the /proc filesystem, enhancing privacy by limiting process visibility to the owner. Adversaries exploit this by remounting /proc with *hidepid=2*, concealing their processes from non-root users and evading detection tools like ps or top. The detection rule identifies such activity by monitoring for the execution of the mount command with specific arguments, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the alert details to confirm the presence of the *mount* process execution with arguments indicating */proc* and *hidepid=2*.
* Check the user account associated with the process execution to determine if it is a legitimate administrative user or a potential adversary.
* Investigate the parent process of the *mount* command to understand the context and origin of the execution, ensuring it is not part of a known or legitimate administrative script.
* Examine recent login activity and user sessions on the host to identify any unauthorized access or suspicious behavior around the time of the alert.
* Analyze other processes running on the system to identify any hidden or suspicious activities that might be related to the use of *hidepid=2*.
* Review system logs and audit logs for any additional indicators of compromise or related suspicious activities that coincide with the alert.

**False positive analysis**

* System administrators or automated scripts may remount /proc with hidepid=2 for legitimate privacy or security reasons. To handle this, create exceptions for known administrative scripts or users by excluding their specific command lines or user IDs.
* Some security tools or monitoring solutions might use hidepid=2 as part of their normal operation to enhance system security. Identify these tools and exclude their processes from triggering alerts by adding them to an allowlist.
* Cloud environments or containerized applications might use hidepid=2 to isolate processes for multi-tenant security. Review the environment’s standard operating procedures and exclude these known behaviors from detection.
* Regular system updates or maintenance scripts might temporarily use hidepid=2. Document these occurrences and adjust the detection rule to ignore these specific maintenance windows or scripts.
* If using a specific Linux distribution that employs hidepid=2 by default for certain operations, verify these defaults and configure the detection rule to exclude them.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Use root privileges to remount the /proc filesystem without the *hidepid=2* option to restore visibility of all processes.
* Conduct a thorough review of running processes and system logs to identify any unauthorized or suspicious activities that may have been concealed.
* Terminate any identified malicious processes and remove any associated files or scripts from the system.
* Change all system and user passwords to prevent unauthorized access, especially if credential theft is suspected.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and alerting for future attempts to use the *hidepid* option, ensuring rapid detection and response.


## Setup [_setup_439]

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


## Rule query [_rule_query_730]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "executed", "process_started") and
  process.name == "mount" and process.args == "/proc" and process.args == "-o" and process.args : "*hidepid=2*" and
  not process.parent.command_line like "/opt/cloudlinux/*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)



