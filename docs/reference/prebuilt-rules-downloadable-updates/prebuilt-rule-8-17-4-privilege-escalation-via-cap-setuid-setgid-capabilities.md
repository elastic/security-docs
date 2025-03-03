---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-privilege-escalation-via-cap-setuid-setgid-capabilities.html
---

# Privilege Escalation via CAP_SETUID/SETGID Capabilities [prebuilt-rule-8-17-4-privilege-escalation-via-cap-setuid-setgid-capabilities]

Identifies instances where a process (granted CAP_SETUID and/or CAP_SETGID capabilities) is executed, after which the user’s access is elevated to UID/GID 0 (root). In Linux, the CAP_SETUID and CAP_SETGID capabilities allow a process to change its UID and GID, respectively, providing control over user and group identity management. Attackers may leverage a misconfiguration for exploitation in order to escalate their privileges to root.

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
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4540]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Privilege Escalation via CAP_SETUID/SETGID Capabilities**

In Linux, CAP_SETUID and CAP_SETGID capabilities allow processes to change user and group IDs, crucial for identity management. Adversaries exploit misconfigurations to gain root access. The detection rule identifies processes with these capabilities that elevate privileges to root, excluding benign scenarios, to flag potential misuse.

**Possible investigation steps**

* Review the process details such as process.name and process.executable to identify the specific application or script that triggered the alert. This can help determine if the process is expected or potentially malicious.
* Examine the process.parent.executable and process.parent.name fields to understand the parent process that initiated the suspicious process. This can provide context on whether the parent process is legitimate or part of a known attack vector.
* Check the user.id field to confirm the user context under which the process was executed. If the user is not expected to have elevated privileges, this could indicate a potential compromise.
* Investigate the process.command_line to analyze the command executed. Look for any unusual or unexpected command patterns that could suggest malicious intent.
* Correlate the alert with other security events or logs from the same host.id to identify any related suspicious activities or patterns that could indicate a broader attack.
* Assess the environment for any recent changes or misconfigurations that could have inadvertently granted CAP_SETUID or CAP_SETGID capabilities to unauthorized processes.

**False positive analysis**

* Processes related to system management tools like VMware, SolarWinds, and language tools may trigger false positives. Exclude these by adding their executables to the exception list.
* Scheduled tasks or system updates that involve processes like update-notifier or dbus-daemon can cause false alerts. Consider excluding these parent process names from the detection rule.
* Automation tools such as Ansible or scripts executed by Python may inadvertently match the rule. Exclude command lines that match known automation patterns.
* Legitimate use of sudo or pkexec for administrative tasks can be misinterpreted as privilege escalation. Exclude these executables if they are part of regular administrative operations.
* Monitoring tools like osqueryd or saposcol might trigger the rule during normal operations. Add these process names to the exception list to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified with CAP_SETUID or CAP_SETGID capabilities that have escalated privileges to root, ensuring no further exploitation occurs.
* Conduct a thorough review of the affected system’s user and group configurations to identify and correct any misconfigurations that allowed the privilege escalation.
* Revoke unnecessary CAP_SETUID and CAP_SETGID capabilities from processes and users that do not require them, reducing the attack surface for future exploitation.
* Restore the affected system from a known good backup if unauthorized changes or persistent threats are detected, ensuring the system is returned to a secure state.
* Monitor the system and network for any signs of continued or attempted exploitation, using enhanced logging and alerting to detect similar threats in the future.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_1372]

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


## Rule query [_rule_query_5532]

```js
sequence by host.id, process.entity_id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name != null and
   (process.thread.capabilities.effective : "CAP_SET?ID" or process.thread.capabilities.permitted : "CAP_SET?ID") and
   user.id != "0" and not (
     process.parent.executable : ("/tmp/newroot/*", "/opt/carbonblack*") or
     process.parent.executable in (
       "/opt/SolarWinds/Agent/bin/Plugins/JobEngine/SolarWinds.Agent.JobEngine.Plugin", "/usr/bin/vmware-toolbox-cmd",
       "/usr/bin/dbus-daemon", "/usr/bin/update-notifier", "/usr/share/language-tools/language-options",
       "/opt/SolarWinds/Agent/*", "/usr/local/sbin/lynis.sh"
     ) or
     process.executable : ("/opt/dynatrace/*", "/tmp/newroot/*", "/opt/SolarWinds/Agent/*") or
     process.executable in (
       "/bin/fgrep", "/usr/bin/sudo", "/usr/bin/pkexec", "/usr/lib/cockpit/cockpit-session", "/usr/sbin/suexec"
     ) or
     process.parent.name in ("update-notifier", "language-options", "osqueryd", "saposcol", "dbus-daemon", "osqueryi", "sdbrun") or
     process.command_line like ("sudo*BECOME-SUCCESS*", "/bin/sh*sapsysinfo.sh*", "sudo su", "sudo su -") or
     process.name in ("sudo", "fgrep", "lsb_release", "apt-update", "dbus-daemon-launch-helper", "man") or
     process.parent.command_line like "/usr/bin/python*ansible*"
   )]
  [process where host.os.type == "linux" and event.action == "uid_change" and event.type == "change" and
   (process.thread.capabilities.effective : "CAP_SET?ID" or process.thread.capabilities.permitted : "CAP_SET?ID")
   and user.id == "0"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Setuid and Setgid
    * ID: T1548.001
    * Reference URL: [https://attack.mitre.org/techniques/T1548/001/](https://attack.mitre.org/techniques/T1548/001/)



