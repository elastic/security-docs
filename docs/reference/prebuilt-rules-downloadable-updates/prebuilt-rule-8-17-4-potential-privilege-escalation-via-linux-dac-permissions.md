---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-privilege-escalation-via-linux-dac-permissions.html
---

# Potential Privilege Escalation via Linux DAC permissions [prebuilt-rule-8-17-4-potential-privilege-escalation-via-linux-dac-permissions]

Identifies potential privilege escalation exploitation of DAC (Discretionary access control) file permissions. The rule identifies exploitation of DAC checks on sensitive file paths via suspicious processes whose capabilities include CAP_DAC_OVERRIDE (where a process can bypass all read write and execution checks) or CAP_DAC_READ_SEARCH (where a process can read any file or perform any executable permission on the directories).

**Rule type**: new_terms

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

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4514]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privilege Escalation via Linux DAC permissions**

Linux Discretionary Access Control (DAC) allows file owners to set permissions, potentially leading to privilege escalation if misconfigured. Adversaries exploit DAC by using processes with capabilities like CAP_DAC_OVERRIDE to bypass permission checks. The detection rule identifies suspicious processes accessing sensitive files, excluding benign activities, to flag potential misuse of DAC permissions.

**Possible investigation steps**

* Review the process command line to identify the specific command executed and determine if it involves sensitive files like sudoers, passwd, shadow, or directories under /root/.
* Check the user ID associated with the process to verify if it is a non-root user attempting to access or modify sensitive files.
* Investigate the process name and executable path to ensure it is not part of the excluded benign processes or paths, such as tar, getent, or /usr/lib/**/lxc/rootfs/**.
* Analyze the parent process name to determine if it is a known benign parent like dpkg or gnome-shell, which might indicate a legitimate operation.
* Examine the process thread capabilities, specifically CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH, to understand the level of access the process has and assess if it aligns with expected behavior for the user or application.
* Correlate the event with other logs or alerts to identify any patterns or sequences of activities that might indicate a broader attack or misconfiguration issue.

**False positive analysis**

* Processes like "tar", "getent", "su", and others listed in the rule are known to perform legitimate operations on sensitive files. Exclude these processes from triggering alerts by adding them to the exception list in the detection rule.
* System management tools such as "dpkg" and "podman" may access sensitive files during routine operations. Consider excluding these tools if they are part of regular system maintenance activities.
* Processes running under user ID "0" (root) are often legitimate and necessary for system operations. Ensure that these are excluded from alerts to avoid unnecessary noise.
* Executables located in paths like /usr/lib/**/lxc/rootfs/** are typically part of containerized environments and may not pose a threat. Exclude these paths if they are part of your standard infrastructure.
* Parent processes such as "java" or those with names ending in "postinst" may be involved in legitimate software installations or updates. Review and exclude these if they are part of expected system behavior.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule, especially those with CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH capabilities accessing sensitive files.
* Conduct a thorough review of the affected system’s user accounts and permissions to identify and revoke any unauthorized privilege escalations.
* Restore any modified or compromised sensitive files, such as /etc/passwd or /etc/shadow, from a known good backup.
* Implement additional monitoring on the affected system to detect any further attempts at privilege escalation or unauthorized access.
* Escalate the incident to the security operations team for a comprehensive investigation to determine the root cause and potential impact.
* Apply security patches and updates to the affected system to mitigate any known vulnerabilities that could be exploited for privilege escalation.


## Setup [_setup_1347]

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


## Rule query [_rule_query_5506]

```js
event.category:process and host.os.type:linux and event.type:start and event.action:exec and
(process.thread.capabilities.permitted:CAP_DAC_* or process.thread.capabilities.effective: CAP_DAC_*) and
process.command_line:(*sudoers* or *passwd* or *shadow* or */root/.ssh*) and not (
  user.id : "0" or
  process.name : (
    "tar" or "getent" or "su" or "stat" or "dirname" or "chown" or "sudo" or "dpkg-split" or "dpkg-deb" or "dpkg" or
    "podman" or "awk" or "passwd" or "dpkg-maintscript-helper" or "mutt_dotlock" or "nscd" or "logger" or "gpasswd"
  ) or
  process.executable : /usr/lib/*/lxc/rootfs/* or
  process.parent.name : (
    "dpkg" or "java" or *postinst or "dpkg-preconfigure" or "gnome-shell"
  )
)
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



