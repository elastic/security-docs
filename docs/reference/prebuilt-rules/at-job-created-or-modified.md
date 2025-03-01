---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/at-job-created-or-modified.html
---

# At Job Created or Modified [at-job-created-or-modified]

This rule monitors for at jobs being created or renamed. Linux at jobs are scheduled tasks that can be leveraged by system administrators to set up scheduled tasks, but may be abused by malicious actors for persistence, privilege escalation and command execution. By creating or modifying cron job configurations, attackers can execute malicious commands or scripts at predefined intervals, ensuring their continued presence and enabling unauthorized activities.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Privilege Escalation
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_140]

**Triage and analysis**

[TBC: QUOTE]
**Investigating At Job Created or Modified**

The *at* command in Linux schedules tasks for future execution, aiding system admins in automating routine jobs. However, attackers can exploit this for persistence, privilege escalation, or executing unauthorized commands. The detection rule identifies suspicious *at* job creations or modifications by monitoring specific file paths and excluding benign processes, helping to flag potential malicious activities.

**Possible investigation steps**

* Review the file path of the created or modified *at* job to confirm it is within the monitored directory: /var/spool/cron/atjobs/*. Determine if the file path is expected or unusual for the system’s typical operations.
* Identify the process that triggered the alert by examining the process.executable field. Check if the process is known and expected in the context of the system’s normal operations.
* Investigate the user account associated with the process that created or modified the *at* job. Determine if the account has legitimate reasons to schedule tasks or if it might be compromised.
* Check the contents of the *at* job file to understand the commands or scripts scheduled for execution. Look for any suspicious or unauthorized commands that could indicate malicious intent.
* Correlate the event with other recent alerts or logs from the same host to identify any patterns or additional indicators of compromise, such as privilege escalation attempts or unauthorized access.
* Verify if there are any known vulnerabilities or exploits associated with the processes or commands involved in the alert, which could provide further context on the potential threat.

**False positive analysis**

* System package managers like dpkg, rpm, and yum can trigger false positives when they create or modify at jobs during software installations or updates. To manage this, ensure these processes are included in the exclusion list within the detection rule.
* Automated system management tools such as Puppet and Chef may also create or modify at jobs as part of their routine operations. Add these tools to the exclusion list to prevent unnecessary alerts.
* Temporary files with extensions like swp or dpkg-remove can be mistakenly flagged. Exclude these file extensions from the rule to reduce false positives.
* Processes running from directories like /nix/store or /snap can be benign and should be considered for exclusion if they are part of regular system operations.
* If the process executable is null, it might indicate a benign system process that lacks a defined executable path. Consider reviewing these cases to determine if they are legitimate and adjust the rule accordingly.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or execution of malicious tasks.
* Terminate any suspicious processes associated with the creation or modification of *at* jobs that are not part of the excluded benign processes.
* Review and remove any unauthorized *at* jobs found in the /var/spool/cron/atjobs/ directory to eliminate persistence mechanisms.
* Conduct a thorough examination of the system for additional indicators of compromise, such as unauthorized user accounts or unexpected network connections.
* Restore the system from a known good backup if malicious activity is confirmed and cannot be fully remediated.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for *at* job activities to detect similar threats in the future, ensuring that alerts are promptly reviewed and acted upon.


## Setup [_setup_80]

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


## Rule query [_rule_query_143]

```js
file where host.os.type == "linux" and
event.action in ("rename", "creation") and file.path : "/var/spool/cron/atjobs/*" and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/local/bin/dockerd"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : ("/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*") or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: At
    * ID: T1053.002
    * Reference URL: [https://attack.mitre.org/techniques/T1053/002/](https://attack.mitre.org/techniques/T1053/002/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: At
    * ID: T1053.002
    * Reference URL: [https://attack.mitre.org/techniques/T1053/002/](https://attack.mitre.org/techniques/T1053/002/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: At
    * ID: T1053.002
    * Reference URL: [https://attack.mitre.org/techniques/T1053/002/](https://attack.mitre.org/techniques/T1053/002/)



