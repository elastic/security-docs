---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-openssh-backdoor-logging-activity.html
---

# Potential OpenSSH Backdoor Logging Activity [potential-openssh-backdoor-logging-activity]

Identifies a Secure Shell (SSH) client or server process creating or writing to a known SSH backdoor log file. Adversaries may modify SSH related binaries for persistence or credential access via patching sensitive functions to enable unauthorized access or to log SSH credentials for exfiltration.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.file-*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/eset/malware-ioc/tree/master/sshdoor](https://github.com/eset/malware-ioc/tree/master/sshdoor)
* [https://www.welivesecurity.com/wp-content/uploads/2021/01/ESET_Kobalos.pdf](https://www.welivesecurity.com/wp-content/uploads/2021/01/ESET_Kobalos.pdf)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Credential Access
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_718]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential OpenSSH Backdoor Logging Activity**

OpenSSH is a widely used protocol for secure remote administration and file transfers. Adversaries may exploit OpenSSH by modifying its binaries to log credentials or maintain unauthorized access. The detection rule identifies suspicious file changes linked to SSH processes, focusing on unusual file names, extensions, and paths indicative of backdoor activity, thus helping to uncover potential security breaches.

**Possible investigation steps**

* Review the file change event details to identify the specific file name, extension, and path involved in the alert. Pay particular attention to unusual file names or extensions and paths listed in the query, such as "/usr/lib/**.so.**" or "/private/etc/ssh/.sshd_auth".
* Examine the process executable that triggered the alert, either "/usr/sbin/sshd" or "/usr/bin/ssh", to determine if it has been modified or replaced. Check the integrity of these binaries using hash comparisons against known good versions.
* Investigate the user account associated with the process that made the file change. Determine if the account has a history of suspicious activity or if it has been compromised.
* Check for any recent or unusual login attempts or sessions related to the SSH service on the host. Look for patterns that might indicate unauthorized access or credential harvesting.
* Analyze system logs, such as auth.log or secure.log, for any anomalies or entries that coincide with the time of the file change event. This can provide additional context or evidence of malicious activity.
* If a backdoor is suspected, consider isolating the affected system from the network to prevent further unauthorized access and begin remediation efforts, such as restoring from a clean backup or reinstalling the affected services.

**False positive analysis**

* Routine system updates or package installations may trigger file changes in SSH-related directories. Users can create exceptions for known update processes to prevent false alerts.
* Custom scripts or administrative tasks that modify SSH configuration files for legitimate purposes might be flagged. Users should whitelist these scripts or processes if they are verified as non-malicious.
* Backup or synchronization tools that create temporary files with unusual extensions or names in SSH directories can cause false positives. Exclude these tools from monitoring if they are part of regular operations.
* Development or testing environments where SSH binaries are frequently modified for testing purposes may generate alerts. Implement exclusions for these environments to reduce noise.
* Automated configuration management tools like Ansible or Puppet that modify SSH settings as part of their operations can be excluded if they are part of authorized workflows.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious SSH processes identified in the alert to halt potential backdoor activity.
* Conduct a thorough review of the modified files and binaries, particularly those listed in the query, to assess the extent of the compromise and identify any malicious code or unauthorized changes.
* Restore affected files and binaries from a known good backup to ensure system integrity and remove any backdoor modifications.
* Change all SSH credentials and keys associated with the compromised system to prevent unauthorized access using potentially logged credentials.
* Implement additional monitoring on the affected system and network for any signs of persistence or further malicious activity, focusing on the paths and file types highlighted in the detection query.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected, ensuring a coordinated response to the threat.


## Setup [_setup_456]

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

**Custom Ingest Pipeline**

For versions <8.2, you need to add a custom ingest pipeline to populate `event.ingested` with @timestamp for non-elastic-agent indexes, like auditbeats/filebeat/winlogbeat etc. For more details to add a custom ingest pipeline refer to the [guide](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md).


## Rule query [_rule_query_764]

```js
file where host.os.type == "linux" and event.type == "change" and process.executable : ("/usr/sbin/sshd", "/usr/bin/ssh") and
  (
    (file.name : (".*", "~*", "*~") and not file.name : (".cache", ".viminfo", ".bash_history", ".google_authenticator",
      ".jelenv", ".csvignore", ".rtreport")) or
    file.extension : ("in", "out", "ini", "h", "gz", "so", "sock", "sync", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9") or
    file.path :
    (
      "/private/etc/*--",
      "/usr/share/*",
      "/usr/include/*",
      "/usr/local/include/*",
      "/private/tmp/*",
      "/private/var/tmp/*",
      "/usr/tmp/*",
      "/usr/share/man/*",
      "/usr/local/share/*",
      "/usr/lib/*.so.*",
      "/private/etc/ssh/.sshd_auth",
      "/usr/bin/ssd",
      "/private/var/opt/power",
      "/private/etc/ssh/ssh_known_hosts",
      "/private/var/html/lol",
      "/private/var/log/utmp",
      "/private/var/lib",
      "/var/run/sshd/sshd.pid",
      "/var/run/nscd/ns.pid",
      "/var/run/udev/ud.pid",
      "/var/run/udevd.pid"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Compromise Host Software Binary
    * ID: T1554
    * Reference URL: [https://attack.mitre.org/techniques/T1554/](https://attack.mitre.org/techniques/T1554/)



