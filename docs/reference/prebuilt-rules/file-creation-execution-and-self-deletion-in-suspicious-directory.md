---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/file-creation-execution-and-self-deletion-in-suspicious-directory.html
---

# File Creation, Execution and Self-Deletion in Suspicious Directory [file-creation-execution-and-self-deletion-in-suspicious-directory]

This rule monitors for the creation of a file, followed by its execution and self-deletion in a short timespan within a directory often used for malicious purposes by threat actors. This behavior is often used by malware to execute malicious code and delete itself to hide its tracks.

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
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_331]

**Triage and analysis**

[TBC: QUOTE]
**Investigating File Creation, Execution and Self-Deletion in Suspicious Directory**

In Linux environments, temporary directories like `/tmp` and `/var/tmp` are often used for storing transient files. Adversaries exploit these directories to execute malicious payloads and erase traces by creating, running, and deleting files swiftly. The detection rule identifies this pattern by monitoring file creation, execution, and deletion events within these directories, flagging suspicious activities that align with common malware behaviors.

**Possible investigation steps**

* Review the file creation event details, focusing on the file path and name to determine if it matches known malicious patterns or if it is a legitimate file.
* Examine the process execution event, paying attention to the process name and parent process name to identify if the execution was initiated by a suspicious or unauthorized shell.
* Investigate the user.id and host.id associated with the events to determine if the activity aligns with expected user behavior or if it indicates potential compromise.
* Check for any network activity or connections initiated by the process to identify potential data exfiltration or communication with command and control servers.
* Analyze the deletion event to confirm whether the file was removed by a legitimate process or if it was part of a self-deletion mechanism used by malware.
* Correlate these events with any other alerts or logs from the same host or user to identify patterns or additional indicators of compromise.

**False positive analysis**

* Development and testing activities in temporary directories can trigger false positives. Exclude specific paths or processes related to known development tools or scripts that frequently create, execute, and delete files in these directories.
* Automated system maintenance scripts may perform similar actions. Identify and whitelist these scripts by their process names or paths to prevent unnecessary alerts.
* Backup or deployment tools like Veeam or Spack may use temporary directories for legitimate operations. Add exceptions for these tools by specifying their executable paths or process names.
* Temporary file operations by legitimate applications such as web servers or database services might be flagged. Monitor and exclude these applications by their known behaviors or specific file paths they use.
* Regular system updates or package installations can involve temporary file handling. Recognize and exclude these activities by identifying the associated package manager processes or update scripts.

**Response and remediation**

* Isolate the affected host immediately to prevent further spread of the potential malware. Disconnect it from the network to contain the threat.
* Terminate any suspicious processes identified in the alert, especially those executed from temporary directories, to stop any ongoing malicious activity.
* Conduct a thorough examination of the affected directories (/tmp, /var/tmp, etc.) to identify and remove any remaining malicious files or scripts.
* Restore any affected systems from a known good backup to ensure that no remnants of the malware remain.
* Update and patch the affected system to close any vulnerabilities that may have been exploited by the threat actor.
* Enhance monitoring and logging on the affected host and similar systems to detect any recurrence of this behavior, focusing on file creation, execution, and deletion events in temporary directories.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems may be compromised.


## Setup [_setup_206]

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


## Rule query [_rule_query_350]

```js
sequence by host.id, user.id with maxspan=1m
  [file where host.os.type == "linux" and event.action == "creation" and
   process.name in ("curl", "wget", "fetch", "ftp", "sftp", "scp", "rsync", "ld") and
   file.path : ("/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*",
     "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*")] by file.name
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
   not process.parent.executable like (
     "/tmp/VeeamApp*", "/tmp/rajh/spack-stage/*", "plz-out/bin/vault/bridge/test/e2e/base/bridge-dev",
     "/usr/bin/ranlib", "/usr/bin/ar", "plz-out/bin/vault/bridge/test/e2e/base/local-k8s"
   )] by process.name
  [file where host.os.type == "linux" and event.action == "deletion" and
   file.path : (
     "/dev/shm/*", "/run/shm/*", "/tmp/*", "/var/tmp/*", "/run/*", "/var/run/*", "/var/www/*", "/proc/*/fd/*"
    ) and not process.name in ("rm", "ld", "conftest", "link", "gcc", "getarch", "ld")] by file.name
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



