---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/systemd-generator-created.html
---

# Systemd Generator Created [systemd-generator-created]

This rule detects the creation of a systemd generator file. Generators are small executables executed by systemd at bootup and during configuration reloads. Their main role is to convert non-native configuration and execution parameters into dynamically generated unit files, symlinks, or drop-ins, extending the unit file hierarchy for the service manager. Systemd generators can be used to execute arbitrary code at boot time, which can be leveraged by attackers to maintain persistence on a Linux system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://pberba.github.io/security/2022/02/07/linux-threat-hunting-for-persistence-systemd-generators/](https://pberba.github.io/security/2022/02/07/linux-threat-hunting-for-persistence-systemd-generators/)
* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1064]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Systemd Generator Created**

Systemd generators are scripts that systemd runs at boot or during configuration reloads to convert non-native configurations into unit files. Adversaries can exploit this by creating malicious generators to execute arbitrary code, ensuring persistence or escalating privileges. The detection rule identifies suspicious generator file creations or renames, excluding benign processes and file types, to flag potential abuse.

**Possible investigation steps**

* Review the file path where the generator was created or renamed to determine if it is located in a standard systemd generator directory, such as /run/systemd/system-generators/ or /etc/systemd/user-generators/.
* Identify the process that created or renamed the generator file by examining the process.executable field, and determine if it is a known benign process or potentially malicious.
* Check the file extension and original extension fields to ensure the file is not a temporary or expected system file, such as those with extensions like "swp" or "dpkg-new".
* Investigate the history and behavior of the process that created the generator file, including any associated network connections or file modifications, to assess if it exhibits signs of malicious activity.
* Correlate the event with other security alerts or logs from the same host to identify any patterns or additional indicators of compromise that might suggest persistence or privilege escalation attempts.

**False positive analysis**

* Package managers like dpkg, rpm, and yum can trigger false positives when they create or rename files in systemd generator directories during software installations or updates. To handle these, exclude processes associated with these package managers as specified in the rule.
* Automated system management tools such as Puppet and Chef may also create or modify generator files as part of their configuration management tasks. Exclude these processes by adding them to the exception list if they are part of your environment.
* Temporary files with extensions like swp, swpx, and swx, often created by text editors, can be mistakenly flagged. Ensure these extensions are included in the exclusion list to prevent unnecessary alerts.
* System updates or maintenance scripts that run as part of regular operations might create or modify generator files. Identify these scripts and add their executables to the exclusion list to reduce false positives.
* Custom scripts or tools that are part of legitimate administrative tasks may also trigger alerts. Review these scripts and consider excluding their executables if they are verified as non-malicious.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further execution of potentially malicious code and lateral movement.
* Terminate any suspicious processes associated with the creation or modification of systemd generator files to halt any ongoing malicious activity.
* Conduct a thorough review of the systemd generator directories to identify and remove any unauthorized or suspicious generator files.
* Restore any modified or deleted legitimate systemd generator files from a known good backup to ensure system integrity.
* Implement file integrity monitoring on systemd generator directories to detect unauthorized changes in the future.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Review and update access controls and permissions for systemd generator directories to limit the ability to create or modify files to authorized users only.


## Setup [_setup_670]

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


## Rule query [_rule_query_1119]

```js
file where host.os.type == "linux" and event.action in ("rename", "creation") and file.path : (
"/run/systemd/system-generators/*", "/etc/systemd/system-generators/*",
"/usr/local/lib/systemd/system-generators/*", "/lib/systemd/system-generators/*",
"/usr/lib/systemd/system-generators/*", "/etc/systemd/user-generators/*",
"/usr/local/lib/systemd/user-generators/*", "/usr/lib/systemd/user-generators/*",
"/lib/systemd/user-generators/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client", "/usr/sbin/sshd",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/platform-python"
  ) or
  process.name like~ ("ssm-agent-worker", "crio", "docker-init", "systemd", "pacman", "python*", "platform-python*") or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable == null
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Systemd Service
    * ID: T1543.002
    * Reference URL: [https://attack.mitre.org/techniques/T1543/002/](https://attack.mitre.org/techniques/T1543/002/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Systemd Service
    * ID: T1543.002
    * Reference URL: [https://attack.mitre.org/techniques/T1543/002/](https://attack.mitre.org/techniques/T1543/002/)



