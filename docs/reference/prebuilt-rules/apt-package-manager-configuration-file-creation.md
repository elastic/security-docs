---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/apt-package-manager-configuration-file-creation.html
---

# APT Package Manager Configuration File Creation [apt-package-manager-configuration-file-creation]

Detects file creation events in the configuration directory for the APT package manager. In Linux, APT (Advanced Package Tool) is a command-line utility used for handling packages on (by default) Debian-based systems, providing functions for installing, updating, upgrading, and removing software along with managing package repositories. Attackers can backdoor APT to gain persistence by injecting malicious code into scripts that APT runs, thereby ensuring continued unauthorized access or control each time APT is used for package management.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://packetstormsecurity.com/files/152668/APT-Package-Manager-Persistence.html](https://packetstormsecurity.com/files/152668/APT-Package-Manager-Persistence.md)
* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3]

**Triage and analysis**

[TBC: QUOTE]
**Investigating APT Package Manager Configuration File Creation**

APT is a crucial tool for managing software on Debian-based Linux systems, handling tasks like installation and updates. Adversaries may exploit APT by inserting malicious scripts into its configuration files, ensuring persistent access. The detection rule monitors for unauthorized file creation or renaming in APT’s configuration directory, excluding legitimate processes, to identify potential tampering.

**Possible investigation steps**

* Review the file creation or renaming event details, focusing on the file path to confirm it is within the APT configuration directory (/etc/apt/apt.conf.d/).
* Identify the process responsible for the file creation or renaming by examining the process.executable field, ensuring it is not one of the legitimate processes listed in the query.
* Investigate the origin and purpose of the newly created or renamed file by checking its contents for any suspicious or unauthorized scripts or configurations.
* Correlate the event with recent system activity to determine if there are any other related alerts or anomalies, such as unusual user logins or network connections, that could indicate a broader attack.
* Check the file’s metadata, such as timestamps and ownership, to identify any discrepancies or signs of tampering that could suggest malicious activity.
* If the process responsible for the event is unknown or suspicious, conduct a deeper analysis of the process, including its parent process, command-line arguments, and any associated network activity.

**False positive analysis**

* Legitimate package management operations by system tools like dpkg or apt-get can trigger alerts. To manage this, ensure these processes are included in the exclusion list within the detection rule.
* Temporary files created during package updates or installations, such as those with extensions like swp or dpkg-new, may cause false positives. Exclude these file extensions from triggering alerts.
* Automated system maintenance scripts or tools like puppet or chef-client might modify APT configuration files as part of their normal operations. Add these processes to the exclusion list to prevent unnecessary alerts.
* Custom scripts or administrative tasks that involve renaming or creating files in the APT configuration directory should be reviewed. If deemed safe, add these specific scripts or processes to the exclusion criteria.
* Processes running from directories like /nix/store or /var/lib/dpkg may be part of legitimate system operations. Consider excluding these paths if they are verified as non-threatening.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or potential lateral movement by the adversary.
* Conduct a thorough review of the newly created or renamed files in the /etc/apt/apt.conf.d/ directory to identify any malicious scripts or unauthorized changes.
* Remove any identified malicious files or scripts from the APT configuration directory to eliminate the persistence mechanism.
* Restore any legitimate configuration files from a known good backup to ensure the integrity of the APT configuration.
* Perform a comprehensive scan of the system using updated antivirus or endpoint detection tools to identify and remove any additional malware or unauthorized changes.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for the APT configuration directory and related processes to detect similar threats in the future.


## Setup [_setup]

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


## Rule query [_rule_query_3]

```js
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path : "/etc/apt/apt.conf.d/*" and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/netplan/generate",
    "/usr/local/bin/apt-get", "/usr/bin/apt-get"
  ) or
  file.path :("/etc/apt/apt.conf.d/*.tmp*") or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/*", "/usr/libexec/*",
    "/etc/kernel/*"
  ) or
  process.executable == null or
  process.name in ("pveupdate", "perl", "executor", "crio", "docker-init", "dockerd", "pvedaemon") or
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

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Installer Packages
    * ID: T1546.016
    * Reference URL: [https://attack.mitre.org/techniques/T1546/016/](https://attack.mitre.org/techniques/T1546/016/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



