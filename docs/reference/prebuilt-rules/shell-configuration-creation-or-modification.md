---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/shell-configuration-creation-or-modification.html
---

# Shell Configuration Creation or Modification [shell-configuration-creation-or-modification]

This rule monitors the creation/alteration of a shell configuration file. Unix systems use shell configuration files to set environment variables, create aliases, and customize the user’s environment. Adversaries may modify or add a shell configuration file to execute malicious code and gain persistence in the system. This behavior is consistent with the Kaiji malware family.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://intezer.com/blog/research/kaiji-new-chinese-linux-malware-turning-to-golang/](https://intezer.com/blog/research/kaiji-new-chinese-linux-malware-turning-to-golang/)
* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_928]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Shell Configuration Creation or Modification**

Shell configuration files in Unix-like systems are crucial for setting up user environments by defining variables, aliases, and startup scripts. Adversaries exploit these files to execute malicious code persistently. The detection rule identifies suspicious creation or modification of these files, excluding benign processes, to flag potential threats, aligning with tactics like persistence and event-triggered execution.

**Possible investigation steps**

* Review the specific file path involved in the alert to determine if it is a system-wide or user-specific shell configuration file, as listed in the query.
* Identify the process executable that triggered the alert and verify if it is part of the excluded benign processes. If not, investigate the process’s origin and purpose.
* Check the modification or creation timestamp of the file to correlate with any known user activities or scheduled tasks that might explain the change.
* Examine the contents of the modified or newly created shell configuration file for any suspicious or unauthorized entries, such as unexpected scripts or commands.
* Investigate the user account associated with the file modification to determine if the activity aligns with their typical behavior or if the account may have been compromised.
* Cross-reference the alert with other security logs or alerts to identify any related suspicious activities or patterns that could indicate a broader attack campaign.

**False positive analysis**

* System package managers like dpkg, rpm, and yum often modify shell configuration files during software installations or updates. To handle these, exclude processes with executables such as /bin/dpkg or /usr/bin/rpm from triggering alerts.
* Automated system management tools like Puppet and Chef may alter shell configuration files as part of their routine operations. Exclude these processes by adding exceptions for executables like /opt/puppetlabs/puppet/bin/puppet or /usr/bin/chef-client.
* User account management activities, such as adding new users, can lead to shell configuration file modifications. Exclude processes like /usr/sbin/adduser or /sbin/useradd to prevent false positives in these scenarios.
* Temporary files created by text editors (e.g., .swp files) during editing sessions can trigger alerts. Exclude file extensions such as swp, swpx, and swx to avoid these false positives.
* Virtualization and containerization tools like Docker and Podman may modify shell configuration files as part of their operations. Exclude executables like /usr/bin/dockerd or /usr/bin/podman to manage these cases.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Review the modified or newly created shell configuration files to identify and remove any unauthorized or malicious code.
* Restore the affected shell configuration files from a known good backup to ensure the system’s environment is clean and secure.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malware or persistence mechanisms.
* Monitor the system and network for any signs of re-infection or related suspicious activity, focusing on the indicators of compromise (IOCs) associated with the Kaiji malware family.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.
* Implement additional monitoring and alerting for changes to shell configuration files to enhance detection of similar threats in the future.


## Setup [_setup_584]

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


## Rule query [_rule_query_988]

```js
file where host.os.type == "linux" and event.action in ("rename", "creation") and file.path : (
  // system-wide configurations
  "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/bash.bash_logout", "/etc/zsh/*",
  "/etc/csh.cshrc", "/etc/csh.login", "/etc/fish/config.fish", "/etc/ksh.kshrc",
  // root and user configurations
  "/home/*/.profile", "/home/*/.bashrc", "/home/*/.bash_login", "/home/*/.bash_logout", "/home/*/.bash_profile",
  "/root/.profile", "/root/.bashrc", "/root/.bash_login", "/root/.bash_logout", "/root/.bash_profile",
  "/home/*/.zprofile", "/home/*/.zshrc", "/root/.zprofile", "/root/.zshrc",
  "/home/*/.cshrc", "/home/*/.login", "/home/*/.logout", "/root/.cshrc", "/root/.login", "/root/.logout",
  "/home/*/.config/fish/config.fish", "/root/.config/fish/config.fish",
  "/home/*/.kshrc", "/root/.kshrc"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/sbin/adduser", "/usr/sbin/useradd", "/usr/local/bin/dockerd",
    "/usr/sbin/gdm", "/usr/bin/unzip", "/usr/bin/gnome-shell", "/sbin/mkhomedir_helper", "/usr/sbin/sshd",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/bin/xfce4-session", "/usr/libexec/oddjob/mkhomedir", "/sbin/useradd",
    "/usr/lib/systemd/systemd", "/usr/sbin/crond", "/usr/bin/pamac-daemon", "/usr/sbin/mkhomedir_helper",
    "/opt/pbis/sbin/lwsmd", "/usr/sbin/oddjobd"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*",
    "/usr/libexec/platform-python*"
  ) or
  process.executable == null or
  process.name in ("adclient", "mkhomedir_helper", "teleport", "mkhomedir", "adduser", "desktopDaemon", "executor", "crio") or
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

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Unix Shell Configuration Modification
    * ID: T1546.004
    * Reference URL: [https://attack.mitre.org/techniques/T1546/004/](https://attack.mitre.org/techniques/T1546/004/)



