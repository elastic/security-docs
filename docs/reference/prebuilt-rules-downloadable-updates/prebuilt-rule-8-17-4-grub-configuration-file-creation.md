---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-grub-configuration-file-creation.html
---

# GRUB Configuration File Creation [prebuilt-rule-8-17-4-grub-configuration-file-creation]

This rule detects the creation of GRUB configuration files on Linux systems. The GRUB configuration file is used to configure the boot loader, which is responsible for loading the operating system. Attackers may create malicious GRUB configuration files to execute arbitrary code or escalate privileges during the boot process, which can be leveraged to maintain persistence on the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4456]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GRUB Configuration File Creation**

GRUB (Grand Unified Bootloader) is crucial for booting Linux systems, managing the boot process, and loading the OS. Adversaries may exploit GRUB by creating or altering configuration files to execute unauthorized code or gain elevated privileges, ensuring persistence. The detection rule identifies suspicious creation of GRUB files, excluding legitimate processes, to flag potential security threats.

**Possible investigation steps**

* Review the file path and name to determine if it matches any known GRUB configuration files, as specified in the query (e.g., "/etc/default/grub", "/boot/grub2/grub.cfg").
* Identify the process that created the file by examining the process.executable field, ensuring it is not one of the excluded legitimate processes.
* Check the timestamp of the file creation event to correlate it with any other suspicious activities or changes in the system around the same time.
* Investigate the user account associated with the process that created the file to determine if it has the necessary permissions and if the activity aligns with the user’s typical behavior.
* Analyze the contents of the newly created or modified GRUB configuration file for any unauthorized or suspicious entries that could indicate malicious intent.
* Cross-reference the event with other security logs or alerts to identify any related activities or patterns that could suggest a broader attack or compromise.

**False positive analysis**

* System package managers like dpkg, rpm, and yum may trigger false positives when they update or modify GRUB configuration files during routine package installations or updates. To handle this, ensure these processes are included in the exclusion list within the detection rule.
* Automated system management tools such as Puppet, Chef, and Ansible can also cause false positives when they manage GRUB configurations as part of their configuration management tasks. Consider adding these tools to the exclusion list if they are part of your environment.
* Virtualization and containerization tools like Docker, Podman, and VirtualBox might modify GRUB files as part of their operations. Verify these processes and exclude them if they are legitimate in your setup.
* Temporary files created by text editors or system processes, such as those with extensions like swp or swx, can be mistaken for GRUB configuration files. Ensure these extensions are part of the exclusion criteria to prevent unnecessary alerts.
* Custom scripts or administrative tasks that modify GRUB configurations for legitimate reasons should be reviewed and, if deemed safe, added to the exclusion list to avoid repeated false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement or further unauthorized access.
* Review the GRUB configuration files identified in the alert to confirm unauthorized modifications or creations. Restore any altered files from a known good backup if necessary.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious code or backdoors that may have been introduced.
* Change all system and user passwords on the affected machine to prevent unauthorized access using potentially compromised credentials.
* Monitor the system for any further suspicious activity, particularly focusing on processes attempting to modify GRUB configuration files.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement additional logging and monitoring for GRUB configuration changes to enhance detection capabilities and prevent future unauthorized modifications.


## Setup [_setup_1299]

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


## Rule query [_rule_query_5448]

```js
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and file.path like~ (
  "/etc/default/grub.d/*", "/etc/default/grub", "/etc/grub.d/*",
  "/boot/grub2/grub.cfg", "/boot/grub/grub.cfg", "/boot/efi/EFI/*/grub.cfg",
  "/etc/sysconfig/grub"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/bin/crio", "/usr/sbin/crond",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/kaniko/kaniko-executor",
    "/usr/local/bin/dockerd", "/usr/bin/podman", "/bin/install", "/proc/self/exe", "/usr/lib/systemd/systemd",
    "/usr/sbin/sshd", "/usr/bin/gitlab-runner", "/opt/gitlab/embedded/bin/ruby", "/usr/sbin/gdm", "/usr/bin/install",
    "/usr/local/manageengine/uems_agent/bin/dcregister", "/usr/local/bin/pacman"
  ) or
  process.executable like~ (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  (process.name == "sed" and file.name : "sed*")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Pre-OS Boot
    * ID: T1542
    * Reference URL: [https://attack.mitre.org/techniques/T1542/](https://attack.mitre.org/techniques/T1542/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)



