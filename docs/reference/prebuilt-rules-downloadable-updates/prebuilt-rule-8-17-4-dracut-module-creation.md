---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-dracut-module-creation.html
---

# Dracut Module Creation [prebuilt-rule-8-17-4-dracut-module-creation]

This rule detects the creation of Dracut module files on Linux systems. Dracut is a tool used to generate an initramfs image that is used to boot the system. Dracut modules are scripts that are executed during the initramfs image generation process. Attackers may create malicious Dracut modules to execute arbitrary code at boot time, which can be leveraged to maintain persistence on a Linux system.

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

## Investigation guide [_investigation_guide_4448]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Dracut Module Creation**

Dracut is a utility for generating initramfs images, crucial for booting Linux systems. It uses modules, which are scripts executed during image creation. Adversaries may exploit this by crafting malicious modules to execute code at boot, ensuring persistence. The detection rule identifies unauthorized module creation by monitoring file paths and excluding known legitimate processes, helping to flag potential threats.

**Possible investigation steps**

* Review the file path of the created Dracut module to determine if it matches known legitimate paths or if it appears suspicious, focusing on paths like "/lib/dracut/modules.d/**" and "/usr/lib/dracut/modules.d/**".
* Identify the process that created the Dracut module by examining the process.executable field, and verify if it is listed in the known legitimate processes or if it is an unexpected process.
* Check the file extension of the created module to ensure it is not one of the excluded extensions such as "swp", "swpx", "swx", or "dpkg-remove".
* Investigate the history and behavior of the process that created the module, including its parent process and any associated network activity, to assess if it has been involved in other suspicious activities.
* Correlate the alert with other security events or logs from the same host to identify any patterns or additional indicators of compromise that might suggest malicious activity.
* Consult threat intelligence sources to determine if there are any known threats or campaigns associated with the process or file path involved in the alert.

**False positive analysis**

* Package managers like dpkg, rpm, and yum may trigger false positives when they update or install packages. To handle this, ensure these processes are included in the exclusion list within the detection rule.
* Automated system management tools such as Puppet, Chef, and Ansible can create or modify Dracut modules as part of their configuration management tasks. Add these tools to the exclusion list to prevent false alerts.
* System updates or maintenance scripts that run as part of regular system operations might be flagged. Review these scripts and add their executables to the exclusion list if they are verified as non-threatening.
* Custom scripts or applications that interact with Dracut modules for legitimate purposes should be reviewed and, if deemed safe, added to the exclusion list to avoid unnecessary alerts.
* Temporary files or backup files with extensions like swp or dpkg-remove may be mistakenly flagged. Ensure these extensions are included in the exclusion criteria to reduce false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread or communication with potential command and control servers.
* Conduct a thorough review of the Dracut module files located in the specified directories (/lib/dracut/modules.d/**, /usr/lib/dracut/modules.d/**) to identify and remove any unauthorized or suspicious modules.
* Restore the system from a known good backup if malicious Dracut modules are confirmed, ensuring that the backup predates the unauthorized changes.
* Implement additional monitoring on the affected system to detect any further unauthorized Dracut module creation or other suspicious activities.
* Review and tighten access controls and permissions for the directories and processes involved in Dracut module creation to prevent unauthorized modifications.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Update and enhance detection capabilities to include alerts for any future unauthorized Dracut module creation attempts, leveraging the specific indicators identified in this incident.


## Setup [_setup_1291]

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


## Rule query [_rule_query_5440]

```js
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and
file.path like~ ("/lib/dracut/modules.d/*", "/usr/lib/dracut/modules.d/*") and not (
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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



