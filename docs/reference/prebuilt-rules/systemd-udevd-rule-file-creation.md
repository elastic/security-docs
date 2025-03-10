---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/systemd-udevd-rule-file-creation.html
---

# Systemd-udevd Rule File Creation [systemd-udevd-rule-file-creation]

Monitors for the creation of rule files that are used by systemd-udevd to manage device nodes and handle kernel device events in the Linux operating system. Systemd-udevd can be exploited for persistence by adversaries by creating malicious udev rules that trigger on specific events, executing arbitrary commands or payloads whenever a certain device is plugged in or recognized by the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1069]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Systemd-udevd Rule File Creation**

Systemd-udevd manages device nodes and handles kernel device events in Linux, using rule files to automate responses to hardware changes. Adversaries can exploit this by creating malicious rules that execute commands when specific devices are connected. The detection rule monitors the creation of these rule files, excluding legitimate processes, to identify potential abuse and ensure system integrity.

**Possible investigation steps**

* Review the file path and name to determine if the rule file is located in a directory commonly used for udev rules, such as /etc/udev/rules.d/ or /lib/udev/.
* Examine the process executable that created or renamed the rule file to identify if it is a known legitimate process or an unexpected one, as specified in the query.
* Check the file extension and ensure it is .rules, confirming it is intended for udev rule configuration.
* Investigate the process name and path to determine if it matches any of the excluded legitimate processes or paths, which could indicate a false positive.
* Analyze the contents of the newly created or modified rule file to identify any suspicious or malicious commands that could be executed when a device is connected.
* Correlate the event with other system logs to identify any related activities or anomalies around the time of the rule file creation or modification.
* Assess the risk and impact of the rule file creation by considering the context of the system and any potential persistence mechanisms it might enable for an adversary.

**False positive analysis**

* System updates and package installations can trigger rule file creations. Exclude processes like dpkg, rpm, and yum by adding them to the exception list to prevent false positives during legitimate system maintenance.
* Container management tools such as Docker and Podman may create or modify udev rules. Exclude these processes to avoid alerts when containers are being managed.
* Automated system configuration tools like Puppet and Chef can modify udev rules as part of their operations. Add these tools to the exception list to reduce noise from routine configuration changes.
* Snap package installations and updates can lead to rule file changes. Exclude snapd and related processes to prevent false positives during snap operations.
* Netplan and systemd processes may generate or modify udev rules as part of network configuration or system initialization. Exclude these processes to avoid unnecessary alerts during legitimate system activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further execution of malicious udev rules and potential lateral movement.
* Identify and review the newly created or modified udev rule files in the specified directories to determine if they contain malicious commands or payloads.
* Remove any unauthorized or malicious udev rule files to prevent them from executing on device connection events.
* Restore any affected system configurations or files from a known good backup to ensure system integrity.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection tools to identify and remove any additional malware or persistence mechanisms.
* Monitor the system for any further suspicious activity or attempts to recreate malicious udev rules, adjusting detection mechanisms as necessary.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected, ensuring comprehensive threat containment and remediation.


## Setup [_setup_675]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click Add integrations.
* In the query bar, search for Elastic Defend and select the integration to see more details about it.
* Click Add Elastic Defend.
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either Traditional Endpoints or Cloud Workloads.
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in New agent policy name. If other agent policies already exist, you can click the Existing hosts tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click Save and Continue.
* To complete the integration, select Add Elastic Agent to your hosts and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_1124]

```js
file where host.os.type == "linux" and event.action in ("rename", "creation") and
process.executable != null and file.extension == "rules" and
file.path : (
  "/lib/udev/*", "/etc/udev/rules.d/*", "/usr/lib/udev/rules.d/*", "/run/udev/rules.d/*", "/usr/local/lib/udev/rules.d/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/netplan/generate",
    "/lib/systemd/system-generators/netplan", "/lib/systemd/systemd", "/usr/bin/containerd", "/usr/sbin/sshd",
    "/kaniko/executor"
  ) or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/*", "/usr/libexec/*"
  ) or
  process.name in (
    "systemd", "netplan", "apt-get", "vmware-config-tools.pl", "systemd-hwdb", "ssm-agent-worker", "crio", "cloud-init", "convert2rhel"
  ) or
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

    * Name: Boot or Logon Initialization Scripts
    * ID: T1037
    * Reference URL: [https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)



