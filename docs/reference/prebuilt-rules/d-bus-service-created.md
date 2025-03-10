---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/d-bus-service-created.html
---

# D-Bus Service Created [d-bus-service-created]

This rule detects the creation of D-Bus service files on Linux systems. D-Bus is a message bus system that provides a way for applications to talk to one another. D-Bus services are defined in service files that are typically located in default directories. The rule looks for the creation of service files that are not associated with known package managers or system services. Attackers may create malicious D-Bus services to establish persistence or escalate privileges on a system.

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
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_257]

**Triage and analysis**

[TBC: QUOTE]
**Investigating D-Bus Service Created**

D-Bus is an inter-process communication system in Linux, enabling applications to communicate. Adversaries may exploit D-Bus by creating unauthorized service files to maintain persistence or escalate privileges. The detection rule identifies suspicious service file creations in key directories, excluding known legitimate processes, to flag potential malicious activity.

**Possible investigation steps**

* Review the file path and extension to confirm if the created file is located in one of the monitored directories such as /usr/share/dbus-1/system-services/ or /etc/dbus-1/system.d/, and ensure it has a .service or .conf extension.
* Examine the process executable that created the file to determine if it is listed as a known legitimate process in the exclusion list. If not, investigate the process further to understand its origin and purpose.
* Check the process name and path for any unusual or unexpected patterns, especially if it is not part of the known exclusions like ssm-agent-worker or platform-python*.
* Investigate the file creation time and correlate it with other system activities or logs to identify any suspicious behavior or patterns around the time of the alert.
* Look into the user account associated with the process that created the file to determine if it has the necessary permissions and if the activity aligns with the user’s typical behavior.
* Search for any related alerts or logs that might indicate a broader attack pattern, such as other unauthorized file creations or modifications in the system.

**False positive analysis**

* Package manager operations can trigger false positives when legitimate service files are created during software installations or updates. To manage this, exclude processes associated with known package managers like dpkg, rpm, and yum from the detection rule.
* System service updates may also result in false positives. Exclude processes such as systemd and crond that are responsible for legitimate system service management.
* Development and testing environments often involve the creation of temporary or test service files. Exclude paths and processes specific to these environments, such as those under /tmp or /dev/fd, to reduce noise.
* Automation tools like Puppet and Chef can create service files as part of their configuration management tasks. Exclude these tools by adding their executable paths to the exception list.
* Custom scripts or tools that mimic package manager behavior might also cause false positives. Identify and exclude these specific scripts or tools by their process names or paths if they are known to be benign.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes associated with the creation of unauthorized D-Bus service files to halt potential malicious activity.
* Remove any unauthorized D-Bus service files identified in the specified directories to eliminate persistence mechanisms.
* Conduct a thorough review of user accounts and privileges on the affected system to ensure no unauthorized privilege escalation has occurred.
* Restore the system from a known good backup if unauthorized changes or damage to the system are detected.
* Monitor the system and network for any signs of re-infection or similar suspicious activities, using enhanced logging and alerting mechanisms.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.


## Setup [_setup_170]

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


## Rule query [_rule_query_268]

```js
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and
file.extension in ("service", "conf") and file.path like~ (
  "/usr/share/dbus-1/system-services/*", "/etc/dbus-1/system.d/*",
  "/lib/dbus-1/system-services/*", "/run/dbus/system.d/*",
  "/home/*/.local/share/dbus-1/services/*", "/home/*/.dbus/session-bus/*",
  "/usr/share/dbus-1/services/*", "/etc/dbus-1/session.d/*"
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
    "/usr/local/manageengine/uems_agent/bin/dcregister"
  ) or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  process.name like (
    "ssm-agent-worker", "platform-python*", "dnf_install", "cloudflared", "lxc-pve-prestart-hook",
    "convert-usrmerge", "elastic-agent", "google_metadata_script_runner", "update-alternatives", "gitlab-runner",
    "install", "crio", "apt-get", "package-cleanup", "dcservice", "dcregister", "jumpcloud-agent", "executor"
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

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)



