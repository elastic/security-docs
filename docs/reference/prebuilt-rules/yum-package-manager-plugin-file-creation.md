---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/yum-package-manager-plugin-file-creation.html
---

# Yum Package Manager Plugin File Creation [yum-package-manager-plugin-file-creation]

Detects file creation events in the plugin directories for the Yum package manager. In Linux, Yum (Yellowdog Updater, Modified) is a command-line utility used for handling packages on (by default) Fedora-based systems, providing functions for installing, updating, upgrading, and removing software along with managing package repositories. Attackers can backdoor Yum to gain persistence by injecting malicious code into plugins that Yum runs, thereby ensuring continued unauthorized access or control each time Yum is used for package management.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/local/yum_package_manager_persistence.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/local/yum_package_manager_persistence.rb)
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

## Investigation guide [_investigation_guide_1211]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Yum Package Manager Plugin File Creation**

The Yum package manager is integral to managing software on Fedora-based Linux systems, utilizing plugins to extend its functionality. Adversaries may exploit this by inserting malicious code into these plugins, ensuring persistent access whenever Yum is executed. The detection rule identifies suspicious file creation in plugin directories, excluding legitimate processes and temporary files, to flag potential unauthorized modifications.

**Possible investigation steps**

* Review the file creation event details, focusing on the file path to confirm if it matches the plugin directories "/usr/lib/yum-plugins/**" or "/etc/yum/pluginconf.d/**".
* Identify the process responsible for the file creation by examining the process.executable field, ensuring it is not one of the legitimate processes listed in the exclusion criteria.
* Check the file extension and name to ensure it is not a temporary or excluded file type, such as those with extensions "swp", "swpx", "swx", or names starting with ".ansible".
* Investigate the origin and legitimacy of the process by correlating with other system logs or using threat intelligence to determine if the process is known to be associated with malicious activity.
* Assess the file content for any signs of malicious code or unauthorized modifications, especially if the file is a script or configuration file.
* Determine if there have been any recent changes or updates to the system that could explain the file creation, such as legitimate software installations or updates.

**False positive analysis**

* Legitimate software updates or installations may trigger file creation events in Yum plugin directories. To handle these, users can create exceptions for known package management processes like rpm, dnf, and yum, which are already included in the rule’s exclusion list.
* Temporary files created by text editors or system processes, such as those with extensions like swp, swpx, or swx, can be safely excluded as they are typically non-threatening. Ensure these extensions are part of the exclusion criteria.
* Automation tools like Ansible may generate temporary files in the plugin directories. Users can exclude file names starting with .ansible or .ansible_tmp to prevent false positives from these operations.
* Processes running from specific directories like /nix/store or /var/lib/dpkg are often part of legitimate system operations. Users should verify these paths and include them in the exclusion list if they are part of regular system behavior.
* System maintenance scripts or tools like sed and perl may create temporary files during their execution. Users can exclude these specific process names and file patterns to reduce false alerts.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes that may be running as a result of the malicious plugin modification to halt any ongoing malicious activity.
* Restore the compromised plugin files from a known good backup to ensure the integrity of the Yum package manager’s functionality.
* Conduct a thorough review of user accounts and permissions on the affected system to identify and remove any unauthorized access or privilege escalations.
* Implement file integrity monitoring on the Yum plugin directories to detect any future unauthorized modifications promptly.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.
* Update and patch the system to the latest security standards to mitigate any vulnerabilities that may have been exploited by the adversary.


## Setup [_setup_759]

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


## Rule query [_rule_query_1241]

```js
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path : ("/usr/lib/yum-plugins/*", "/etc/yum/pluginconf.d/*") and not (
  process.executable in (
    "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf", "/usr/bin/microdnf", "/bin/rpm",
    "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum", "/bin/dnf", "/usr/bin/dnf",
    "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet", "/bin/puppet",
    "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client", "/bin/autossl_check",
    "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd",
    "/usr/libexec/netplan/generate"
  ) or
  process.name in ("yumBackend.py", "crio") or
  file.extension in ("swp", "swpx", "swx") or
  file.Ext.original.name like ".ansible*" or
  file.name like ".ansible_tmp*" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/*", "/usr/libexec/*",
    "/etc/kernel/*"
  ) or
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



