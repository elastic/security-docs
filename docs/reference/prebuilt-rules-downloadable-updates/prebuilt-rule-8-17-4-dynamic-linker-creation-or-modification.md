---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-dynamic-linker-creation-or-modification.html
---

# Dynamic Linker Creation or Modification [prebuilt-rule-8-17-4-dynamic-linker-creation-or-modification]

Detects the creation or modification of files related to the dynamic linker on Linux systems. The dynamic linker is a shared library that is used by the Linux kernel to load and execute programs. Attackers may attempt to hijack the execution flow of a program by modifying the dynamic linker configuration files.

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
* Tactic: Defense Evasion
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4340]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Dynamic Linker Creation or Modification**

The dynamic linker in Linux systems is crucial for loading shared libraries needed by programs at runtime. Adversaries may exploit this by altering linker configuration files to hijack program execution, enabling persistence or evasion. The detection rule identifies suspicious creation or renaming of these files, excluding benign processes and extensions, to flag potential threats.

**Possible investigation steps**

* Review the file path involved in the alert to determine if it matches any of the critical dynamic linker configuration files such as /etc/ld.so.preload, /etc/ld.so.conf.d/*, or /etc/ld.so.conf.
* Identify the process that triggered the alert by examining the process.executable field and verify if it is listed as a benign process in the exclusion list. If not, investigate the legitimacy of the process.
* Check the file extension and file.Ext.original.extension fields to ensure the file is not a temporary or expected system file, such as those with extensions like swp, swpx, swx, or dpkg-new.
* Investigate the process.name field to determine if the process is a known system utility like java, sed, or perl, and assess if its usage in this context is typical or suspicious.
* Gather additional context by reviewing recent system logs and other security alerts to identify any related or preceding suspicious activities that might indicate a broader attack or compromise.

**False positive analysis**

* Package management operations can trigger false positives when legitimate package managers like dpkg, rpm, or yum modify linker configuration files. To handle this, ensure these processes are included in the exclusion list to prevent unnecessary alerts.
* System updates or software installations often involve temporary file modifications with extensions like swp or dpkg-new. Exclude these extensions to reduce false positives.
* Automated system management tools such as Puppet or Chef may modify linker files as part of their configuration management tasks. Add these tools to the exclusion list to avoid false alerts.
* Virtualization and containerization platforms like Docker or VMware may alter linker configurations during normal operations. Verify these processes and exclude them if they are part of routine system behavior.
* Custom scripts or applications that use common names like sed or perl might be flagged if they interact with linker files. Review these scripts and consider excluding them if they are verified as safe.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Review and restore the original dynamic linker configuration files from a known good backup to ensure the integrity of the system’s execution flow.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any additional malicious software or scripts.
* Analyze system logs and the process execution history to identify the source of the unauthorized changes and determine if any other systems may be compromised.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on the organization.
* Implement additional monitoring on the affected system and similar systems to detect any future attempts to modify dynamic linker configuration files.
* Review and update access controls and permissions to ensure that only authorized personnel have the ability to modify critical system files, reducing the risk of similar incidents in the future.


## Setup [_setup_1188]

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


## Rule query [_rule_query_5332]

```js
file where host.os.type == "linux" and event.action in ("creation", "rename") and
file.path : ("/etc/ld.so.preload", "/etc/ld.so.conf.d/*", "/etc/ld.so.conf") and
not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/libexec/platform-python",
    "/usr/lib/snapd/snap-update-ns", "/usr/bin/vmware-config-tools.pl"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*", "/opt/dynatrace/oneagent/*"
  ) or
  process.executable == null or
  process.name in (
    "java", "executor", "ssm-agent-worker", "packagekitd", "crio", "dockerd-entrypoint.sh",
    "docker-init", "BootTimeChecker"
  ) or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)



