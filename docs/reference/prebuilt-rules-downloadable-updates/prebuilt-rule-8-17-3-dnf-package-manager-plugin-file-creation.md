---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-dnf-package-manager-plugin-file-creation.html
---

# DNF Package Manager Plugin File Creation [prebuilt-rule-8-17-3-dnf-package-manager-plugin-file-creation]

Detects file creation events in the plugin directories for the Yum package manager. In Linux, DNF (Dandified YUM) is a command-line utility used for handling packages on Fedora-based systems, providing functions for installing, updating, upgrading, and removing software along with managing package repositories. Attackers can backdoor DNF to gain persistence by injecting malicious code into plugins that DNF runs, thereby ensuring continued unauthorized access or control each time DNF is used for package management.

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

**References**:

* [https://pwnshift.github.io/2020/10/01/persistence.html](https://pwnshift.github.io/2020/10/01/persistence.md)
* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_880]

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
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead.

For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md). - Click "Save and Continue". - To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts.

For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_4927]

```js
file where host.os.type == "linux" and event.action in ("rename", "creation") and
file.path : ("/usr/lib/python*/site-packages/dnf-plugins/*", "/etc/dnf/plugins/*") and not (
  process.executable in (
    "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf", "/usr/bin/microdnf", "/bin/rpm",
    "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum", "/bin/dnf", "/usr/bin/dnf",
    "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet", "/bin/puppet",
    "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client", "/bin/autossl_check",
    "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd",
    "/usr/libexec/netplan/generate"
  ) or
  file.extension in ("swp", "swpx", "swx") or
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



