---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-networkmanager-dispatcher-script-creation.html
---

# NetworkManager Dispatcher Script Creation [prebuilt-rule-8-17-4-networkmanager-dispatcher-script-creation]

This rule detects the creation of a NetworkManager dispatcher script on a Linux system. NetworkManager dispatcher scripts are shell scripts that NetworkManager executes when network interfaces change state. Attackers can abuse NetworkManager dispatcher scripts to maintain persistence on a system by executing malicious code whenever a network event occurs.

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

## Investigation guide [_investigation_guide_4474]

**Triage and analysis**

[TBC: QUOTE]
**Investigating NetworkManager Dispatcher Script Creation**

NetworkManager dispatcher scripts are executed on Linux systems when network interfaces change state, allowing for automated responses to network events. Adversaries can exploit this by creating scripts that execute malicious code, ensuring persistence and evasion. The detection rule identifies unauthorized script creation by monitoring file creation events in the dispatcher directory, excluding known legitimate processes and file types, thus highlighting potential abuse.

**Possible investigation steps**

* Review the file creation event details to identify the specific script created in the /etc/NetworkManager/dispatcher.d/ directory, noting the file path and name.
* Examine the process that created the script by checking the process.executable field to determine if it is an unexpected or suspicious process not listed in the known legitimate processes.
* Investigate the contents of the newly created script to identify any potentially malicious code or commands that could indicate an attempt to maintain persistence or execute unauthorized actions.
* Check the system’s recent network events and changes to see if the script has been triggered and executed, which could provide further context on its intended use.
* Correlate the event with other security alerts or logs from the same host to identify any related suspicious activities or patterns that could indicate a broader attack or compromise.

**False positive analysis**

* Package management tools like dpkg, rpm, and yum may trigger false positives when they create or modify dispatcher scripts during software installations or updates. To handle these, ensure that the process executables for these tools are included in the exclusion list within the detection rule.
* Automated system management tools such as Puppet, Chef, and Ansible can also cause false positives when they deploy or update configurations. Verify that the executables for these tools are part of the exclusion criteria to prevent unnecessary alerts.
* Temporary files created by text editors like Vim may be mistakenly flagged. These files typically have extensions like swp or swpx. Ensure these extensions are included in the exclusion list to avoid false positives.
* Custom scripts or applications that are known to create or modify dispatcher scripts for legitimate purposes should be reviewed. If deemed safe, add their process executables to the exclusion list to prevent them from being flagged.
* Consider monitoring the frequency and context of script creation events. If certain scripts are frequently created by known processes, evaluate the need to adjust the rule to reduce noise while maintaining security efficacy.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further execution of potentially malicious scripts and limit the attacker’s ability to maintain persistence.
* Review and remove any unauthorized scripts found in the /etc/NetworkManager/dispatcher.d/ directory to eliminate the immediate threat.
* Conduct a thorough examination of the system for additional signs of compromise, such as unexpected processes or network connections, to identify any further malicious activity.
* Restore any affected systems from a known good backup to ensure the removal of any persistent threats that may have been established.
* Implement stricter access controls and monitoring on the /etc/NetworkManager/dispatcher.d/ directory to prevent unauthorized script creation in the future.
* Escalate the incident to the security operations team for further investigation and to determine if the threat is part of a larger attack campaign.
* Update and enhance endpoint detection and response (EDR) solutions to improve detection capabilities for similar threats, leveraging the MITRE ATT&CK framework for guidance on persistence and execution techniques.


## Setup [_setup_1316]

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


## Rule query [_rule_query_5466]

```js
file where host.os.type == "linux" and event.type == "creation" and file.path like~ "/etc/NetworkManager/dispatcher.d/*" and not (
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



