---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-git-hook-created-or-modified.html
---

# Git Hook Created or Modified [prebuilt-rule-8-17-4-git-hook-created-or-modified]

This rule detects the creation or modification of a Git hook file on a Linux system. Git hooks are scripts that Git executes before or after events such as commit, push, and receive. They are used to automate tasks, enforce policies, and customize Git’s behavior. Attackers can abuse Git hooks to maintain persistence on a system by executing malicious code whenever a specific Git event occurs.

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

* [https://git-scm.com/docs/githooks/2.26.0](https://git-scm.com/docs/githooks/2.26.0)
* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

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

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4453]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Git Hook Created or Modified**

Git hooks are scripts that automate tasks by executing before or after Git events like commits or pushes. While beneficial for developers, adversaries can exploit them to execute malicious code, maintaining persistence on a system. The detection rule identifies suspicious creation or modification of Git hooks on Linux, excluding benign processes, to flag potential abuse.

**Possible investigation steps**

* Review the file path to confirm the location of the modified or created Git hook file and determine if it aligns with known repositories or projects on the system.
* Identify the process executable responsible for the creation or modification of the Git hook file and verify if it is a known and legitimate process, excluding those listed in the query.
* Check the timestamp of the event to correlate with any known user activities or scheduled tasks that might explain the modification or creation of the Git hook.
* Investigate the user account associated with the process that triggered the alert to determine if the activity aligns with their typical behavior or if it appears suspicious.
* Examine the contents of the modified or newly created Git hook file to identify any potentially malicious code or unexpected changes.
* Cross-reference the event with other security logs or alerts to identify any related suspicious activities or patterns that might indicate a broader attack or compromise.

**False positive analysis**

* System package managers like dpkg, rpm, and yum can trigger false positives when they create or modify Git hooks during package installations or updates. To manage this, ensure these executables are included in the exclusion list within the detection rule.
* Automated deployment tools such as Puppet and Chef may modify Git hooks as part of their configuration management processes. Exclude these tools by adding their executables to the exception list to prevent false alerts.
* Continuous integration and deployment systems like Jenkins or GitLab runners might modify Git hooks as part of their build processes. Identify and exclude these processes by adding their specific executables or paths to the exclusion criteria.
* Custom scripts or internal tools that are known to modify Git hooks for legitimate purposes should be identified and their executables added to the exclusion list to avoid unnecessary alerts.
* Consider excluding specific directories or paths that are known to be used by trusted applications or processes for Git hook modifications, ensuring these are not flagged as suspicious.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement or further execution of malicious code.
* Terminate any suspicious processes associated with the creation or modification of Git hooks that are not part of the known benign processes listed in the detection rule.
* Conduct a thorough review of the modified or newly created Git hook scripts to identify and remove any malicious code or unauthorized changes.
* Restore any affected Git repositories from a known good backup to ensure integrity and remove any persistence mechanisms.
* Implement file integrity monitoring on the .git/hooks directory to detect unauthorized changes in the future.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Review and update access controls and permissions for Git repositories to limit the ability to modify hook scripts to only trusted users.


## Setup [_setup_1296]

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


## Rule query [_rule_query_5445]

```js
file where host.os.type == "linux" and event.type == "creation" and file.path : "*.git/hooks/*" and
file.extension == null and process.executable != null and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/usr/bin/pamac-daemon", "/bin/pamac-daemon",
    "/usr/local/bin/dockerd", "/sbin/dockerd"
  ) or
  process.executable : ("/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*") or
  process.name in ("git", "dirname", "tar", "gitea", "git-lfs") or
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



