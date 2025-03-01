---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-sudo-hijacking.html
---

# Potential Sudo Hijacking [prebuilt-rule-8-17-4-potential-sudo-hijacking]

Identifies the creation of a sudo binary located at /usr/bin/sudo. Attackers may hijack the default sudo binary and replace it with a custom binary or script that can read the user’s password in clear text to escalate privileges or enable persistence onto the system every time the sudo binary is executed.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://eapolsniper.github.io/2020/08/17/Sudo-Hijacking/](https://eapolsniper.github.io/2020/08/17/Sudo-Hijacking/)
* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4535]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Sudo Hijacking**

Sudo is a critical utility in Linux environments, allowing users to execute commands with elevated privileges. Adversaries may exploit this by replacing the sudo binary with a malicious version to capture passwords or maintain persistence. The detection rule identifies suspicious creation or renaming of the sudo binary, excluding legitimate package management processes, to flag potential hijacking attempts.

**Possible investigation steps**

* Review the file creation or rename event details to confirm the file path is either /usr/bin/sudo or /bin/sudo, as these are critical locations for the sudo binary.
* Check the process executable that triggered the event to ensure it is not part of the legitimate package management processes listed in the query, such as /bin/dpkg or /usr/bin/yum.
* Investigate the user account associated with the event to determine if the activity aligns with their typical behavior or if it appears suspicious.
* Examine the system logs around the time of the event for any unusual activity or errors that might indicate tampering or unauthorized access.
* Verify the integrity of the current sudo binary by comparing its hash with a known good version to detect any unauthorized modifications.
* Assess the system for any additional signs of compromise, such as unexpected network connections or new user accounts, which may indicate broader malicious activity.

**False positive analysis**

* Package management processes can trigger false positives when legitimate updates or installations occur. To handle this, ensure that processes like dpkg, rpm, yum, and apt are included in the exclusion list as they are common package managers.
* Custom scripts or automation tools that modify the sudo binary for legitimate reasons may cause alerts. Review these scripts and consider adding their paths to the exclusion list if they are verified as safe.
* Temporary files or directories used during legitimate software installations or updates, such as those in /var/lib/dpkg or /tmp, can lead to false positives. Exclude these paths if they are part of a known and safe process.
* Development or testing environments where sudo binaries are frequently modified for testing purposes might trigger alerts. In such cases, consider excluding these environments from monitoring or adding specific exclusions for known safe modifications.
* Ensure that any process or executable that is known to interact with the sudo binary in a non-malicious way is added to the exclusion list to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the attacker.
* Verify the integrity of the sudo binary by comparing its hash with a known good version from a trusted source. If compromised, replace it with the legitimate binary.
* Conduct a thorough review of system logs and the process execution history to identify any unauthorized changes or suspicious activities related to the sudo binary.
* Reset passwords for all user accounts on the affected system, especially those with elevated privileges, to mitigate potential credential theft.
* Implement additional monitoring on the affected system and similar environments to detect any further attempts to modify critical binaries or escalate privileges.
* Escalate the incident to the security operations team for a comprehensive investigation and to determine if other systems may be affected.
* Review and update access controls and permissions to ensure that only authorized personnel can modify critical system binaries.


## Setup [_setup_1367]

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


## Rule query [_rule_query_5527]

```js
file where host.os.type == "linux" and event.action in ("creation", "rename") and
file.path in ("/usr/bin/sudo", "/bin/sudo") and not (
  file.Ext.original.path in ("/usr/bin/sudo", "/bin/sudo") or
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum", "/bin/dnf", "/usr/bin/dnf",
    "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic", "/bin/pacman", "/usr/bin/pacman",
    "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk", "/usr/local/sbin/apk", "/usr/bin/apt",
    "/usr/sbin/pacman", "/usr/bin/microdnf", "/usr/local/bin/dockerd", "/usr/local/bin/podman", "/usr/local/bin/dnf",
    "/kaniko/executor", "/proc/self/exe", "/usr/bin/apt-get", "/usr/bin/apt-cache", "/usr/bin/apt-mark"
  ) or
  file.Ext.original.extension == "dpkg-new" or
  process.executable : (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/var/lib/docker/*"
  ) or
  process.executable == null or
  (process.name == "sed" and file.name : "sed*")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Sudo and Sudo Caching
    * ID: T1548.003
    * Reference URL: [https://attack.mitre.org/techniques/T1548/003/](https://attack.mitre.org/techniques/T1548/003/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)



