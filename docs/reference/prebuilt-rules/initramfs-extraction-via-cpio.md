---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/initramfs-extraction-via-cpio.html
---

# Initramfs Extraction via CPIO [initramfs-extraction-via-cpio]

This rule detects the extraction of an initramfs image using the `cpio` command on Linux systems. The `cpio` command is used to create or extract cpio archives. Attackers may extract the initramfs image to modify the contents or add malicious files, which can be leveraged to maintain persistence on the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

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
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_431]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Initramfs Extraction via CPIO**

Initramfs is a temporary filesystem used during the Linux boot process, containing essential drivers and scripts. Attackers may exploit the `cpio` command to extract and modify initramfs, embedding malicious files to ensure persistence. The detection rule identifies suspicious `cpio` usage by monitoring process execution patterns, excluding legitimate parent processes, to flag potential threats.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the cpio command with arguments "-H" or "--format" and "newc" to ensure the alert is not a false positive.
* Investigate the parent process of the cpio command to determine if it is an unexpected or unauthorized process, as legitimate processes like mkinitramfs or dracut should be excluded.
* Check the execution path of the parent process to verify if it matches any known legitimate paths such as "/usr/share/initramfs-tools/**" or "/nix/store/**".
* Analyze the timeline of events around the cpio execution to identify any preceding or subsequent suspicious activities that might indicate a broader attack or persistence mechanism.
* Examine the system for any unauthorized modifications or additions to the initramfs image that could indicate tampering or the presence of malicious files.
* Correlate the alert with other security data sources like Elastic Endgame, Elastic Defend, or Crowdstrike to gather additional context and assess the scope of the potential threat.

**False positive analysis**

* Legitimate system updates or maintenance activities may trigger the rule when tools like mkinitramfs or dracut are used. To handle this, ensure these processes are excluded by verifying that the parent process is mkinitramfs or dracut.
* Custom scripts or automation tools that manage initramfs might use cpio in a non-malicious context. Review these scripts and add their parent process names or paths to the exclusion list if they are verified as safe.
* Systems using non-standard initramfs management tools located in directories like /usr/share/initramfs-tools or /nix/store may cause false positives. Confirm these tools' legitimacy and update the exclusion paths accordingly.
* Development or testing environments where initramfs is frequently modified for legitimate reasons can generate alerts. Consider creating environment-specific exceptions to reduce noise while maintaining security in production systems.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or spread of potential malware.
* Terminate any suspicious processes related to the `cpio` command that do not have legitimate parent processes, such as `mkinitramfs` or `dracut`.
* Conduct a thorough review of the extracted initramfs contents to identify and remove any unauthorized or malicious files.
* Restore the initramfs from a known good backup to ensure system integrity and remove any potential persistence mechanisms.
* Monitor the system for any further suspicious activity, particularly related to the `cpio` command, to ensure the threat has been fully mitigated.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems may be affected.
* Update security policies and procedures to include specific checks for unauthorized `cpio` usage and enhance detection capabilities for similar threats.


## Setup [_setup_273]

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


## Rule query [_rule_query_465]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed") and
process.name == "cpio" and process.args in ("-H", "--format") and process.args == "newc" and not (
  process.parent.name in ("mkinitramfs", "dracut") or
  process.parent.executable like~ ("/usr/share/initramfs-tools/*", "/nix/store/*")
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



