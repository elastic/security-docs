---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempt-to-mount-smb-share-via-command-line.html
---

# Attempt to Mount SMB Share via Command Line [attempt-to-mount-smb-share-via-command-line]

Identifies the execution of macOS built-in commands to mount a Server Message Block (SMB) network share. Adversaries may use valid accounts to interact with a remote network share using SMB.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.freebsd.org/cgi/man.cgi?mount_smbfs](https://www.freebsd.org/cgi/man.cgi?mount_smbfs)
* [https://ss64.com/osx/mount.html](https://ss64.com/osx/mount.md)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_163]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Attempt to Mount SMB Share via Command Line**

SMB (Server Message Block) is a protocol used for network file sharing, allowing applications to read and write to files and request services from server programs in a computer network. Adversaries exploit SMB to move laterally within a network by accessing shared resources using valid credentials. The detection rule identifies suspicious command-line activities on macOS, such as using built-in commands to mount SMB shares, which may indicate unauthorized access attempts. It filters out benign processes, like those from Google Drive, to reduce false positives, focusing on potential threats.

**Possible investigation steps**

* Review the process details to confirm the execution of commands like "mount_smbfs", "open", "mount", or "osascript" with arguments indicating an attempt to mount an SMB share.
* Check the user account associated with the process to determine if it is a valid and authorized user for accessing SMB shares.
* Investigate the source and destination IP addresses involved in the SMB connection attempt to identify if they are known and trusted within the network.
* Examine the parent process of the suspicious activity to understand the context and origin of the command execution, ensuring it is not a benign process like Google Drive.
* Look for any other related alerts or logs that might indicate lateral movement or unauthorized access attempts within the network.
* Assess the risk and impact of the activity by correlating it with other security events or incidents involving the same user or system.

**False positive analysis**

* Google Drive operations can trigger this rule due to its use of SMB for file synchronization. To manage this, exclude processes originating from the Google Drive application by using the provided exception for its executable path.
* Legitimate user activities involving manual mounting of SMB shares for accessing network resources may be flagged. To handle this, identify and whitelist specific user accounts or devices that regularly perform these actions as part of their normal workflow.
* Automated backup solutions that utilize SMB for network storage access might be detected. Review and exclude these processes by identifying their specific command-line patterns or parent processes.
* Development or testing environments where SMB shares are frequently mounted for application testing can cause alerts. Implement exceptions for these environments by specifying known IP addresses or hostnames associated with the test servers.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further lateral movement by the adversary.
* Verify the credentials used in the SMB mount attempt to determine if they have been compromised. Reset passwords and revoke access if necessary.
* Conduct a thorough review of recent login activities and access logs on the affected system and any connected SMB shares to identify unauthorized access or data exfiltration.
* Remove any unauthorized SMB mounts and ensure that no persistent connections remain active.
* Update and patch the macOS system and any related software to mitigate known vulnerabilities that could be exploited for lateral movement.
* Enhance monitoring and logging on the network to detect future unauthorized SMB mount attempts, focusing on the specific command-line patterns identified in the alert.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on the broader network infrastructure.


## Setup [_setup_101]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a macOS System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, for MacOS it is recommended to select "Traditional Endpoints".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_167]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  (
    process.name : "mount_smbfs" or
    (process.name : "open" and process.args : "smb://*") or
    (process.name : "mount" and process.args : "smbfs") or
    (process.name : "osascript" and process.command_line : "osascript*mount volume*smb://*")
  ) and
  not process.parent.executable : "/Applications/Google Drive.app/Contents/MacOS/Google Drive"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SMB/Windows Admin Shares
    * ID: T1021.002
    * Reference URL: [https://attack.mitre.org/techniques/T1021/002/](https://attack.mitre.org/techniques/T1021/002/)



