---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-interactive-shell-launched-from-system-user.html
---

# Unusual Interactive Shell Launched from System User [prebuilt-rule-8-17-4-unusual-interactive-shell-launched-from-system-user]

This rule detects interactive shells launched from system users. System users typically do not require interactive shells, and their presence may indicate malicious activity.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.process*

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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4348]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Interactive Shell Launched from System User**

In Linux environments, system users are typically non-interactive and serve specific system functions. Adversaries may exploit these accounts to launch interactive shells, bypassing security measures and evading detection. The detection rule identifies such anomalies by monitoring process activities linked to system users, excluding legitimate processes, and flagging unexpected interactive shell launches, thus highlighting potential malicious activity.

**Possible investigation steps**

* Review the process details to identify the specific interactive shell that was launched, focusing on the process.interactive:true field.
* Examine the user.name field to determine which system user account was used to launch the shell and assess whether this account should have interactive shell access.
* Investigate the process.parent.executable and process.parent.name fields to understand the parent process that initiated the shell, checking for any unusual or unauthorized parent processes.
* Analyze the process.args field for any suspicious or unexpected command-line arguments that might indicate malicious intent.
* Cross-reference the event.timestamp with other security logs to identify any correlated activities or anomalies around the same time frame.
* Check for any recent changes or anomalies in the system user’s account settings or permissions that could have facilitated the shell launch.
* Assess the risk and impact of the activity by considering the context of the system and the potential for further malicious actions.

**False positive analysis**

* System maintenance tasks may trigger interactive shells from system users like *daemon* or *systemd-timesync*. To handle these, review the specific maintenance scripts and add exceptions for known benign processes.
* Automated backup or update processes might launch interactive shells under system users such as *backup* or *apt*. Identify these processes and exclude them by adding their parent process names or arguments to the exception list.
* Some monitoring or logging tools may use system accounts like *messagebus* or *dbus* to execute interactive shells. Verify these tools and exclude their activities if they are legitimate and necessary for system operations.
* Custom scripts or applications running under system users for specific tasks could be misidentified. Document these scripts and add their process names to the exclusion criteria to prevent false alerts.
* In environments where certain system users are repurposed for non-standard tasks, ensure these tasks are documented and create exceptions for their associated processes to avoid unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious interactive shell sessions initiated by system users to halt potential malicious activities.
* Conduct a thorough review of the affected system’s logs and processes to identify any additional indicators of compromise or unauthorized changes.
* Reset credentials for the compromised system user accounts and any other accounts that may have been accessed or affected.
* Implement stricter access controls and monitoring for system user accounts to prevent unauthorized interactive shell launches in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Update detection mechanisms and rules to enhance monitoring for similar threats, ensuring that any future attempts are quickly identified and addressed.


## Setup [_setup_1196]

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


## Rule query [_rule_query_5340]

```js
event.category:process and host.os.type:linux and event.type:start and event.action:exec and user.name:(
   daemon or bin or sys or sync or games or man or mail or news or uucp or proxy or backup or list or irc
   or gnats or _apt or Debian-exim or systemd-timesync or messagebus or uuidd or _chrony or sshd or
   gamer or shutdown or halt or dbus or polkitd or rtkit or pipewire or tcpdump or clevis or
   libstoreagemgmt or geoclue or tss or sssd or gnome-initial-setup or pesign or dnsmasq or chrony
) and process.interactive:true and process.parent.executable:* and not (
  process.parent.name:(
    apt-key or apt-config or gpgv or gpgconf or man-db.postinst or sendmail or rpm or nullmailer-inject
  ) or
  process.args:(/etc/apt/trusted.gpg.d/* or /tmp/apt-key-gpg*) or
  process.name:(awk or apt-config or dpkg or grep or gpgv or sed) or
  (user.name:_apt and process.name:(sqv or apt-key or gpgconf or sort or mktemp or find or cmp or gpg-connect-agent)) or
  (user.name:man and process.name:mandb) or
  (user.name:daemon and process.name:at)
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)

* Sub-technique:

    * Name: Hidden Users
    * ID: T1564.002
    * Reference URL: [https://attack.mitre.org/techniques/T1564/002/](https://attack.mitre.org/techniques/T1564/002/)



