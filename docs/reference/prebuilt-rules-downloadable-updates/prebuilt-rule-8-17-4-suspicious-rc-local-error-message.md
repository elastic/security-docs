---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-rc-local-error-message.html
---

# Suspicious rc.local Error Message [prebuilt-rule-8-17-4-suspicious-rc-local-error-message]

This rule monitors the syslog log file for error messages related to the rc.local process. The rc.local file is a script that is executed during the boot process on Linux systems. Attackers may attempt to modify the rc.local file to execute malicious commands or scripts during system startup. This rule detects error messages such as "Connection refused," "No such file or directory," or "command not found" in the syslog log file, which may indicate that the rc.local file has been tampered with.

**Rule type**: query

**Rule indices**:

* logs-system.syslog-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.intezer.com/blog/malware-analysis/hiddenwasp-malware-targeting-linux-systems/](https://www.intezer.com/blog/malware-analysis/hiddenwasp-malware-targeting-linux-systems/)
* [https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/#8-boot-or-logon-initialization-scripts-rc-scripts](https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/#8-boot-or-logon-initialization-scripts-rc-scripts)
* [https://www.cyberciti.biz/faq/how-to-enable-rc-local-shell-script-on-systemd-while-booting-linux-system/](https://www.cyberciti.biz/faq/how-to-enable-rc-local-shell-script-on-systemd-while-booting-linux-system/)
* [https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms](https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4482]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious rc.local Error Message**

The rc.local script is crucial in Linux systems, executing commands at boot. Adversaries may exploit this by inserting malicious scripts to gain persistence. The detection rule monitors syslog for specific error messages linked to rc.local, such as "Connection refused," indicating potential tampering. This proactive monitoring helps identify unauthorized modifications, mitigating persistent threats.

**Possible investigation steps**

* Review the syslog entries for the specific error messages "Connection refused," "No such file or directory," or "command not found" associated with the rc.local process to understand the context and frequency of these errors.
* Check the rc.local file for any recent modifications or unusual entries that could indicate tampering or unauthorized changes.
* Investigate the source of the error messages by identifying any related processes or network connections that might have triggered the "Connection refused" error.
* Examine the system’s boot logs and startup scripts to identify any anomalies or unauthorized scripts that may have been introduced.
* Cross-reference the timestamps of the error messages with other system logs to identify any correlated suspicious activities or changes in the system.

**False positive analysis**

* Legitimate software updates or installations may modify the rc.local file, triggering error messages. Users can create exceptions for known update processes by identifying the specific software and excluding its related syslog entries.
* Custom scripts or administrative tasks that intentionally modify rc.local for legitimate purposes might cause false alerts. Document these scripts and add them to an exclusion list to prevent unnecessary alerts.
* Network configuration changes can lead to temporary "Connection refused" errors. If these changes are expected, users should temporarily adjust the monitoring rule to ignore these specific messages during the maintenance window.
* System misconfigurations or missing dependencies might result in "No such file or directory" or "command not found" errors. Regularly audit system configurations and ensure all necessary files and commands are correctly installed to minimize these false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or spread of potential malware.
* Review the rc.local file for unauthorized modifications and restore it from a known good backup if tampering is confirmed.
* Conduct a thorough scan of the system using updated antivirus and anti-malware tools to identify and remove any malicious scripts or software.
* Check for additional persistence mechanisms by reviewing other boot or logon initialization scripts and scheduled tasks.
* Escalate the incident to the security operations team for further investigation and to determine if other systems are affected.
* Implement enhanced monitoring on the affected system and similar systems to detect any future unauthorized changes to boot scripts.
* Review and update access controls and permissions to ensure that only authorized personnel can modify critical system files like rc.local.


## Setup [_setup_1320]

**Setup**

This rule requires data coming in from one of the following integrations: - Filebeat

**Filebeat Setup**

Filebeat is a lightweight shipper for forwarding and centralizing log data. Installed as an agent on your servers, Filebeat monitors the log files or locations that you specify, collects log events, and forwards them either to Elasticsearch or Logstash for indexing.

**The following steps should be executed in order to add the Filebeat for the Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://docs/reference/filebeat/setup-repositories.md).
* To run Filebeat on Docker follow the setup instructions in the [helper guide](beats://docs/reference/filebeat/running-on-docker.md).
* To run Filebeat on Kubernetes follow the setup instructions in the [helper guide](beats://docs/reference/filebeat/running-on-kubernetes.md).
* For quick start information for Filebeat refer to the [helper guide](https://www.elastic.co/guide/en/beats/filebeat/8.11/filebeat-installation-configuration.html).
* For complete Setup and Run Filebeat information refer to the [helper guide](beats://docs/reference/filebeat/setting-up-running.md).

**Rule Specific Setup Note**

* This rule requires the Filebeat System Module to be enabled.
* The system module collects and parses logs created by the system logging service of common Unix/Linux based distributions.
* To run the system module of Filebeat on Linux follow the setup instructions in the [helper guide](beats://docs/reference/filebeat/filebeat-module-system.md).


## Rule query [_rule_query_5474]

```js
host.os.type:linux and event.dataset:system.syslog and process.name:rc.local and
message:("Connection refused" or "No such file or directory" or "command not found")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Initialization Scripts
    * ID: T1037
    * Reference URL: [https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)

* Sub-technique:

    * Name: RC Scripts
    * ID: T1037.004
    * Reference URL: [https://attack.mitre.org/techniques/T1037/004/](https://attack.mitre.org/techniques/T1037/004/)



