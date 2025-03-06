---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/pluggable-authentication-module-pam-source-download.html
---

# Pluggable Authentication Module (PAM) Source Download [pluggable-authentication-module-pam-source-download]

This rule detects the usage of `curl` or `wget` to download the source code of a Pluggable Authentication Module (PAM) shared object file. Attackers may download the source code of a PAM shared object file to create a backdoor in the authentication process.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/zephrax/linux-pam-backdoor](https://github.com/zephrax/linux-pam-backdoor)
* [https://github.com/eurialo/pambd](https://github.com/eurialo/pambd)
* [http://0x90909090.blogspot.com/2016/06/creating-backdoor-in-pam-in-5-line-of.html](http://0x90909090.blogspot.com/2016/06/creating-backdoor-in-pam-in-5-line-of.md)
* [https://www.trendmicro.com/en_us/research/19/i/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload.html](https://www.trendmicro.com/en_us/research/19/i/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload.html)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Persistence
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_635]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Pluggable Authentication Module (PAM) Source Download**

Pluggable Authentication Modules (PAM) are integral to Linux systems, managing authentication tasks. Adversaries may exploit PAM by downloading its source code to insert backdoors, compromising authentication. The detection rule identifies suspicious downloads of PAM source files using tools like `curl` or `wget`, flagging potential threats to system integrity and user credentials.

**Possible investigation steps**

* Review the process details to confirm the use of `curl` or `wget` for downloading the PAM source file, focusing on the `process.name` and `process.args` fields to verify the URL pattern matches the suspicious download.
* Check the user account associated with the process execution to determine if the activity was initiated by a legitimate user or a potential adversary.
* Investigate the system’s command history and logs to identify any preceding or subsequent commands that might indicate further malicious activity or attempts to compile and install the downloaded PAM source.
* Examine network logs for any unusual outbound connections or data exfiltration attempts following the download, which could suggest further compromise.
* Assess the integrity of existing PAM modules on the system to ensure no unauthorized modifications or backdoors have been introduced.
* Correlate this event with other alerts or anomalies on the same host to identify patterns or a broader attack campaign.

**False positive analysis**

* Legitimate system administrators or developers may download PAM source files for testing or development purposes. To handle this, create exceptions for known user accounts or IP addresses that regularly perform such downloads.
* Automated scripts or configuration management tools might use `curl` or `wget` to download PAM source files as part of routine updates or system setups. Identify these scripts and whitelist their activities to prevent false positives.
* Security researchers or auditors may download PAM source files to conduct security assessments. Establish a process to verify and approve these activities, allowing exceptions for recognized research teams or individuals.
* Educational institutions or training environments might download PAM source files for instructional purposes. Implement a policy to exclude these environments from triggering alerts, ensuring they are recognized as non-threatening.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any active `curl` or `wget` processes identified in the alert to stop the download of potentially malicious PAM source files.
* Conduct a thorough review of PAM configuration files and shared object files on the affected system to identify and remove any unauthorized modifications or backdoors.
* Restore the affected system from a known good backup if unauthorized changes to PAM files are detected and cannot be easily reversed.
* Implement stricter access controls and monitoring on systems handling PAM configurations to prevent unauthorized downloads or modifications in the future.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.
* Update detection mechanisms to monitor for similar download attempts and unauthorized modifications to critical authentication components.


## Rule query [_rule_query_677]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event") and
process.name in ("curl", "wget") and
process.args like~ "https://github.com/linux-pam/linux-pam/releases/download/v*/Linux-PAM-*.tar.xz"
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

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)



