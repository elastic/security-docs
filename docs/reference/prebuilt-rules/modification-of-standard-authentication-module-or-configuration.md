---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/modification-of-standard-authentication-module-or-configuration.html
---

# Modification of Standard Authentication Module or Configuration [modification-of-standard-authentication-module-or-configuration]

Adversaries may modify the standard authentication module for persistence via patching the normal authorization process or modifying the login configuration to allow unauthorized access or elevate privileges.

**Rule type**: new_terms

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/zephrax/linux-pam-backdoor](https://github.com/zephrax/linux-pam-backdoor)
* [https://github.com/eurialo/pambd](https://github.com/eurialo/pambd)
* [http://0x90909090.blogspot.com/2016/06/creating-backdoor-in-pam-in-5-line-of.html](http://0x90909090.blogspot.com/2016/06/creating-backdoor-in-pam-in-5-line-of.md)
* [https://www.trendmicro.com/en_us/research/19/i/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload.html](https://www.trendmicro.com/en_us/research/19/i/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload.md)

**Tags**:

* Domain: Endpoint
* OS: macOS
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 205

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_544]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Modification of Standard Authentication Module or Configuration**

Authentication modules, such as PAM (Pluggable Authentication Modules), are crucial for managing user authentication in Linux and macOS environments. Adversaries may exploit these by altering module files or configurations to gain unauthorized access or escalate privileges. The detection rule identifies suspicious changes to these modules, excluding legitimate processes and paths, to flag potential unauthorized modifications.

**Possible investigation steps**

* Review the specific file that triggered the alert by examining the file.name and file.path fields to determine if it is a known authentication module or configuration file.
* Investigate the process that made the change by analyzing the process.executable field to identify if it is a legitimate process or potentially malicious.
* Check the process.name field to see if the process is one of the excluded legitimate processes, which might indicate a false positive.
* Look into recent system changes or updates that might have affected authentication modules, focusing on the time frame around the alert.
* Correlate the alert with other security events or logs to identify any related suspicious activities or patterns, such as unauthorized access attempts or privilege escalation.
* Verify the integrity of the affected authentication module or configuration file by comparing it with a known good version or using file integrity monitoring tools.

**False positive analysis**

* Package management operations such as updates or installations can trigger false positives. Exclude processes like yum, dnf, rpm, and dpkg from the detection rule to prevent these benign activities from being flagged.
* System maintenance tasks often involve legitimate changes to authentication modules. Exclude processes like authconfig, pam-auth-update, and pam-config to avoid false alerts during routine maintenance.
* Development and testing environments may frequently modify authentication modules for testing purposes. Consider excluding paths like /tmp/snap.rootfs_*/pam_*.so and /tmp/newroot/lib/**/pam_**.so to reduce noise from these environments.
* Backup and synchronization tools such as rsync can cause false positives when they interact with authentication module files. Exclude rsync from the detection rule to prevent these non-threatening activities from being flagged.
* Containerized environments may have different paths and processes that interact with authentication modules. Exclude processes like containerd and paths like /tmp/newroot/usr/lib64/security/pam_*.so to account for these variations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Conduct a thorough review of the modified authentication module or configuration file to identify unauthorized changes and revert them to their original state using a known good backup.
* Reset passwords for all user accounts on the affected system, prioritizing accounts with elevated privileges, to mitigate potential credential compromise.
* Perform a comprehensive scan of the system for additional indicators of compromise, such as unauthorized user accounts or scheduled tasks, and remove any malicious artifacts found.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if other systems may be affected.
* Implement enhanced monitoring on the affected system and similar environments to detect any future unauthorized modifications to authentication modules or configurations.
* Review and update access controls and authentication policies to strengthen security measures and reduce the risk of similar attacks in the future.


## Rule query [_rule_query_585]

```js
event.category:file and event.type:change and
  (file.name:pam_*.so or file.path:(/etc/pam.d/* or /private/etc/pam.d/* or /usr/lib64/security/*)) and
  process.executable:
    (* and
      not
      (
        /usr/libexec/packagekitd or
        /usr/bin/vim or
        /usr/libexec/xpcproxy or
        /usr/bin/bsdtar or
        /usr/local/bin/brew or
        "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc/Contents/MacOS/package_script_service"
      )
    ) and
  not file.path:
         (
           /tmp/snap.rootfs_*/pam_*.so or
           /tmp/newroot/lib/*/pam_*.so or
           /private/var/folders/*/T/com.apple.fileprovider.ArchiveService/TemporaryItems/*/lib/security/pam_*.so or
           /tmp/newroot/usr/lib64/security/pam_*.so
         ) and
  not process.name:
         (
           yum or dnf or rsync or platform-python or authconfig or rpm or pdkg or apk or dnf-automatic or btrfs or
           dpkg or pam-auth-update or steam or platform-python3.6 or pam-config or microdnf or yum_install or yum-cron or
           systemd or containerd or pacman
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

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)



