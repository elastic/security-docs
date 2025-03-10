---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/pluggable-authentication-module-pam-creation-in-unusual-directory.html
---

# Pluggable Authentication Module (PAM) Creation in Unusual Directory [pluggable-authentication-module-pam-creation-in-unusual-directory]

This rule detects the creation of Pluggable Authentication Module (PAM) shared object files in unusual directories. Attackers may compile PAM shared object files in temporary directories, to move them to system directories later, potentially allowing them to maintain persistence on a compromised system, or harvest account credentials.

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

* [https://github.com/zephrax/linux-pam-backdoor](https://github.com/zephrax/linux-pam-backdoor)
* [https://github.com/eurialo/pambd](https://github.com/eurialo/pambd)
* [http://0x90909090.blogspot.com/2016/06/creating-backdoor-in-pam-in-5-line-of.html](http://0x90909090.blogspot.com/2016/06/creating-backdoor-in-pam-in-5-line-of.md)
* [https://www.trendmicro.com/en_us/research/19/i/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload.html](https://www.trendmicro.com/en_us/research/19/i/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload.md)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Persistence
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_634]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Pluggable Authentication Module (PAM) Creation in Unusual Directory**

Pluggable Authentication Modules (PAM) are integral to Linux systems, managing authentication tasks. Adversaries may exploit PAM by creating malicious modules in non-standard directories, aiming to gain persistence or capture credentials. The detection rule identifies such anomalies by monitoring the creation of PAM files outside typical system paths, excluding benign processes and known directories, thus highlighting potential threats.

**Possible investigation steps**

* Review the file creation event details, focusing on the file path and name to determine the exact location and nature of the PAM shared object file created.
* Investigate the process that created the file by examining the process name and its parent process to understand the context and legitimacy of the file creation.
* Check the user account associated with the process that created the file to assess if it has the necessary permissions and if the activity aligns with typical user behavior.
* Analyze recent system logs and command history for any suspicious activities or commands that might indicate an attempt to compile or move PAM modules.
* Correlate the event with other security alerts or anomalies on the system to identify potential patterns or coordinated actions that could indicate a broader compromise.
* If possible, retrieve and analyze the contents of the PAM shared object file to identify any malicious code or indicators of compromise.

**False positive analysis**

* Development and testing environments may compile PAM modules in temporary directories. To manage this, exclude paths commonly used for development, such as "/tmp/dev/**" or "/var/tmp/test/**".
* Containerized applications might create PAM modules in non-standard directories. Exclude processes like "dockerd" and "containerd" to prevent false positives from container operations.
* Package managers or system update tools may temporarily store PAM modules in unusual directories during updates. Exclude paths like "/var/cache/pacman/pkg/**" or "/var/lib/dpkg/tmp.ci/**" to avoid alerts during legitimate system updates.
* Custom scripts or automation tools might generate PAM modules in user-specific directories. Identify and exclude these specific scripts or paths if they are known to be safe and necessary for operations.
* Temporary backup or recovery operations might involve copying PAM modules to non-standard locations. Exclude paths used for backups, such as "/backup/**" or "/recovery/**", if these operations are verified as secure.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Conduct a thorough review of the unusual directory where the PAM file was created to identify any other suspicious files or activities, and remove any malicious files found.
* Analyze the process that created the PAM file to determine if it was initiated by a legitimate user or process, and terminate any malicious processes.
* Reset credentials for any accounts that may have been compromised, focusing on those with elevated privileges or access to sensitive systems.
* Restore the affected system from a known good backup to ensure that no malicious modifications persist.
* Implement additional monitoring on the affected system and similar systems to detect any further attempts to create PAM files in unusual directories.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Rule query [_rule_query_676]

```js
file where host.os.type == "linux" and event.type == "creation" and file.name like "pam_*.so" and not file.path like (
  "/lib/security/*",
  "/lib64/security/*",
  "/lib/x86_64-linux-gnu/security/*",
  "/usr/lib/security/*",
  "/usr/lib64/security/*",
  "/usr/lib/x86_64-linux-gnu/security/*"
) and not (
  process.name in ("dockerd", "containerd", "steam", "buildkitd", "unsquashfs", "pacman") or
  file.path like (
    "/build/rootImage/nix/store/*", "/home/*/.local/share/containers/*", "/nix/store/*", "/var/lib/containerd/*",
    "/var/snap/*", "/usr/share/nix/nix/store/*", "/tmp/cura/squashfs-root/*", "/home/*/docker/*", "/tmp/containerd*"
  )
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



