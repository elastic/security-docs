---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-pluggable-authentication-module-pam-creation-in-unusual-directory.html
---

# Pluggable Authentication Module (PAM) Creation in Unusual Directory [prebuilt-rule-8-17-2-pluggable-authentication-module-pam-creation-in-unusual-directory]

This rule detects the creation of Pluggable Authentication Module (PAM) shared object files in unusual directories. Attackers may compile PAM shared object files in temporary directories, to move them to system directories later, potentially allowing them to maintain persistence on a compromised system, or harvest account credentials.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

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

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4803]

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



