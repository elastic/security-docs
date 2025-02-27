---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-creation-or-modification-of-pluggable-authentication-module-or-configuration.html
---

# Creation or Modification of Pluggable Authentication Module or Configuration [prebuilt-rule-8-17-2-creation-or-modification-of-pluggable-authentication-module-or-configuration]

This rule monitors for the creation or modification of Pluggable Authentication Module (PAM) shared object files or configuration files. Attackers may create or modify these files to maintain persistence on a compromised system, or harvest account credentials.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

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
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Persistence
* Data Source: Elastic Defend

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4814]

```js
file where host.os.type == "linux" and event.action in ("rename", "creation") and
process.executable != null and (
  (file.path like~ (
    "/lib/security/*", "/lib64/security/*", "/usr/lib/security/*", "/usr/lib64/security/*",
    "/lib/x86_64-linux-gnu/security/*", "/usr/lib/x86_64-linux-gnu/security/*"
  ) and file.extension == "so") or
  (file.path like~ "/etc/pam.d/*" and file.extension == null) or
  (file.path like~ "/etc/security/pam_*" or file.path == "/etc/pam.conf")
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/sbin/pam-auth-update",
    "/usr/lib/systemd/systemd", "/usr/libexec/packagekitd", "/usr/bin/bsdtar", "/sbin/pam-auth-update"
  ) or
  file.path like (
    "/tmp/snap.rootfs_*/pam_*.so", "/tmp/newroot/lib/*/pam_*.so", "/tmp/newroot/usr/lib64/security/pam_*.so"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable like (
    "/nix/store/*", "/var/lib/dpkg/*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
  ) or
  (process.name == "sed" and file.name like~ "sed*") or
  (process.name == "perl" and file.name like~ "e2scrub_all.tmp*")
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



