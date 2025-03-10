---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-loadable-kernel-module-configuration-file-creation.html
---

# Loadable Kernel Module Configuration File Creation [prebuilt-rule-8-17-2-loadable-kernel-module-configuration-file-creation]

This rule detects the creation of Loadable Kernel Module (LKM) configuration files. Attackers may create or modify these files to allow their LKMs to be loaded upon reboot, ensuring persistence on a compromised system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

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
* Tactic: Defense Evasion
* Data Source: Elastic Defend

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4802]

```js
file where host.os.type == "linux" and event.action in ("rename", "creation") and process.executable != null and
file.path like~ (
  "/etc/modules", "/etc/modprobe.d/*", "/usr/lib/modprobe.d/*", "/etc/modules-load.d/*",
  "/run/modules-load.d/*", "/usr/local/lib/modules-load.d/*", "/usr/lib/modules-load.d/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/local/bin/dockerd", "/opt/elasticbeanstalk/bin/platform-engine",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/opt/imunify360/venv/bin/python3",
    "/opt/eset/efs/lib/utild", "/usr/sbin/anacron", "/usr/bin/podman", "/kaniko/kaniko-executor", "/usr/bin/prime-select"
  ) or
  file.extension in ("swp", "swpx", "swx", "dpkg-remove") or
  file.Ext.original.extension == "dpkg-new" or
  process.executable like (
    "/nix/store/*", "/var/lib/dpkg/info/kmod.postinst", "/tmp/vmis.*", "/snap/*", "/dev/fd/*",
    "/usr/libexec/platform-python*"
  ) or
  process.executable == null or
  process.name in (
    "crond", "executor", "puppet", "droplet-agent.postinst", "cf-agent", "schedd", "imunify-notifier", "perl",
    "jumpcloud-agent", "crio", "dnf_install", "utild"
  ) or
  (process.name == "sed" and file.name : "sed*") or
  (process.name == "perl" and file.name : "e2scrub_all.tmp*")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Kernel Modules and Extensions
    * ID: T1547.006
    * Reference URL: [https://attack.mitre.org/techniques/T1547/006/](https://attack.mitre.org/techniques/T1547/006/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Rootkit
    * ID: T1014
    * Reference URL: [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)



