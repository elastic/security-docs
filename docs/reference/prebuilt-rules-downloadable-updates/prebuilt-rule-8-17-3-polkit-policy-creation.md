---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-polkit-policy-creation.html
---

# Polkit Policy Creation [prebuilt-rule-8-17-3-polkit-policy-creation]

This rule monitors for the creation of Polkit policy files on Linux systems. Polkit policy files are used to define the permissions for system-wide services and applications. The creation of new Polkit policy files may indicate an attempt to modify the authentication process, which could be used for persistence by an adversary.

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

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Persistence
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: Elastic Endgame

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4843]

```js
file where host.os.type == "linux" and event.type == "creation" and process.executable != null and
file.extension in ("rules", "pkla", "policy") and file.path like~ (

  // Rule files
  "/etc/polkit-1/rules.d/*", "/usr/share/polkit-1/rules.d/*",

  // pkla files
  "/etc/polkit-1/localauthority/*", "/var/lib/polkit-1/localauthority/*",

  // Action files
  "/usr/share/polkit-1/actions/*",

  // Misc. legacy paths
  "/lib/polkit-1/rules.d/*", "/lib64/polkit-1/rules.d/*", "/var/lib/polkit-1/rules.d/*"
) and not (
  process.executable in (
    "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd", "/usr/bin/dockerd", "/usr/sbin/dockerd", "/bin/microdnf",
    "/usr/bin/microdnf", "/bin/rpm", "/usr/bin/rpm", "/bin/snapd", "/usr/bin/snapd", "/bin/yum", "/usr/bin/yum",
    "/bin/dnf", "/usr/bin/dnf", "/bin/podman", "/usr/bin/podman", "/bin/dnf-automatic", "/usr/bin/dnf-automatic",
    "/bin/pacman", "/usr/bin/pacman", "/usr/bin/dpkg-divert", "/bin/dpkg-divert", "/sbin/apk", "/usr/sbin/apk",
    "/usr/local/sbin/apk", "/usr/bin/apt", "/usr/sbin/pacman", "/bin/podman", "/usr/bin/podman", "/usr/bin/puppet",
    "/bin/puppet", "/opt/puppetlabs/puppet/bin/puppet", "/usr/bin/chef-client", "/bin/chef-client",
    "/bin/autossl_check", "/usr/bin/autossl_check", "/proc/self/exe", "/dev/fd/*",  "/usr/bin/pamac-daemon",
    "/bin/pamac-daemon", "/usr/lib/snapd/snapd", "/usr/local/bin/dockerd", "/usr/bin/crio", "/usr/sbin/crond",
    "/opt/puppetlabs/puppet/bin/ruby", "/usr/libexec/platform-python", "/kaniko/kaniko-executor",
    "/usr/local/bin/dockerd", "/usr/bin/podman", "/bin/install", "/proc/self/exe", "/usr/lib/systemd/systemd",
    "/usr/sbin/sshd", "/usr/bin/gitlab-runner", "/opt/gitlab/embedded/bin/ruby", "/usr/sbin/gdm", "/usr/bin/install",
    "/usr/local/manageengine/uems_agent/bin/dcregister", "/usr/local/bin/pacman"
  ) or
process.executable like~ (
    "/nix/store/*", "/var/lib/dpkg/*", "/tmp/vmis.*", "/snap/*", "/dev/fd/*", "/usr/lib/virtualbox/*"
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



