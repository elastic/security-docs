---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/polkit-policy-creation.html
---

# Polkit Policy Creation [polkit-policy-creation]

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
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_637]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Polkit Policy Creation**

Polkit, or PolicyKit, is a system service in Linux environments that manages system-wide privileges, allowing non-privileged processes to communicate with privileged ones. Adversaries may exploit Polkit by creating or modifying policy files to gain unauthorized access or maintain persistence. The detection rule monitors the creation of these files in critical directories, excluding known legitimate processes, to identify potential malicious activity.

**Possible investigation steps**

* Review the file path and extension to confirm if the created file is located in one of the critical directories specified in the query, such as /etc/polkit-1/rules.d/ or /usr/share/polkit-1/actions/.
* Identify the process executable responsible for the file creation and verify if it is listed in the exclusion list of known legitimate processes. If not, this may warrant further investigation.
* Check the timestamp of the file creation event to determine if it coincides with any known maintenance or update activities, which could explain the file creation.
* Investigate the user account associated with the process that created the file to determine if it has the necessary privileges and if the activity aligns with the user’s typical behavior.
* Examine any recent changes or updates to the system that might have triggered the creation of the Polkit policy file, such as software installations or configuration changes.
* Look for any related alerts or logs that might indicate a broader pattern of suspicious activity, such as unauthorized access attempts or other policy modifications.

**False positive analysis**

* System package managers like dpkg, rpm, and yum may create or modify Polkit policy files during legitimate software installations or updates. To handle these, ensure that the rule excludes processes associated with these package managers as specified in the rule’s exception list.
* Container management tools such as Docker and Podman might also trigger false positives when managing containerized applications. Users should verify that these executables are included in the exclusion list to prevent unnecessary alerts.
* Automation tools like Puppet and Chef can modify policy files as part of their configuration management tasks. Confirm that these processes are part of the exclusion criteria to avoid false positives.
* Snap package installations and updates can lead to the creation of policy files. Ensure that paths related to Snap are covered in the exclusion patterns to minimize false alerts.
* Virtualization software such as VirtualBox may interact with Polkit policy files. Users should check that relevant paths and executables are included in the exceptions to reduce false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified as creating or modifying Polkit policy files, especially those not listed in the known legitimate processes.
* Review and restore the integrity of the Polkit policy files by comparing them against a known good baseline or backup to ensure no unauthorized changes persist.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or processes.
* Implement additional monitoring on the affected system and similar systems to detect any further attempts to create or modify Polkit policy files.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat is part of a larger attack campaign.
* Review and update access controls and permissions related to Polkit policy files to ensure only authorized processes and users can create or modify these files, reducing the risk of future exploitation.


## Rule query [_rule_query_679]

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



