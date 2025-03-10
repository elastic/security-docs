---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/privilege-escalation-via-suid-sgid.html
---

# Privilege Escalation via SUID/SGID [privilege-escalation-via-suid-sgid]

Identifies instances where a process is executed with user/group ID 0 (root), and a real user/group ID that is not 0. This is indicative of a process that has been granted SUID/SGID permissions, allowing it to run with elevated privileges. Attackers may leverage a misconfiguration for exploitation in order to escalate their privileges to root, or establish a backdoor for persistence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/#+suid](https://gtfobins.github.io/#+suid)
* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_822]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Privilege Escalation via SUID/SGID**

SUID/SGID are Unix/Linux permissions that allow users to execute files with the file owner’s or group’s privileges, often root. Adversaries exploit misconfigured SUID/SGID binaries to gain elevated access or persistence. The detection rule identifies processes running with root privileges but initiated by non-root users, flagging potential misuse of SUID/SGID permissions.

**Possible investigation steps**

* Review the process details, including process.name and process.args, to understand the nature of the executed command and its intended function.
* Check the process.real_user.id and process.real_group.id to identify the non-root user or group that initiated the process, and assess whether this user should have access to execute such commands.
* Investigate the parent process (process.parent.name) to determine the origin of the execution and whether it aligns with expected behavior or indicates potential compromise.
* Examine the system logs and user activity around the time of the alert to identify any suspicious actions or patterns that could suggest privilege escalation attempts.
* Verify the SUID/SGID permissions of the flagged binary to ensure they are correctly configured and assess whether they have been altered or misconfigured.
* Cross-reference the process with known vulnerabilities or exploits associated with the specific binary or command to determine if it is being targeted for privilege escalation.

**False positive analysis**

* Processes initiated by legitimate system maintenance tasks or scripts may trigger the rule. Review scheduled tasks and scripts to identify benign activities and consider excluding them from the rule.
* Some system utilities or applications may inherently require SUID/SGID permissions for normal operation. Verify the necessity of these permissions and exclude known safe applications from the rule.
* Development or testing environments often run processes with elevated privileges for debugging purposes. Identify these environments and apply exceptions to avoid false positives.
* Administrative tools or scripts executed by system administrators might appear as privilege escalation attempts. Ensure these are documented and excluded if they are part of routine administrative tasks.
* Processes with the parent name "spine" are already excluded, indicating a known benign pattern. Review similar patterns in your environment and apply similar exclusions where applicable.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the attacker.
* Terminate any suspicious processes identified by the detection rule that are running with elevated privileges but were initiated by non-root users.
* Conduct a thorough review of the SUID/SGID binaries on the affected system to identify and remove any unnecessary or misconfigured binaries that could be exploited for privilege escalation.
* Reset credentials and review access permissions for any accounts that may have been compromised or used in the attack to ensure they do not retain unauthorized elevated privileges.
* Apply security patches and updates to the operating system and all installed software to mitigate known vulnerabilities that could be exploited for privilege escalation.
* Implement enhanced monitoring and logging for SUID/SGID execution and privilege escalation attempts to detect and respond to similar threats in the future.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_540]

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
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_876]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  (process.user.id == "0" and process.real_user.id != "0") or
  (process.group.id == "0" and process.real_group.id != "0")
) and (
  process.name in (
    "aa-exec", "ab", "agetty", "alpine", "ar", "arj", "arp", "as", "ascii-xfr", "ash", "aspell",
    "atobm", "awk", "base32", "base64", "basenc", "basez", "bash", "bc", "bridge", "busctl",
    "busybox", "bzip2", "cabal", "capsh", "cat", "choom", "chown", "chroot", "clamscan", "cmp",
    "column", "comm", "cp", "cpio", "cpulimit", "csh", "csplit", "csvtool", "cupsfilter", "curl",
    "cut", "dash", "date", "dd", "debugfs", "dialog", "diff", "dig", "distcc", "dmsetup", "docker",
    "dosbox", "ed", "efax", "elvish", "emacs", "env", "eqn", "espeak", "expand", "expect", "file",
    "find", "fish", "flock", "fmt", "fold", "gawk", "gcore", "gdb", "genie", "genisoimage", "gimp",
    "grep", "gtester", "gzip", "hd", "head", "hexdump", "highlight", "hping3", "iconv", "install",
    "ionice", "ispell", "jjs", "join", "jq", "jrunscript", "julia", "ksh", "ksshell", "kubectl",
    "ld.so", "less", "links", "logsave", "look", "lua", "make", "mawk", "minicom", "more",
    "mosquitto", "msgattrib", "msgcat", "msgconv", "msgfilter", "msgmerge", "msguniq", "multitime",
    "mv", "nasm", "nawk", "ncftp", "nft", "nice", "nl", "nm", "nmap", "node", "nohup", "ntpdate",
    "od", "openssl", "openvpn", "pandoc", "paste", "perf", "perl", "pexec", "pg", "php", "pidstat",
    "pr", "ptx", "python", "rc", "readelf", "restic", "rev", "rlwrap", "rsync", "rtorrent",
    "run-parts", "rview", "rvim", "sash", "scanmem", "sed", "setarch", "setfacl", "setlock", "shuf",
    "soelim", "softlimit", "sort", "sqlite3", "ss", "ssh-agent", "ssh-keygen", "ssh-keyscan",
    "sshpass", "start-stop-daemon", "stdbuf", "strace", "strings", "sysctl", "systemctl", "tac",
    "tail", "taskset", "tbl", "tclsh", "tee", "terraform", "tftp", "tic", "time", "timeout", "troff",
    "ul", "unexpand", "uniq", "unshare", "unsquashfs", "unzip", "update-alternatives", "uudecode",
    "uuencode", "vagrant", "varnishncsa", "view", "vigr", "vim", "vimdiff", "vipw", "w3m", "watch",
    "wc", "wget", "whiptail", "xargs", "xdotool", "xmodmap", "xmore", "xxd", "xz", "yash", "zsh",
    "zsoelim"
  ) or
  process.name == "ip" and (
    (process.args == "-force" and process.args in ("-batch", "-b")) or (process.args == "exec")
  )
) and not process.parent.name == "spine"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Setuid and Setgid
    * ID: T1548.001
    * Reference URL: [https://attack.mitre.org/techniques/T1548/001/](https://attack.mitre.org/techniques/T1548/001/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



