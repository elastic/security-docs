---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suid-sgid-bit-set.html
---

# SUID/SGID Bit Set [prebuilt-rule-8-17-4-suid-sgid-bit-set]

An adversary may add the setuid or setgid bit to a file or directory in order to run a file with the privileges of the owning user or group. An adversary can take advantage of this to either do a shell escape or exploit a vulnerability in an application with the setuid or setgid bit to get code running in a different user’s context. Additionally, adversaries can use this mechanism on their own malware to make sure they’re able to execute in elevated contexts in the future.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**:

* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3976]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SUID/SGID Bit Set**

The SUID/SGID bits in Unix-like systems allow files to execute with the privileges of the file owner or group, enabling necessary elevated permissions for certain applications. However, adversaries can exploit these bits to escalate privileges by modifying files to run with higher access rights. The detection rule identifies suspicious use of commands like `chmod` or `install` to set these bits, excluding known safe paths, to flag potential privilege escalation attempts.

**Possible investigation steps**

* Review the process details to identify the user who executed the command, focusing on the process.name and process.args fields to understand the specific command and arguments used.
* Check the process.parent.executable field to determine the parent process and assess whether it is a known legitimate process or potentially malicious.
* Investigate the file or directory targeted by the SUID/SGID bit modification by examining the process.args field for any unusual or sensitive paths that could indicate privilege escalation attempts.
* Correlate the event with other recent activities from the same user or system to identify any patterns or anomalies that could suggest malicious behavior.
* Verify if the file or directory with modified SUID/SGID bits is part of a known safe path as listed in the exclusion criteria, and assess whether the modification is expected or authorized.

**False positive analysis**

* System package installations or updates may trigger the rule when legitimate processes like package managers set SUID/SGID bits. To handle this, exclude paths related to package management, such as "/var/lib/dpkg/info*".
* Docker or container-related operations might set these bits during normal operations. Exclude paths like "/var/lib/docker/*" to prevent false positives from container management activities.
* Temporary directories used during system operations, such as "/tmp/newroot/*", can cause false alerts. Exclude these paths to avoid unnecessary alerts from temporary system processes.
* Specific system services or applications, like "/usr/bin/ssh-agent", may require SUID/SGID bits for legitimate functionality. Exclude these known safe executables to reduce false positives.
* Custom scripts or applications that are known to require elevated permissions should be reviewed and, if deemed safe, added to the exclusion list to prevent repeated false alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or privilege escalation.
* Identify and terminate any suspicious processes associated with the use of `chmod` or `install` commands that have set the SUID/SGID bits, especially those not in the excluded safe paths.
* Review and revert any unauthorized changes to file permissions, specifically those with SUID/SGID bits set, to their original state.
* Conduct a thorough audit of user accounts and privileges on the affected system to ensure no unauthorized accounts or privilege escalations have occurred.
* Implement additional monitoring on the affected system to detect any further attempts to exploit SUID/SGID bits, focusing on the specific commands and arguments identified in the detection query.
* Escalate the incident to the security operations team for a deeper investigation into potential lateral movement or persistence mechanisms that may have been established by the adversary.
* Apply patches and updates to the affected system and any vulnerable applications to mitigate known vulnerabilities that could be exploited in conjunction with SUID/SGID bit abuse.


## Rule query [_rule_query_4993]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and (
  (process.name == "chmod" and (process.args : ("+s", "u+s", "g+s") or process.args regex "[24][0-9]{3}")) or
  (process.name == "install" and process.args : "-m" and
  (process.args : ("+s", "u+s", "g+s") or process.args regex "[24][0-9]{3}"))
) and not (
  process.parent.executable : (
    "/usr/NX/*", "/var/lib/docker/*", "/var/lib/dpkg/info*", "/tmp/newroot/*",
    "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc/Contents/MacOS/package_script_service"
  ) or
  process.args : (
    "/run/*", "/var/run/*", "/usr/bin/keybase-redirector", "/usr/local/share/fonts", "/usr/bin/ssh-agent"
  )
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

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



