---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-sudo-heap-based-buffer-overflow-attempt.html
---

# Sudo Heap-Based Buffer Overflow Attempt [prebuilt-rule-8-17-4-sudo-heap-based-buffer-overflow-attempt]

Identifies the attempted use of a heap-based buffer overflow vulnerability for the Sudo binary in Unix-like systems (CVE-2021-3156). Successful exploitation allows an unprivileged user to escalate to the root user.

**Rule type**: threshold

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-3156](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-3156)
* [https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit](https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)
* [https://www.bleepingcomputer.com/news/security/latest-macos-big-sur-also-has-sudo-root-privilege-escalation-flaw](https://www.bleepingcomputer.com/news/security/latest-macos-big-sur-also-has-sudo-root-privilege-escalation-flaw)
* [https://www.sudo.ws/alerts/unescape_overflow.html](https://www.sudo.ws/alerts/unescape_overflow.md)

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3977]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Sudo Heap-Based Buffer Overflow Attempt**

Sudo is a critical utility in Unix-like systems, allowing users to execute commands with elevated privileges. A heap-based buffer overflow in Sudo (CVE-2021-3156) can be exploited by attackers to gain root access. Adversaries may craft specific command-line arguments to trigger this vulnerability. The detection rule identifies suspicious Sudo or Sudoedit invocations with particular argument patterns, signaling potential exploitation attempts.

**Possible investigation steps**

* Review the alert details to confirm the presence of suspicious Sudo or Sudoedit invocations with the specific argument patterns: process.args containing a backslash followed by either "-i" or "-s".
* Examine the process execution context by gathering additional details such as the user account associated with the process, the parent process, and the command line used.
* Check the system logs for any other unusual or unauthorized activities around the time of the alert to identify potential lateral movement or further exploitation attempts.
* Investigate the history of the user account involved to determine if there have been any previous suspicious activities or privilege escalation attempts.
* Assess the system for any signs of compromise or unauthorized changes, such as new user accounts, modified files, or unexpected network connections.
* Verify the current version of Sudo installed on the system to determine if it is vulnerable to CVE-2021-3156 and consider applying patches or updates if necessary.

**False positive analysis**

* Routine administrative tasks using sudo or sudoedit with interactive or shell options may trigger the rule. Review the context of these commands and consider excluding specific user accounts or scripts that are known to perform legitimate administrative functions.
* Automated scripts or cron jobs that use sudo with the -i or -s options for legitimate purposes can be flagged. Identify these scripts and add them to an exception list to prevent unnecessary alerts.
* Development or testing environments where users frequently test commands with elevated privileges might generate false positives. Implement a separate monitoring policy for these environments or exclude known test accounts.
* Security tools or monitoring solutions that simulate attacks for testing purposes may inadvertently trigger the rule. Ensure these tools are recognized and excluded from triggering alerts by adding them to an exception list.
* Users with legitimate reasons to frequently switch to root using sudo -i or sudo -s should be identified, and their activities should be monitored separately to avoid false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further exploitation or lateral movement by the attacker.
* Terminate any suspicious sudo or sudoedit processes identified by the detection rule to halt ongoing exploitation attempts.
* Apply the latest security patches and updates to the Sudo utility on all affected systems to remediate the vulnerability (CVE-2021-3156).
* Conduct a thorough review of system logs and process execution history to identify any unauthorized access or privilege escalation activities.
* Reset passwords for all user accounts on the affected system, especially those with elevated privileges, to mitigate potential credential compromise.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the scope of the breach.
* Implement enhanced monitoring and alerting for sudo and sudoedit command executions across the network to detect similar exploitation attempts in the future.


## Rule query [_rule_query_4994]

```js
event.category:process and event.type:start and
  process.name:(sudo or sudoedit) and
  process.args:(*\\ and ("-i" or "-s"))
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



