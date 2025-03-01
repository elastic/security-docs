---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-sensitive-keys-or-passwords-searched-for-inside-a-container.html
---

# Sensitive Keys Or Passwords Searched For Inside A Container [prebuilt-rule-8-17-4-sensitive-keys-or-passwords-searched-for-inside-a-container]

This rule detects the use of system search utilities like grep and find to search for private SSH keys or passwords inside a container. Unauthorized access to these sensitive files could lead to further compromise of the container environment or facilitate a container breakout to the underlying host machine.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://sysdig.com/blog/cve-2021-25741-kubelet-falco/](https://sysdig.com/blog/cve-2021-25741-kubelet-falco/)

**Tags**:

* Data Source: Elastic Defend for Containers
* Domain: Container
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4120]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Sensitive Keys Or Passwords Searched For Inside A Container**

Containers encapsulate applications, providing isolated environments. Adversaries may exploit search utilities like grep or find to locate sensitive credentials within containers, potentially leading to unauthorized access or container escape. The detection rule identifies suspicious searches for private keys or passwords, flagging potential credential access attempts by monitoring process activities and arguments.

**Possible investigation steps**

* Review the process details to identify the specific container where the search activity occurred, using the container.id field to gather context about the environment.
* Examine the process.name and process.args fields to determine the exact command executed and assess whether it aligns with typical usage patterns or indicates malicious intent.
* Check the user context under which the process was executed to understand if the activity was performed by a legitimate user or an unauthorized entity.
* Investigate the container’s recent activity logs to identify any other suspicious behavior or anomalies that might correlate with the search for sensitive keys or passwords.
* Assess the potential impact by determining if any sensitive files, such as private keys or password files, were accessed or exfiltrated following the search activity.
* If possible, correlate the event with network logs to identify any outbound connections that might suggest data exfiltration attempts.

**False positive analysis**

* Routine administrative tasks may trigger the rule when system administrators use grep or find to audit or manage SSH keys and passwords within containers. To mitigate this, create exceptions for known administrative scripts or processes that regularly perform these tasks.
* Automated backup or configuration management tools might search for sensitive files as part of their normal operation. Identify these tools and exclude their process IDs or specific command patterns from triggering the rule.
* Security scanning tools that check for the presence of sensitive files could be flagged. Whitelist these tools by their process names or arguments to prevent false positives.
* Developers or DevOps personnel might use search utilities during debugging or development processes. Establish a list of trusted users or roles and exclude their activities from the rule to reduce noise.
* Continuous integration/continuous deployment (CI/CD) pipelines may include steps that search for keys or passwords for validation purposes. Exclude these pipeline processes by identifying their unique process arguments or container IDs.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized access or potential container escape to the host system. This can be done by stopping the container or disconnecting it from the network.
* Conduct a thorough review of the container’s logs and process activities to identify any unauthorized access or data exfiltration attempts. Pay special attention to the processes and arguments flagged by the detection rule.
* Rotate any potentially compromised credentials, including SSH keys and passwords, that were stored or accessed within the container. Ensure that new credentials are securely stored and managed.
* Assess the container’s configuration and access controls to identify and rectify any security misconfigurations that may have allowed the unauthorized search for sensitive information.
* Implement additional monitoring and alerting for similar suspicious activities across other containers and the host environment to detect and respond to potential threats promptly.
* Escalate the incident to the security operations team for further investigation and to determine if the threat has spread beyond the initial container.
* Review and update container security policies and practices to prevent recurrence, including enforcing least privilege access and using secrets management solutions to handle sensitive information securely.


## Rule query [_rule_query_5137]

```js
process where container.id: "*" and event.type== "start" and
((
/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/
  (process.name in ("grep", "egrep", "fgrep") or process.args in ("grep", "egrep", "fgrep"))
    and process.args : ("*BEGIN PRIVATE*", "*BEGIN OPENSSH PRIVATE*", "*BEGIN RSA PRIVATE*",
"*BEGIN DSA PRIVATE*", "*BEGIN EC PRIVATE*", "*pass*", "*ssh*", "*user*")
)
or
(
/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/
  (process.name in ("find", "locate", "mlocate") or process.args in ("find", "locate", "mlocate"))
    and process.args : ("*id_rsa*", "*id_dsa*")
))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Sub-technique:

    * Name: Credentials In Files
    * ID: T1552.001
    * Reference URL: [https://attack.mitre.org/techniques/T1552/001/](https://attack.mitre.org/techniques/T1552/001/)



