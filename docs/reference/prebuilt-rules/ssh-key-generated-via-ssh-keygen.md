---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/ssh-key-generated-via-ssh-keygen.html
---

# SSH Key Generated via ssh-keygen [ssh-key-generated-via-ssh-keygen]

This rule identifies the creation of SSH keys using the ssh-keygen tool, which is the standard utility for generating SSH keys. Users often create SSH keys for authentication with remote services. However, threat actors can exploit this tool to move laterally across a network or maintain persistence by generating unauthorized SSH keys, granting them SSH access to systems.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_896]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SSH Key Generated via ssh-keygen**

SSH keys, created using the ssh-keygen tool, are essential for secure authentication in Linux environments. While typically used for legitimate access to remote systems, adversaries can exploit this by generating unauthorized keys, enabling lateral movement or persistence. The detection rule identifies suspicious key creation by monitoring specific directories and actions, helping to flag potential misuse by threat actors.

**Possible investigation steps**

* Review the alert details to identify the specific file path and name where the SSH key was created, focusing on directories like "/home/**/.ssh/**", "/root/.ssh/**", and "/etc/ssh/**".
* Check the user account associated with the SSH key creation event to determine if the action aligns with expected behavior for that user.
* Investigate the process execution context by examining the process tree and parent processes of "/usr/bin/ssh-keygen" to identify any potentially suspicious activity leading to the key generation.
* Analyze recent login and access logs for the user and system involved to detect any unusual or unauthorized access patterns.
* Correlate the event with other security alerts or logs to identify if there are signs of lateral movement or persistence tactics being employed by a threat actor.
* Verify the legitimacy of the SSH key by consulting with the system owner or user to confirm if the key creation was authorized and necessary.

**False positive analysis**

* Routine administrative tasks may trigger the rule when system administrators generate SSH keys for legitimate purposes. To manage this, create exceptions for specific user accounts or directories known to be used by trusted administrators.
* Automated scripts or configuration management tools that regularly generate SSH keys for system provisioning or maintenance can cause false positives. Identify these scripts and exclude their associated processes or file paths from the rule.
* Development environments where developers frequently create SSH keys for testing or deployment purposes might be flagged. Consider excluding directories or user accounts associated with these environments to reduce noise.
* Backup or recovery processes that involve SSH key generation can also trigger alerts. Review these processes and exclude relevant file paths or processes to prevent unnecessary alerts.
* Security tools or monitoring solutions that simulate SSH key generation for testing or validation purposes may be mistakenly flagged. Identify these tools and add exceptions for their activities to avoid false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Revoke any unauthorized SSH keys found in the monitored directories (/home/**/.ssh/**, /root/.ssh/**, /etc/ssh/**) to cut off access for threat actors.
* Conduct a thorough review of user accounts and SSH key pairs on the affected system to identify and remove any unauthorized accounts or keys.
* Reset passwords and regenerate SSH keys for legitimate users to ensure that compromised credentials are not reused.
* Monitor network traffic and system logs for any signs of further unauthorized access attempts or suspicious activity related to SSH.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the breach.
* Implement additional monitoring and alerting for SSH key generation activities across the network to enhance detection of similar threats in the future.


## Rule query [_rule_query_952]

```js
file where host.os.type == "linux" and event.action in ("creation", "file_create_event") and
process.executable == "/usr/bin/ssh-keygen" and file.path : ("/home/*/.ssh/*", "/root/.ssh/*", "/etc/ssh/*") and
not file.name : "known_hosts.*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: SSH Authorized Keys
    * ID: T1098.004
    * Reference URL: [https://attack.mitre.org/techniques/T1098/004/](https://attack.mitre.org/techniques/T1098/004/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SSH
    * ID: T1021.004
    * Reference URL: [https://attack.mitre.org/techniques/T1021/004/](https://attack.mitre.org/techniques/T1021/004/)

* Technique:

    * Name: Remote Service Session Hijacking
    * ID: T1563
    * Reference URL: [https://attack.mitre.org/techniques/T1563/](https://attack.mitre.org/techniques/T1563/)

* Sub-technique:

    * Name: SSH Hijacking
    * ID: T1563.001
    * Reference URL: [https://attack.mitre.org/techniques/T1563/001/](https://attack.mitre.org/techniques/T1563/001/)



