---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-pass-the-hash-pth-attempt.html
---

# Potential Pass-the-Hash (PtH) Attempt [potential-pass-the-hash-pth-attempt]

Adversaries may pass the hash using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user’s cleartext password.

**Rule type**: new_terms

**Rule indices**:

* winlogbeat-*
* logs-windows.*
* logs-system.security*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://attack.mitre.org/techniques/T1550/002/](https://attack.mitre.org/techniques/T1550/002/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Data Source: System
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_719]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Pass-the-Hash (PtH) Attempt**

Pass-the-Hash (PtH) is a technique where attackers use stolen password hashes to authenticate and move laterally across systems without needing plaintext passwords. This method exploits the authentication process in Windows environments. The detection rule identifies suspicious logins using specific logon types and processes, indicating potential PtH activity, by monitoring successful authentications with certain user IDs and logon processes.

**Possible investigation steps**

* Review the event logs for the specific user IDs (S-1-5-21-* or S-1-12-1-*) to identify any unusual or unauthorized access patterns, focusing on the time and source of the logon events.
* Examine the winlog.event_data.LogonProcessName field for "seclogo" to determine if this process is commonly used in your environment or if it appears suspicious or unexpected.
* Correlate the successful authentication events with other security logs to identify any lateral movement or access to sensitive systems that occurred after the initial logon.
* Investigate the source IP addresses and hostnames associated with the logon events to determine if they are known and trusted within the network or if they originate from unusual or external locations.
* Check for any recent changes or anomalies in the accounts associated with the suspicious user IDs, such as password resets, privilege escalations, or unusual account activity.
* Consult threat intelligence sources to see if there are any known campaigns or threat actors using similar techniques or targeting similar environments.

**False positive analysis**

* Legitimate administrative tools or scripts that use the "NewCredentials" logon type for automation or scheduled tasks can trigger false positives. Review and whitelist known benign processes or scripts that are part of regular operations.
* Security software or monitoring tools that perform regular checks using the "seclogo" logon process may be misidentified. Identify and exclude these tools from the detection rule to prevent unnecessary alerts.
* Service accounts with user IDs matching the specified patterns (S-1-5-21-* or S-1-12-1-*) might be flagged during routine operations. Ensure these accounts are documented and create exceptions for their expected activities.
* Regularly scheduled tasks or maintenance activities that involve authentication processes similar to PtH can cause false positives. Document these activities and adjust the detection rule to account for their occurrence.
* User behavior analytics might incorrectly flag normal user activities as suspicious. Implement user behavior baselining to differentiate between typical and atypical logon patterns, refining the detection criteria accordingly.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further lateral movement by the attacker.
* Revoke any active sessions associated with the compromised user IDs (S-1-5-21-* or S-1-12-1-*) to disrupt the attacker’s access.
* Conduct a password reset for the affected accounts and any other accounts that may have been accessed using the compromised hashes.
* Review and update access controls and permissions for the affected accounts to ensure they adhere to the principle of least privilege.
* Deploy endpoint detection and response (EDR) tools to monitor for any further suspicious activity or attempts to use stolen hashes.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the breach.
* Implement additional logging and monitoring for the "seclogo" logon process to enhance detection of future pass-the-hash attempts.


## Rule query [_rule_query_766]

```js
host.os.type:"windows" and
event.category : "authentication" and event.action : "logged-in" and
winlog.logon.type : "NewCredentials" and event.outcome : "success" and
user.id : (S-1-5-21-* or S-1-12-1-*) and winlog.event_data.LogonProcessName : "seclogo"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Pass the Hash
    * ID: T1550.002
    * Reference URL: [https://attack.mitre.org/techniques/T1550/002/](https://attack.mitre.org/techniques/T1550/002/)



