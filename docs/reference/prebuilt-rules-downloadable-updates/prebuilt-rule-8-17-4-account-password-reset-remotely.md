---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-account-password-reset-remotely.html
---

# Account Password Reset Remotely [prebuilt-rule-8-17-4-account-password-reset-remotely]

Identifies an attempt to reset a potentially privileged account password remotely. Adversaries may manipulate account passwords to maintain access or evade password duration policies and preserve compromised credentials.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.security*
* logs-windows.forwarded*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724)
* [https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/](https://stealthbits.com/blog/manipulating-user-passwords-with-mimikatz/)
* [https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Credential%20Access/remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Impact
* Data Source: System
* Resources: Investigation Guide

**Version**: 217

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4924]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Account Password Reset Remotely**

Remote password resets are crucial for managing user accounts, especially for privileged users. However, adversaries exploit this by resetting passwords to maintain unauthorized access or bypass security policies. The detection rule identifies suspicious remote password resets by monitoring successful network logins and subsequent password reset actions, focusing on privileged accounts to minimize noise and highlight potential threats.

**Possible investigation steps**

* Review the source IP address from the authentication event to determine if it is from a known or trusted network. Investigate any unfamiliar or suspicious IP addresses.
* Check the winlog.event_data.TargetUserName from the password reset event to confirm if it belongs to a privileged account and verify if the reset was authorized.
* Correlate the winlog.event_data.SubjectLogonId from both the authentication and password reset events to ensure they are linked and identify the user or process responsible for the actions.
* Investigate the timing and frequency of similar events to identify patterns or anomalies that may indicate malicious activity.
* Examine any recent changes or activities associated with the account in question to assess if there are other signs of compromise or unauthorized access.

**False positive analysis**

* Routine administrative tasks can trigger false positives when legitimate IT staff reset passwords for maintenance or support. To manage this, create exceptions for known IT personnel or service accounts that frequently perform these actions.
* Automated scripts or tools used for account management might cause false alerts. Identify and exclude these scripts or tools by their specific account names or IP addresses.
* Scheduled password resets for compliance or security policies may appear suspicious. Document and exclude these scheduled tasks by their timing and associated accounts.
* Service accounts with naming conventions similar to privileged accounts might be flagged. Review and adjust the rule to exclude these specific service accounts by refining the naming patterns in the query.
* Internal network devices or systems that perform regular password resets could be misinterpreted as threats. Whitelist these devices by their IP addresses or hostnames to reduce noise.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Revoke any active sessions associated with the compromised account to disrupt any ongoing malicious activities.
* Reset the password of the affected account using a secure method, ensuring it is done from a trusted and secure system.
* Conduct a thorough review of recent account activities and system logs to identify any additional unauthorized changes or access attempts.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the breach.
* Implement additional monitoring on the affected account and related systems to detect any further suspicious activities.
* Review and update access controls and privileged account management policies to prevent similar incidents in the future.

**Performance**

This rule may cause medium to high performance impact due to logic scoping all remote Windows logon activity.


## Rule query [_rule_query_5879]

```js
sequence by winlog.computer_name with maxspan=1m
  [authentication where event.action == "logged-in" and
    /* event 4624 need to be logged */
    winlog.logon.type : "Network" and event.outcome == "success" and source.ip != null and
    source.ip != "127.0.0.1" and source.ip != "::1" and
    not winlog.event_data.TargetUserName : ("svc*", "PIM_*", "_*_", "*-*-*", "*$")] by winlog.event_data.TargetLogonId
   /* event 4724 need to be logged */
  [iam where event.action == "reset-password" and
   (
    /*
       This rule is very noisy if not scoped to privileged accounts, duplicate the
       rule and add your own naming convention and accounts of interest here.
     */
    winlog.event_data.TargetUserName: ("*Admin*", "*super*", "*SVC*", "*DC0*", "*service*", "*DMZ*", "*ADM*") or
    winlog.event_data.TargetSid : ("S-1-5-21-*-500", "S-1-12-1-*-500")
    )
  ] by winlog.event_data.SubjectLogonId
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

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Account Access Removal
    * ID: T1531
    * Reference URL: [https://attack.mitre.org/techniques/T1531/](https://attack.mitre.org/techniques/T1531/)



