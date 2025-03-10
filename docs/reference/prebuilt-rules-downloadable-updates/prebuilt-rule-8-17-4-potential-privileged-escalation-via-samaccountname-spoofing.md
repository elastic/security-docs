---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-privileged-escalation-via-samaccountname-spoofing.html
---

# Potential Privileged Escalation via SamAccountName Spoofing [prebuilt-rule-8-17-4-potential-privileged-escalation-via-samaccountname-spoofing]

Identifies a suspicious computer account name rename event, which may indicate an attempt to exploit CVE-2021-42278 to elevate privileges from a standard domain user to a user with domain admin privileges. CVE-2021-42278 is a security vulnerability that allows potential attackers to impersonate a domain controller via samAccountName attribute spoofing.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e](https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e)
* [https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/](https://cloudbrothers.info/en/exploit-kerberos-samaccountname-spoofing/)
* [https://github.com/cube0x0/noPac](https://github.com/cube0x0/noPac)
* [https://twitter.com/exploitph/status/1469157138928914432](https://twitter.com/exploitph/status/1469157138928914432)
* [https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Privilege Escalation
* Use Case: Active Directory Monitoring
* Data Source: Active Directory
* Use Case: Vulnerability
* Data Source: System
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4975]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privileged Escalation via SamAccountName Spoofing**

In Active Directory environments, the samAccountName attribute is crucial for identifying user and computer accounts. Adversaries may exploit vulnerabilities like CVE-2021-42278 to spoof this attribute, potentially elevating privileges by renaming computer accounts to mimic domain controllers. The detection rule identifies suspicious renaming events, where a machine account is altered to resemble a user account, signaling possible privilege escalation attempts.

**Possible investigation steps**

* Review the event logs to confirm the occurrence of a "renamed-user-account" action, focusing on entries where the OldTargetUserName ends with a "$" and the NewTargetUserName does not, indicating a potential spoofing attempt.
* Identify the source of the rename event by examining the event logs for the user or system that initiated the change, and determine if it aligns with expected administrative activity.
* Check the history of the NewTargetUserName to see if it has been used in any recent authentication attempts or privileged operations, which could indicate malicious intent.
* Investigate the associated IP address and hostname from which the rename action was performed to determine if it is a known and trusted source within the network.
* Correlate the event with other security alerts or logs to identify any patterns or additional suspicious activities that might suggest a broader attack campaign.
* Assess the potential impact by determining if the renamed account has been granted elevated privileges or access to sensitive resources since the rename event occurred.

**False positive analysis**

* Routine administrative tasks involving legitimate renaming of computer accounts can trigger false positives. To manage this, create exceptions for known administrative activities by excluding specific administrator accounts or service accounts from the detection rule.
* Automated processes or scripts that rename computer accounts as part of regular maintenance or deployment procedures may also cause false alerts. Identify these processes and exclude their associated accounts or event patterns from the rule.
* Temporary renaming of computer accounts for troubleshooting or testing purposes can be mistaken for suspicious activity. Document and exclude these temporary changes by maintaining a list of authorized personnel and their activities.
* Changes made by trusted third-party software or management tools that interact with Active Directory should be reviewed and, if deemed safe, excluded from triggering alerts by specifying the tool’s account or signature in the rule exceptions.

**Response and remediation**

* Immediately isolate the affected machine from the network to prevent further unauthorized access or lateral movement within the domain.
* Revert any unauthorized changes to the samAccountName attribute by renaming the affected computer account back to its original name.
* Conduct a thorough review of recent changes in Active Directory, focusing on user and computer account modifications, to identify any other potentially compromised accounts.
* Reset passwords for the affected machine account and any other accounts that may have been accessed or modified during the incident.
* Apply the latest security patches and updates to all domain controllers and critical systems to mitigate vulnerabilities like CVE-2021-42278.
* Enhance monitoring and logging for Active Directory events, specifically focusing on account renaming activities, to detect similar threats in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to ensure comprehensive remediation efforts are undertaken.


## Setup [_setup_1563]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_5930]

```js
iam where event.action == "renamed-user-account" and
  /* machine account name renamed to user like account name */
  winlog.event_data.OldTargetUserName : "*$" and not winlog.event_data.NewTargetUserName : "*$"
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

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Domain Accounts
    * ID: T1078.002
    * Reference URL: [https://attack.mitre.org/techniques/T1078/002/](https://attack.mitre.org/techniques/T1078/002/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



