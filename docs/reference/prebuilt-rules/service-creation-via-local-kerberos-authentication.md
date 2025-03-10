---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/service-creation-via-local-kerberos-authentication.html
---

# Service Creation via Local Kerberos Authentication [service-creation-via-local-kerberos-authentication]

Identifies a suspicious local successful logon event where the Logon Package is Kerberos, the remote address is set to localhost, followed by a sevice creation from the same LogonId. This may indicate an attempt to leverage a Kerberos relay attack variant that can be used to elevate privilege locally from a domain joined user to local System privileges.

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

* [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)
* [https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.md)
* [https://github.com/cube0x0/KrbRelay](https://github.com/cube0x0/KrbRelay)
* [https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82](https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Credential Access
* Use Case: Active Directory Monitoring
* Data Source: Active Directory
* Data Source: System
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_922]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Service Creation via Local Kerberos Authentication**

Kerberos is a network authentication protocol designed to provide strong authentication for client/server applications. In Windows environments, it is often used for secure identity verification. Adversaries may exploit Kerberos by relaying authentication tickets locally to escalate privileges, potentially creating services with elevated rights. The detection rule identifies suspicious local logons using Kerberos, followed by service creation, indicating possible misuse. By monitoring specific logon events and service installations, it helps detect unauthorized privilege escalation attempts.

**Possible investigation steps**

* Review the event logs for the specific LogonId identified in the alert to gather details about the logon session, including the user account involved and the time of the logon event.
* Examine the source IP address and port from the logon event to confirm it matches the localhost (127.0.0.1 or ::1) and determine if this aligns with expected behavior for the user or system.
* Investigate the service creation event (event ID 4697) associated with the same LogonId to identify the service name, executable path, and any related command-line arguments to assess if it is legitimate or potentially malicious.
* Check for any recent changes or anomalies in the system or user account, such as modifications to user privileges, group memberships, or recent software installations, that could indicate unauthorized activity.
* Correlate the findings with other security alerts or logs from the same timeframe to identify any patterns or additional indicators of compromise that may suggest a broader attack or compromise.

**False positive analysis**

* Routine administrative tasks may trigger the rule if administrators frequently log in locally using Kerberos and create services as part of their duties. To manage this, create exceptions for known administrative accounts or specific service creation activities that are part of regular maintenance.
* Automated scripts or software updates that use Kerberos authentication and subsequently install or update services can also generate false positives. Identify these scripts or update processes and exclude their associated logon IDs from the rule.
* Security software or monitoring tools that perform regular checks and use Kerberos for authentication might inadvertently trigger the rule. Review the behavior of these tools and whitelist their activities if they are verified as non-threatening.
* In environments where localhost is used for testing or development purposes, developers might log in using Kerberos and create services. Consider excluding specific development machines or user accounts from the rule to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or privilege escalation.
* Terminate any suspicious services created during the incident to halt potential malicious activities.
* Conduct a thorough review of the affected system’s event logs, focusing on the specific LogonId and service creation events to identify the scope of the compromise.
* Reset the credentials of the compromised user account and any other accounts that may have been accessed using the relayed Kerberos tickets.
* Apply patches and updates to the affected system and any other systems in the network to address known vulnerabilities that could be exploited in similar attacks.
* Implement network segmentation to limit the ability of attackers to move laterally within the network, reducing the risk of privilege escalation.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to ensure comprehensive remediation efforts are undertaken.


## Rule query [_rule_query_979]

```js
sequence by winlog.computer_name with maxspan=5m
 [authentication where

  /* event 4624 need to be logged */
  event.action == "logged-in" and event.outcome == "success" and

  /* authenticate locally using relayed kerberos Ticket */
  winlog.event_data.AuthenticationPackageName :"Kerberos" and winlog.logon.type == "Network" and
  cidrmatch(source.ip, "127.0.0.0/8", "::1") and source.port > 0] by winlog.event_data.TargetLogonId

  [any where
   /* event 4697 need to be logged */
   event.action : "service-installed"] by winlog.event_data.SubjectLogonId
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal or Forge Kerberos Tickets
    * ID: T1558
    * Reference URL: [https://attack.mitre.org/techniques/T1558/](https://attack.mitre.org/techniques/T1558/)



