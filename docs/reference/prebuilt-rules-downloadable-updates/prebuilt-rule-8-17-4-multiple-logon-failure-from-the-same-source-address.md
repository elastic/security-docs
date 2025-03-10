---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-multiple-logon-failure-from-the-same-source-address.html
---

# Multiple Logon Failure from the same Source Address [prebuilt-rule-8-17-4-multiple-logon-failure-from-the-same-source-address]

Identifies multiple consecutive logon failures from the same source address and within a short time interval. Adversaries will often brute force login attempts across multiple users with a common or known password, in an attempt to gain access to accounts.

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

* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
* [https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624)
* [https://social.technet.microsoft.com/Forums/ie/en-US/c82ac4f3-a235-472c-9fd3-53aa646cfcfd/network-information-missing-in-event-id-4624?forum=winserversecurity](https://social.technet.microsoft.com/Forums/ie/en-US/c82ac4f3-a235-472c-9fd3-53aa646cfcfd/network-information-missing-in-event-id-4624?forum=winserversecurity)
* [https://serverfault.com/questions/379092/remote-desktop-failed-logon-event-4625-not-logging-ip-address-on-2008-terminal-s/403638#403638](https://serverfault.com/questions/379092/remote-desktop-failed-logon-event-4625-not-logging-ip-address-on-2008-terminal-s/403638#403638)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Resources: Investigation Guide
* Data Source: System

**Version**: 111

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4704]

**Triage and analysis**

**Investigating Multiple Logon Failure from the same Source Address**

Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to guess the password using a repetitive or iterative mechanism systematically. More details can be found [here](https://attack.mitre.org/techniques/T1110/001/).

This rule identifies potential password guessing/brute force activity from a single address.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate the logon failure reason code and the targeted user names.
* Prioritize the investigation if the account is critical or has administrative privileges over the domain.
* Investigate the source IP address of the failed Network Logon attempts.
* Identify whether these attempts are coming from the internet or are internal.
* Investigate other alerts associated with the involved users and source host during the past 48 hours.
* Identify the source and the target computer and their roles in the IT environment.
* Check whether the involved credentials are used in automation or scheduled tasks.
* If this activity is suspicious, contact the account owner and confirm whether they are aware of it.
* Examine the source host for derived artifacts that indicate compromise:
* Observe and collect information about the following activities in the alert source host:
* Attempts to contact external domains and addresses.
* Examine the DNS cache for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve DNS Cache","query":"SELECT * FROM dns_cache"}}
* Examine the host services for suspicious or anomalous entries.
* !{osquery{"label":"Osquery - Retrieve All Services","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services"}}
* !{osquery{"label":"Osquery - Retrieve Services Running on User Accounts","query":"SELECT description, display_name, name, path, pid, service_type, start_type, status, user_account FROM services WHERE\nNOT (user_account LIKE *%LocalSystem* OR user_account LIKE *%LocalService* OR user_account LIKE *%NetworkService* OR\nuser_account == null)\n"}}
* !{osquery{"label":"Osquery - Retrieve Service Unsigned Executables with Virustotal Link","query":"SELECT concat(*https://www.virustotal.com/gui/file/*, sha1) AS VtLink, name, description, start_type, status, pid,\nservices.path FROM services JOIN authenticode ON services.path = authenticode.path OR services.module_path =\nauthenticode.path JOIN hash ON services.path = hash.path WHERE authenticode.result != *trusted*\n"}}
* Investigate potentially compromised accounts. Analysts can do this by searching for login events (for example, 4624) to the host which is the source of this activity

**False positive analysis**

* Understand the context of the authentications by contacting the asset owners. This activity can be related to a new or existing automation or business process that is in a failing state.
* Authentication misconfiguration or obsolete credentials.
* Service account password expired.
* Domain trust relationship issues.
* Infrastructure or availability issues.

**Related rules**

* Multiple Logon Failure Followed by Logon Success - 4e85dc8a-3e41-40d8-bc28-91af7ac6cf60

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the source host to prevent further post-compromise behavior.
* If the asset is exposed to the internet with RDP or other remote services available, take the necessary measures to restrict access to the asset. If not possible, limit the access via the firewall to only the needed IP addresses. Also, ensure the system uses robust authentication mechanisms and is patched regularly.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_1505]

**Setup**

* In some cases the source network address in Windows events 4625/4624 is not populated due to Microsoft logging limitations (examples in the references links). This edge case will break the rule condition and it won’t trigger an alert.


## Rule query [_rule_query_5659]

```js
sequence by winlog.computer_name, source.ip with maxspan=10s
  [authentication where event.action == "logon-failed" and
    /* event 4625 need to be logged */
    winlog.logon.type : "Network" and
    source.ip != null and source.ip != "127.0.0.1" and source.ip != "::1" and
    not user.name : ("ANONYMOUS LOGON", "-", "*$") and not user.domain == "NT AUTHORITY" and

    /*
    noisy failure status codes often associated to authentication misconfiguration :
     0xC000015B - The user has not been granted the requested logon type (also called the logon right) at this machine.
     0XC000005E	- There are currently no logon servers available to service the logon request.
     0XC0000133	- Clocks between DC and other computer too far out of sync.
     0XC0000192	An attempt was made to logon, but the Netlogon service was not started.
    */
    not winlog.event_data.Status : ("0xC000015B", "0XC000005E", "0XC0000133", "0XC0000192")] with runs=10
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)

* Sub-technique:

    * Name: Password Guessing
    * ID: T1110.001
    * Reference URL: [https://attack.mitre.org/techniques/T1110/001/](https://attack.mitre.org/techniques/T1110/001/)

* Sub-technique:

    * Name: Password Spraying
    * ID: T1110.003
    * Reference URL: [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)



