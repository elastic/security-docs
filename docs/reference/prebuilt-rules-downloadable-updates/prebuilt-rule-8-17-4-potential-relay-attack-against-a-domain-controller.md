---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-relay-attack-against-a-domain-controller.html
---

# Potential Relay Attack against a Domain Controller [prebuilt-rule-8-17-4-potential-relay-attack-against-a-domain-controller]

Identifies potential relay attacks against a domain controller (DC) by identifying authentication events using the domain controller computer account coming from other hosts to the DC that owns the account. Attackers may relay the DC hash after capturing it using forced authentication.

**Rule type**: eql

**Rule indices**:

* logs-system.security-*
* logs-windows.forwarded*
* winlogbeat-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
* [https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications](https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications)
* [https://attack.mitre.org/techniques/T1187/](https://attack.mitre.org/techniques/T1187/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Data Source: Active Directory
* Use Case: Active Directory Monitoring
* Data Source: System
* Resources: Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4712]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Relay Attack against a Domain Controller**

Domain Controllers (DCs) are critical in managing authentication within Windows environments. Adversaries exploit this by capturing and relaying DC credentials, often using NTLM authentication, to gain unauthorized access. The detection rule identifies anomalies in authentication events, such as machine accounts logging in from unexpected hosts, indicating potential relay attacks. By analyzing network logon types and mismatched IP addresses, it flags suspicious activities, aiding in early threat detection.

**Possible investigation steps**

* Review the authentication events with event codes 4624 and 4625 to identify any anomalies in logon attempts, focusing on those using NTLM authentication.
* Examine the source IP addresses of the suspicious authentication events to determine if they are external or unexpected within the network environment.
* Verify the machine account names that end with a dollar sign ($) to ensure they match the expected hostnames, and investigate any discrepancies.
* Check the network logon types to confirm if they align with typical usage patterns for the identified machine accounts.
* Investigate the context of the source IP addresses that do not match the host IP, looking for any signs of unauthorized access or unusual network activity.
* Correlate the findings with other security logs and alerts to identify any patterns or additional indicators of compromise related to the potential relay attack.

**False positive analysis**

* Machine accounts performing legitimate network logons from different IP addresses can trigger false positives. To manage this, identify and whitelist known IP addresses associated with legitimate administrative tasks or automated processes.
* Scheduled tasks or automated scripts that use machine accounts for network operations may be flagged. Review and document these tasks, then create exceptions for their associated IP addresses and hostnames.
* Load balancers or proxy servers that alter the source IP address of legitimate authentication requests can cause false alerts. Ensure these devices are accounted for in the network architecture and exclude their IP addresses from the rule.
* Temporary network reconfigurations or migrations might result in machine accounts appearing to log in from unexpected hosts. During such events, temporarily adjust the rule parameters or disable the rule to prevent unnecessary alerts.
* Regularly review and update the list of exceptions to ensure they reflect current network configurations and operational practices, minimizing the risk of overlooking genuine threats.

**Response and remediation**

* Immediately isolate the affected domain controller from the network to prevent further unauthorized access and potential lateral movement by the attacker.
* Conduct a password reset for the domain controller’s machine account and any other accounts that may have been compromised or are at risk, ensuring the use of strong, unique passwords.
* Review and analyze recent authentication logs and network traffic to identify any other potentially compromised systems or accounts, focusing on the source IP addresses flagged in the alert.
* Implement network segmentation to limit the ability of attackers to relay credentials between systems, particularly between domain controllers and other critical infrastructure.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the full scope of the breach.
* Deploy additional monitoring and detection mechanisms to identify similar relay attack patterns in the future, enhancing the detection capabilities for NTLM relay attacks.
* Conduct a post-incident review to identify any gaps in security controls and update policies or procedures to prevent recurrence, ensuring lessons learned are applied to improve overall security posture.


## Rule query [_rule_query_5667]

```js
authentication where host.os.type == "windows" and event.code in ("4624", "4625") and endswith~(user.name, "$") and
    winlog.event_data.AuthenticationPackageName : "NTLM" and winlog.logon.type : "network" and

    /* Filter for a machine account that matches the hostname */
    startswith~(host.name, substring(user.name, 0, -1)) and

    /* Verify if the Source IP belongs to the host */
    not endswith(string(source.ip), string(host.ip)) and
    source.ip != null and source.ip != "::1" and source.ip != "127.0.0.1"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Forced Authentication
    * ID: T1187
    * Reference URL: [https://attack.mitre.org/techniques/T1187/](https://attack.mitre.org/techniques/T1187/)

* Technique:

    * Name: Adversary-in-the-Middle
    * ID: T1557
    * Reference URL: [https://attack.mitre.org/techniques/T1557/](https://attack.mitre.org/techniques/T1557/)

* Sub-technique:

    * Name: LLMNR/NBT-NS Poisoning and SMB Relay
    * ID: T1557.001
    * Reference URL: [https://attack.mitre.org/techniques/T1557/001/](https://attack.mitre.org/techniques/T1557/001/)



