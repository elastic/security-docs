---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-adidns-poisoning-via-wildcard-record-creation.html
---

# Potential ADIDNS Poisoning via Wildcard Record Creation [prebuilt-rule-8-17-4-potential-adidns-poisoning-via-wildcard-record-creation]

Active Directory Integrated DNS (ADIDNS) is one of the core components of AD DS, leveraging AD’s access control and replication to maintain domain consistency. It stores DNS zones as AD objects, a feature that, while robust, introduces some security issues, such as wildcard records, mainly because of the default permission (Any authenticated users) to create DNS-named records. Attackers can create wildcard records to redirect traffic that doesn’t explicitly match records contained in the zone, becoming the Man-in-the-Middle and being able to abuse DNS similarly to LLMNR/NBNS spoofing.

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

* [https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/](https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/)
* [https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications/adidns-spoofing](https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications/adidns-spoofing)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Active Directory
* Use Case: Active Directory Monitoring
* Data Source: System
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4700]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential ADIDNS Poisoning via Wildcard Record Creation**

Active Directory Integrated DNS (ADIDNS) is crucial for maintaining domain consistency by storing DNS zones as AD objects. However, its default permissions allow authenticated users to create DNS records, which adversaries can exploit by adding wildcard records. This enables them to redirect traffic and perform Man-in-the-Middle attacks. The detection rule identifies such abuse by monitoring specific directory service changes indicative of wildcard record creation.

**Possible investigation steps**

* Review the event logs on the affected Windows host to confirm the presence of event code 5137, which indicates a directory service object modification.
* Examine the ObjectDN field in the event data to identify the specific DNS zone where the wildcard record was created, ensuring it starts with "DC=*," to confirm the wildcard nature.
* Check the user account associated with the event to determine if it is a legitimate account or potentially compromised, focusing on any unusual or unauthorized activity.
* Investigate recent changes in the DNS zone to identify any other suspicious modifications or patterns that could indicate further malicious activity.
* Correlate the event with network traffic logs to detect any unusual or redirected traffic patterns that could suggest a Man-in-the-Middle attack.
* Assess the permissions and access controls on the DNS zones to ensure they are appropriately configured and restrict unnecessary modifications by authenticated users.

**False positive analysis**

* Routine administrative changes to DNS records by IT staff can trigger alerts. To manage this, create exceptions for known administrative accounts or specific ObjectDN patterns that correspond to legitimate changes.
* Automated systems or scripts that update DNS records as part of regular maintenance may cause false positives. Identify these systems and exclude their activity from triggering alerts by filtering based on their unique identifiers or event sources.
* Software installations or updates that modify DNS settings might be flagged. Monitor and document these activities, and consider excluding them if they are part of a recognized and secure process.
* Changes made by trusted third-party services that integrate with ADIDNS could be misinterpreted as threats. Verify these services and whitelist their actions to prevent unnecessary alerts.
* Temporary testing environments that mimic production settings might generate alerts. Ensure these environments are clearly documented and excluded from monitoring if they are known to perform non-threatening wildcard record creations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further exploitation or data exfiltration.
* Revoke any potentially compromised credentials associated with the affected system or user accounts involved in the alert.
* Conduct a thorough review of DNS records in the affected zone to identify and remove any unauthorized wildcard entries.
* Implement stricter access controls on DNS record creation, limiting permissions to only necessary administrative accounts.
* Monitor network traffic for signs of Man-in-the-Middle activity, focusing on unusual DNS queries or redirections.
* Escalate the incident to the security operations center (SOC) for further investigation and to assess the potential impact on other systems.
* Update detection mechanisms to include additional indicators of compromise related to ADIDNS abuse, enhancing future threat detection capabilities.


## Setup [_setup_1501]

**Setup**

The *Audit Directory Service Changes* logging policy must be configured for (Success, Failure). Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Policies >
Windows Settings >
Security Settings >
Advanced Audit Policies Configuration >
Audit Policies >
DS Access >
Audit Directory Service Changes (Success,Failure)
```

The above policy does not cover the target object by default (we still need it to be configured to generate events), so we need to set up an AuditRule using [https://github.com/OTRF/Set-AuditRule](https://github.com/OTRF/Set-AuditRule).

```
Set-AuditRule -AdObjectPath 'AD:\CN=MicrosoftDNS,DC=DomainDNSZones,DC=Domain,DC=com' -WellKnownSidType WorldSid -Rights CreateChild -InheritanceFlags Descendents -AttributeGUID e0fa1e8c-9b45-11d0-afdd-00c04fd930c9 -AuditFlags Success
```


## Rule query [_rule_query_5655]

```js
any where host.os.type == "windows" and event.code == "5137" and
    startsWith(winlog.event_data.ObjectDN, "DC=*,")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Adversary-in-the-Middle
    * ID: T1557
    * Reference URL: [https://attack.mitre.org/techniques/T1557/](https://attack.mitre.org/techniques/T1557/)



