---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/ransomware-detected-elastic-defend.html
---

# Ransomware - Detected - Elastic Defend [ransomware-detected-elastic-defend]

Generates a detection alert each time an Elastic Defend alert for ransomware are received. Enabling this rule allows you to immediately begin investigating your Endpoint ransomware alerts. This rule identifies Elastic Defend ransomware detections only, and does not include prevention alerts.

**Rule type**: query

**Rule indices**:

* logs-endpoint.alerts-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-10m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 10000

**References**:

* [https://github.com/elastic/protections-artifacts/tree/main/ransomware](https://github.com/elastic/protections-artifacts/tree/main/ransomware)
* [https://docs.elastic.co/en/integrations/endpoint](https://docs.elastic.co/en/integrations/endpoint)

**Tags**:

* Data Source: Elastic Defend
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_853]

**Triage and analysis**

**Investigating Ransomware - Detected - Elastic Defend**

Ransomware protection adds a dedicated layer of detection and prevention against ransomware attacks. Our Ransomware protection consists of 3 subtypes: `behavioral`, `canary files`, and `MBR`. Our behavioral ransomware protection monitors the low level file system activity of all processes on the system to identify generic file encryption techniques. We include signals such as file header information, entropy calculations, known and suspicious extensions, and more to make verdicts. Canary files serve as a high confidence short-cut to other behavior techniques. Our endpoint places hidden files in select directories on the system and will trigger on any process attempting to tamper with the files. Finally, we protect the Master Boot Record (MBR) with our kernel minifilter driver to prevent this type of ransomware attack.

Generally, our ransomware protection is tuned to have extremely low false positives rates. We understand how alarming and disruptive ransomware false positives can be which has factored into its design goals. More likely than not, if this protection fires, it is a true positive. However, certain categories of software do behave similarly to ransomware from the perspective of this protection. That includes installers and backup software, which can make a large number of modifications to documents (especially during a restore operation). Further, encryption or system utilities which modify the system’s MBR may also trigger our MBR protection.

**Possible investigation steps**

* The `Ransomware.files` field provides details about files modifications (paths, entropy, extension and file headers).
* Investigate the metadata and the activity of the process or processes that triggered the alert.
* Assess whether this activity prevalent in the environment by looking for similar occurrences across hosts.
* Some Ransomware attacks tend to execute the operation on multiple hosts at the same time for maximum impact.
* Verify the activity of the `user.name` associated with the alert (local or remote actity, privileged or standard user).
* Quickly identifying the compromised credentials is critical to remediate Ransomware attacks.
* Verify if there are any other alert types (Behavior or Memory Threat) associated with the same host or user or process within the same time.

**False positive analysis**

* Installers and backup software, which can make a large number of modifications to documents (especially during a restore operation).
* Encryption or system utilities which modify the system’s MBR may also trigger our MBR protection.

**Response and Remediation**

* Immediate Isolation and Containment: Quickly disconnect affected systems from the network, including both wired and wireless connections, to prevent the ransomware from spreading. This includes disabling network cards and removing network cables if necessary, while keeping the systems powered on for forensic purposes.
* Activate Incident Response Team and Plan: Assemble your incident response team and implement your incident response plan. Contact necessary stakeholders including IT security, legal counsel, and executive management. Document all actions taken from the moment of detection. Initial Assessment and Evidence Preservation: Identify the scope of the infection and the type of ransomware.
* Take screenshots of ransom messages and create disk images of affected systems. Record all observable indicators of compromise (IOCs) before any remediation begins.
* Business Impact Analysis: Evaluate which critical business operations are affected and establish priority systems for recovery. Determine regulatory reporting requirements based on the type of data potentially compromised.
* Secure Backup Verification: Identify and verify the integrity of your latest clean backups. Check backup systems for potential compromise and ensure they were disconnected during the attack to prevent encryption of backup data.
* System Recovery Preparation: Build a clean environment for recovery operations, including secured networks and validated clean systems. Prepare tools and resources needed for system restoration.
* Malware Eradication: Remove the ransomware from infected systems using appropriate security tools. This may involve complete system rebuilds from known clean sources rather than attempting to clean infected systems.
* Data Restoration: Begin restoring systems from verified clean backups, starting with the most critical business operations. Implement additional security controls and monitoring during the restoration process.
* Security Posture Strengthening: Update all security systems including firewalls, antivirus, and endpoint protection. Reset all credentials across the organization and implement additional access controls like multi-factor authentication where needed.
* Post-Incident Activities: Conduct a detailed post-incident analysis to identify how the ransomware entered the environment. Update security policies and incident response plans based on lessons learned, and provide additional security awareness training to staff.


## Setup [_setup_555]

**Setup**

**Elastic Defend Alerts**

This rule is designed to capture specific alerts generated by Elastic Defend.

To capture all the Elastic Defend alerts, it is recommended to use all of the Elastic Defend feature-specific protection rules:

Behavior - Detected - Elastic Defend (UUID: 0f615fe4-eaa2-11ee-ae33-f661ea17fbce) Behavior - Prevented - Elastic Defend (UUID: eb804972-ea34-11ee-a417-f661ea17fbce) Malicious File - Detected - Elastic Defend (UUID: f2c3caa6-ea34-11ee-a417-f661ea17fbce) Malicious File - Prevented - Elastic Defend (UUID: f87e6122-ea34-11ee-a417-f661ea17fbce) Memory Threat - Detected - Elastic Defend (UUID: 017de1e4-ea35-11ee-a417-f661ea17fbce) Memory Threat - Prevented - Elastic Defend (UUID: 06f3a26c-ea35-11ee-a417-f661ea17fbce) Ransomware - Detected - Elastic Defend (UUID: 0c74cd7e-ea35-11ee-a417-f661ea17fbce) Ransomware - Prevented - Elastic Defend (UUID: 10f3d520-ea35-11ee-a417-f661ea17fbce)

To avoid generating duplicate alerts, you should enable either all feature-specific protection rules or the Endpoint Security (Elastic Defend) rule (UUID: 9a1a2dae-0b5f-4c3d-8305-a268d404c306).

**Additional notes**

This rule is configured to generate more ***Max alerts per run*** than the default 1000 alerts per run set for all rules. This is to ensure that it captures as many alerts as possible.

***IMPORTANT:*** The rule’s ***Max alerts per run*** setting can be superseded by the `xpack.alerting.rules.run.alerts.max` Kibana config setting, which determines the maximum alerts generated by *any* rule in the Kibana alerting framework. For example, if `xpack.alerting.rules.run.alerts.max` is set to 1000, this rule will still generate no more than 1000 alerts even if its own ***Max alerts per run*** is set higher.

To make sure this rule can generate as many alerts as it’s configured in its own ***Max alerts per run*** setting, increase the `xpack.alerting.rules.run.alerts.max` system setting accordingly.

***NOTE:*** Changing `xpack.alerting.rules.run.alerts.max` is not possible in Serverless projects.


## Rule query [_rule_query_911]

```js
event.kind : alert and event.code : ransomware and (event.type : allowed or (event.type: denied and event.outcome: failure))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Encrypted for Impact
    * ID: T1486
    * Reference URL: [https://attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/)



