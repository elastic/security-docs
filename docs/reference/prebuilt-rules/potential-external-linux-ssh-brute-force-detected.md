---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-external-linux-ssh-brute-force-detected.html
---

# Potential External Linux SSH Brute Force Detected [potential-external-linux-ssh-brute-force-detected]

Identifies multiple external consecutive login failures targeting a user account from the same source address within a short time interval. Adversaries will often brute force login attempts across multiple users with a common or known password, in an attempt to gain access to these accounts.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-system.auth-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 5

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_683]

**Triage and analysis**

**Investigating Potential External Linux SSH Brute Force Detected**

The rule identifies consecutive SSH login failures targeting a user account from the same source IP address to the same target host indicating brute force login attempts.

This rule will generate a lot of noise for systems with a front-facing SSH service, as adversaries scan the internet for remotely accessible SSH services and try to brute force them to gain unauthorized access.

In case this rule generates too much noise and external brute forcing is of not much interest, consider turning this rule off and enabling "Potential Internal Linux SSH Brute Force Detected" to detect internal brute force attempts.

**Possible investigation steps**

* Investigate the login failure user name(s).
* Investigate the source IP address of the failed ssh login attempt(s).
* Investigate other alerts associated with the user/host during the past 48 hours.
* Identify the source and the target computer and their roles in the IT environment.

**False positive analysis**

* Authentication misconfiguration or obsolete credentials.
* Service account password expired.
* Infrastructure or availability issue.

**Related Rules**

* Potential Internal Linux SSH Brute Force Detected - 1c27fa22-7727-4dd3-81c0-de6da5555feb
* Potential SSH Password Guessing - 8cb84371-d053-4f4f-bce0-c74990e28f28

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_436]

**Setup**

This rule requires data coming in from Filebeat.

**Filebeat Setup**

Filebeat is a lightweight shipper for forwarding and centralizing log data. Installed as an agent on your servers, Filebeat monitors the log files or locations that you specify, collects log events, and forwards them either to Elasticsearch or Logstash for indexing.

**The following steps should be executed in order to add the Filebeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/filebeat/setup-repositories.md).
* To run Filebeat on Docker follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-docker.md).
* To run Filebeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-kubernetes.md).
* For quick start information for Filebeat refer to the [helper guide](https://www.elastic.co/guide/en/beats/filebeat/8.11/filebeat-installation-configuration.html).
* For complete “Setup and Run Filebeat” information refer to the [helper guide](beats://reference/filebeat/setting-up-running.md).

**Rule Specific Setup Note**

* This rule requires the “Filebeat System Module” to be enabled.
* The system module collects and parses logs created by the system logging service of common Unix/Linux based distributions.
* To run the system module of Filebeat on Linux follow the setup instructions in the [helper guide](beats://reference/filebeat/filebeat-module-system.md).


## Rule query [_rule_query_723]

```js
sequence by host.id, source.ip, user.name with maxspan=15s
  [ authentication where host.os.type == "linux" and
   event.action in ("ssh_login", "user_login") and event.outcome == "failure" and
   not cidrmatch(source.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
       "192.0.0.0/29", "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32",
       "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4",
       "100.64.0.0/10", "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
       "::1", "FE80::/10", "FF00::/8") ] with runs = 10
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



