---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-potential-shell-via-web-server.html
---

# Potential Shell via Web Server [prebuilt-rule-8-4-1-potential-shell-via-web-server]

Identifies suspicious commands executed via a web server, which may suggest a vulnerability and remote shell access.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://pentestlab.blog/tag/web-shell/](https://pentestlab.blog/tag/web-shell/)
* [https://www.elastic.co/security-labs/elastic-response-to-the-the-spring4shell-vulnerability-cve-2022-22965](https://www.elastic.co/security-labs/elastic-response-to-the-the-spring4shell-vulnerability-cve-2022-22965)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Persistence
* Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2659]

## Triage and analysis

## Investigating Potential Shell via Web Server

Adversaries may backdoor web servers with web shells to establish persistent access to systems. A web shell is a web
script that is placed on an openly accessible web server to allow an adversary to use the web server as a gateway into a
network. A web shell may provide a set of functions to execute or a command line interface on the system that hosts the
web server.

This rule detects a web server process spawning script and command line interface programs, potentially indicating
attackers executing commands using the web shell.

### Possible investigation steps

- Investigate abnormal behaviors observed by the subject process such as network connections, file modifications, and
any other spawned child processes.
- Examine the command line to determine which commands or scripts were executed.
- Investigate other alerts associated with the user/host during the past 48 hours.
- If scripts or executables were dropped, retrieve the files and determine if they are malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
        - Check if the domain is newly registered or unexpected.
        - Check the reputation of the domain or IP address.
      - File access, modification, and creation activities.
      - Cron jobs, services and other persistence mechanisms.

## False positive analysis

- This activity is unlikely to happen legitimately. Any activity that triggered the alert and is not inherently
malicious must be monitored by the security team.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement temporary network rules, procedures, and segmentation to contain the malware.
  - Stop suspicious processes.
  - Immediately block the identified indicators of compromise (IoCs).
  - Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that
  attackers could use to reinfect the system.
- Remove and block malicious artifacts identified during triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_3047]

```js
event.category:process and event.type:(start or process_started) and
process.name:(bash or dash or ash or zsh or "python*" or "perl*" or "php*") and
process.parent.name:("apache" or "nginx" or "www" or "apache2" or "httpd" or "www-data")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Server Software Component
    * ID: T1505
    * Reference URL: [https://attack.mitre.org/techniques/T1505/](https://attack.mitre.org/techniques/T1505/)

* Sub-technique:

    * Name: Web Shell
    * ID: T1505.003
    * Reference URL: [https://attack.mitre.org/techniques/T1505/003/](https://attack.mitre.org/techniques/T1505/003/)



