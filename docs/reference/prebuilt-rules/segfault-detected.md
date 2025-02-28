---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/segfault-detected.html
---

# Segfault Detected [segfault-detected]

Monitors kernel logs for segfault messages. A segfault, or segmentation fault, is an error that occurs when a program tries to access a memory location that it’s not allowed to access, typically leading to program termination. A segfault can be an indication of malicious behavior if it results from attempts to exploit buffer overflows or other vulnerabilities in software to execute arbitrary code or disrupt its normal operation.

**Rule type**: query

**Rule indices**:

* logs-system.syslog-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Rule Type: BBR

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_576]

**Setup**

This rule requires data coming in from one of the following integrations: - Filebeat

**Filebeat Setup**

Filebeat is a lightweight shipper for forwarding and centralizing log data. Installed as an agent on your servers, Filebeat monitors the log files or locations that you specify, collects log events, and forwards them either to Elasticsearch or Logstash for indexing.

**The following steps should be executed in order to add the Filebeat for the Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/filebeat/setup-repositories.md).
* To run Filebeat on Docker follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-docker.md).
* To run Filebeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/filebeat/running-on-kubernetes.md).
* For quick start information for Filebeat refer to the [helper guide](https://www.elastic.co/guide/en/beats/filebeat/8.11/filebeat-installation-configuration.html).
* For complete Setup and Run Filebeat information refer to the [helper guide](beats://reference/filebeat/setting-up-running.md).

**Rule Specific Setup Note**

* This rule requires the Filebeat System Module to be enabled.
* The system module collects and parses logs created by the system logging service of common Unix/Linux based distributions.
* To run the system module of Filebeat on Linux follow the setup instructions in the [helper guide](beats://reference/filebeat/filebeat-module-system.md).


## Rule query [_rule_query_970]

```js
host.os.type:linux and event.dataset:"system.syslog" and process.name:kernel and message:segfault
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)



