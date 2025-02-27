---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-potential-linux-hack-tool-launched.html
---

# Potential Linux Hack Tool Launched [prebuilt-rule-8-17-3-potential-linux-hack-tool-launched]

Monitors for the execution of different processes that might be used by attackers for malicious intent. An alert from this rule should be investigated further, as hack tools are commonly used by blue teamers and system administrators as well.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_864]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either "Traditional Endpoints" or "Cloud Workloads".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_4910]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
process.name in~ (
  // exploitation frameworks
  "crackmapexec", "msfconsole", "msfvenom", "sliver-client", "sliver-server", "havoc",
  // network scanners (nmap left out to reduce noise)
  "zenmap", "nuclei", "netdiscover", "legion",
  // web enumeration
  "gobuster", "dirbuster", "dirb", "wfuzz", "ffuf", "whatweb", "eyewitness",
  // web vulnerability scanning
  "wpscan", "joomscan", "droopescan", "nikto",
  // exploitation tools
  "sqlmap", "commix", "yersinia",
  // cracking and brute forcing
  "john", "hashcat", "hydra", "ncrack", "cewl", "fcrackzip", "rainbowcrack",
  // host and network
  "linenum.sh", "linpeas.sh", "pspy32", "pspy32s", "pspy64", "pspy64s", "binwalk", "evil-winrm",
  "linux-exploit-suggester-2.pl", "linux-exploit-suggester.sh", "panix.sh"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)



