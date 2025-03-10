---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/network-traffic-capture-via-cap-net-raw.html
---

# Network Traffic Capture via CAP_NET_RAW [network-traffic-capture-via-cap-net-raw]

Identifies the ability of a process to be able to create RAW and PACKET socket types for the available network namespaces by a non-root user. A malicious process with this capability may exploit routing between hosts, bypass network access controls, and otherwise tamper with host networking if a firewall is not in place to limit the packet types and contents. The CAP_NET_RAW capability allows the process to bind to any address within the available namespaces, which allows network traffic sniffing by a non root user. The rule identifies previously unknown processes executing with CAP_NET_RAW capabilities through the use of the new terms rule type.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*

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
* Tactic: Discovery
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_377]

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
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_627]

```js
event.category:"process" and host.os.type:"linux" and event.type:"start" and event.action:"exec" and process.name:* and
(process.thread.capabilities.effective:"CAP_NET_RAW" or process.thread.capabilities.permitted:"CAP_NET_RAW") and
not user.id:"0"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Network Sniffing
    * ID: T1040
    * Reference URL: [https://attack.mitre.org/techniques/T1040/](https://attack.mitre.org/techniques/T1040/)



