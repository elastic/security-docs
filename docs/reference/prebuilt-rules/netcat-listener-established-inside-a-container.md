---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/netcat-listener-established-inside-a-container.html
---

# Netcat Listener Established Inside A Container [netcat-listener-established-inside-a-container]

This rule detects an established netcat listener running inside a container. Netcat is a utility used for reading and writing data across network connections, and it can be used for malicious purposes such as establishing a backdoor for persistence or exfiltrating data.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Data Source: Elastic Defend for Containers
* Domain: Container
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_569]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Netcat Listener Established Inside A Container**

Netcat is a versatile networking tool used for reading and writing data across network connections, often employed for legitimate purposes like debugging and network diagnostics. However, adversaries can exploit Netcat to establish unauthorized backdoors or exfiltrate data from containers. The detection rule identifies suspicious Netcat activity by monitoring process events within containers, focusing on specific arguments that indicate a listening state, which is a common trait of malicious use. This proactive detection helps mitigate potential threats by flagging unusual network behavior indicative of compromise.

**Possible investigation steps**

* Review the container ID associated with the alert to identify the specific container where the Netcat listener was established. This can help in understanding the context and potential impact.
* Examine the process name and arguments to confirm the presence of Netcat and its listening state. Look for arguments like "-l", "--listen", "-p", or "--source-port" to verify the listener setup.
* Check the parent process of the Netcat instance to determine how it was initiated. This can provide insights into whether it was started by a legitimate application or a potentially malicious script.
* Investigate the network connections associated with the container to identify any unusual or unauthorized connections that may indicate data exfiltration or communication with a command and control server.
* Analyze the container’s recent activity and logs to identify any other suspicious behavior or anomalies that could be related to the Netcat listener, such as unexpected file modifications or other process executions.
* Assess the container’s security posture and configuration to determine if there are any vulnerabilities or misconfigurations that could have been exploited to establish the Netcat listener.

**False positive analysis**

* Development and testing activities within containers may trigger the rule if Netcat is used for legitimate debugging or network diagnostics. Users can create exceptions for specific container IDs or process names associated with known development environments.
* Automated scripts or tools that utilize Netcat for routine network checks or health monitoring might be flagged. To mitigate this, users can whitelist these scripts by identifying their unique process arguments or execution patterns.
* Containers running network services that rely on Netcat for legitimate communication purposes could be mistakenly identified. Users should document and exclude these services by specifying their container IDs and associated process arguments.
* Security tools or monitoring solutions that incorporate Netcat for legitimate scanning or testing purposes may cause false positives. Users can manage this by excluding these tools based on their known process names and arguments.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized access or data exfiltration. This can be done by stopping the container or disconnecting it from the network.
* Conduct a thorough review of the container’s logs and process history to identify any unauthorized access or data transfers that may have occurred.
* Remove any unauthorized Netcat binaries or scripts found within the container to eliminate the backdoor.
* Rebuild the container from a known good image to ensure no residual malicious artifacts remain.
* Update container images and underlying host systems with the latest security patches to mitigate vulnerabilities that could be exploited by similar threats.
* Implement network segmentation and firewall rules to restrict unauthorized outbound connections from containers, reducing the risk of data exfiltration.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other containers or systems within the environment.


## Rule query [_rule_query_610]

```js
process where container.id: "*" and event.type== "start"
and event.action in ("fork", "exec") and
(
process.name:("nc","ncat","netcat","netcat.openbsd","netcat.traditional") or
/*account for tools that execute utilities as a subprocess, in this case the target utility name will appear as a process arg*/
process.args: ("nc","ncat","netcat","netcat.openbsd","netcat.traditional")
) and (
          /* bind shell to echo for command execution */
          (process.args:("-*l*", "--listen", "-*p*", "--source-port") and process.args:("-c", "--sh-exec", "-e", "--exec", "echo","$*"))
          /* bind shell to specific port */
          or process.args:("-*l*", "--listen", "-*p*", "--source-port")
          )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)



