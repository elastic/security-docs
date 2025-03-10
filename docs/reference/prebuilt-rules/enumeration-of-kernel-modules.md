---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/enumeration-of-kernel-modules.html
---

# Enumeration of Kernel Modules [enumeration-of-kernel-modules]

Loadable Kernel Modules (or LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. This identifies attempts to enumerate information about a kernel module.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

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
* Tactic: Discovery
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_300]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Enumeration of Kernel Modules**

Loadable Kernel Modules (LKMs) enhance a Linux kernel’s capabilities dynamically, without requiring a system reboot. Adversaries may exploit this by enumerating kernel modules to gather system information or identify vulnerabilities. The detection rule identifies suspicious enumeration activities by monitoring specific processes and arguments associated with module listing commands, while excluding benign parent processes to reduce false positives.

**Possible investigation steps**

* Review the process details in the alert to identify the specific command used for kernel module enumeration, such as lsmod, modinfo, kmod with list argument, or depmod with --all or -a arguments.
* Examine the process parent name to ensure it is not one of the benign processes listed in the exclusion criteria, such as mkinitramfs, dracut, or systemd, which could indicate a false positive.
* Investigate the user account associated with the process to determine if the activity aligns with expected behavior or if it might indicate unauthorized access.
* Check the timing and frequency of the enumeration activity to assess whether it is part of routine system operations or an anomaly that warrants further investigation.
* Correlate the alert with other security events or logs from the same host to identify any additional suspicious activities or patterns that could suggest a broader attack or compromise.

**False positive analysis**

* System maintenance tools like mkinitramfs and dracut may trigger the rule during legitimate operations. To handle this, ensure these processes are included in the exclusion list to prevent unnecessary alerts.
* Backup and recovery processes such as rear and casper can cause false positives when they interact with kernel modules. Verify these processes are part of the exclusion criteria to avoid misidentification.
* Disk management and storage tools like lvm2 and mdadm might enumerate kernel modules as part of their normal function. Add these to the exclusion list to reduce false positives.
* Virtualization and container management tools such as vz-start and overlayroot may also enumerate modules. Confirm these are excluded to maintain focus on genuine threats.
* Kernel update and management utilities like dkms and kernel-install can trigger alerts during updates. Ensure these are accounted for in the exclusion list to minimize false alarms.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement by the adversary.
* Terminate any suspicious processes identified by the detection rule, specifically those involving unauthorized use of lsmod, modinfo, kmod, or depmod commands.
* Conduct a thorough review of recent system logs and process execution history to identify any unauthorized access or changes made to the system.
* Restore the system from a known good backup if any unauthorized modifications to kernel modules or system files are detected.
* Update and patch the system to the latest security standards to mitigate any known vulnerabilities that could be exploited through kernel modules.
* Implement stricter access controls and monitoring for kernel module management, ensuring only authorized personnel can load or unload modules.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_192]

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


## Rule query [_rule_query_313]

```js
event.category:process and host.os.type:linux and event.type:start and event.action:(exec or exec_event) and (
 (process.name:(lsmod or modinfo)) or
 (process.name:kmod and process.args:list) or
 (process.name:depmod and process.args:(--all or -a))
) and
not (
  process.parent.name:(
    mkinitramfs or cryptroot or framebuffer or dracut or jem or thin-provisioning-tools or readykernel or lvm2 or
    vz-start or iscsi or mdadm or ovalprobes or bcache or plymouth or dkms or overlayroot or weak-modules or zfs or
    systemd or whoopsie-upload-all or kdumpctl or apport-gtk or casper or rear or kernel-install or newrelic-infra
  ) or
  process.parent.executable:/var/lib/dpkg/info/linux-modules*-generic.post*
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



