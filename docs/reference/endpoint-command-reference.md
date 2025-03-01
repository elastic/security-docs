---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/endpoint-command-ref.html
  - https://www.elastic.co/guide/en/serverless/current/security-endpoint-command-ref.html
---

# Endpoint command reference [endpoint-command-ref]

This page lists the commands for management and troubleshooting of {{elastic-endpoint}}, the installed component that performs {{elastic-defend}}'s threat monitoring and prevention.

::::{note}
* {{elastic-endpoint}} is not added to the `PATH` system variable, so you must prepend the commands with the full OS-dependent path:

    * On Windows: `"C:\Program Files\Elastic\Endpoint\elastic-endpoint.exe"`
    * On macOS: `/Library/Elastic/Endpoint/elastic-endpoint`
    * On Linux: `/opt/Elastic/Endpoint/elastic-endpoint`

* You must run the commands with elevated privileges—using `sudo` to run as the root user on Linux and macOS, or running as Administrator on Windows.

::::


The following {{elastic-endpoint}} commands are available:

* [diagnostics](#elastic-endpoint-diagnostics-command)
* [help](#elastic-endpoint-help-command)
* [inspect](#elastic-endpoint-inspect-command)
* [install](#elastic-endpoint-install-command)
* [memorydump](#elastic-endpoint-memorydump-command)
* [run](#elastic-endpoint-run-command)
* [send](#elastic-endpoint-send-command)
* [status](#elastic-endpoint-status-command)
* [test](#elastic-endpoint-test-command)
* [top](#elastic-endpoint-top-command)
* [uninstall](#elastic-endpoint-uninstall-command)
* [version](#elastic-endpoint-version-command)

Each of the commands accepts the following logging options:

* `--log [stdout,stderr,debugview,file]`
* `--log-level [error,info,debug]`


## elastic-endpoint diagnostics [elastic-endpoint-diagnostics-command]

Gather diagnostics information from {{elastic-endpoint}}. This command produces an archive that contains:

* `version.txt`: Version information
* `elastic-endpoint.yaml`: Current policy
* `metrics.json`: Metrics document
* `policy_response.json`: Last policy response
* `system_info.txt`: System information
* `analysis.txt`: Diagnostic analysis report
* `logs` directory: Copy of {{elastic-endpoint}} log files


### Example [_example]

```shell
elastic-endpoint diagnostics
```


## elastic-endpoint help [elastic-endpoint-help-command]

Show help for the available commands.


### Example [_example_2]

```shell
elastic-endpoint help
```


## elastic-endpoint inspect [elastic-endpoint-inspect-command]

Show the current {{elastic-endpoint}} configuration.


### Example [_example_3]

```shell
elastic-endpoint inspect
```


## elastic-endpoint install [elastic-endpoint-install-command]

Install {{elastic-endpoint}} as a system service.

::::{note}
We do not recommend installing {{elastic-endpoint}} using this command. {{elastic-endpoint}} is managed by {{agent}} and cannot function as a standalone service. Therefore, there is no separate installation package for {{elastic-endpoint}}, and it should not be installed independently.
::::



### Options [_options]

`--resources <string>`
:   Specify a resources `.zip` file to be used during the installation. This option is required.

`--upgrade`
:   Upgrade the existing installation.


### Example [_example_4]

```shell
elastic-endpoint install --upgrade --resources endpoint-security-resources.zip
```


## elastic-endpoint memorydump [elastic-endpoint-memorydump-command]

Save a memory dump of the {{elastic-endpoint}} service.


### Options [_options_2]

`--compress`
:   Compress the saved memory dump.

`--timeout <duration>`
:   Specify the memory collection timeout, in seconds; the default is 60 seconds.


### Example [_example_5]

```shell
elastic-endpoint memorydump --timeout 120
```


## elastic-endpoint run [elastic-endpoint-run-command]

Run `elastic-endpoint` as a foreground process if no other instance is already running.


### Example [_example_6]

```shell
elastic-endpoint run
```


## elastic-endpoint send [elastic-endpoint-send-command]

Send the requested document to the {{stack}}.


### Subcommands [_subcommands]

`metadata`
:   Send an off-schedule metrics document to the {{stack}}.


### Example [_example_7]

```shell
elastic-endpoint send metadata
```


## elastic-endpoint status [elastic-endpoint-status-command]

Retrieve the current status of the running {{elastic-endpoint}} service. The command also returns the last known status of {{agent}}.


### Options [_options_3]

`--output`
:   Control the level of detail and formatting of the information. Valid values are:

    * `human`: Returns limited information when {{elastic-endpoint}}'s status is `Healthy`. If any policy actions weren’t successfully applied, the relevant details are displayed.
    * `full`: Always returns the full status information.
    * `json`: Always returns the full status information.



### Example [_example_8]

```shell
elastic-endpoint status --output json
```


## elastic-endpoint test [elastic-endpoint-test-command]

Perform the requested test.


### Subcommands [_subcommands_2]

`output`
:   Test whether {{elastic-endpoint}} can connect to remote resources.


### Example [_example_9]

```shell
elastic-endpoint test output
```


### Example output [_example_output]

```txt
Testing output connections

Using proxy:

Elasticsearch server: https://example.elastic.co:443
        Status: Success

Global artifact server: https://artifacts.security.elastic.co
        Status: Success

Fleet server: https://fleet.example.elastic.co:443
        Status: Success
```


## elastic-endpoint top [elastic-endpoint-top-command]

Show a breakdown of the executables that triggered {{elastic-endpoint}} CPU usage within the last interval. This displays which {{elastic-endpoint}} features are resource-intensive for a particular executable.

::::{note}
The meaning and output of this command are similar, but not identical, to the POSIX `top` command. The `elastic-endpoint top` command aggregates multiple processes by executable. The utilization values aren’t measured by the OS scheduler but by a wall clock in user mode. The output helps identify outliers causing excessive CPU utilization, allowing you to fine-tune the {{elastic-defend}} policy and exception lists in your deployment.
::::



### Options [_options_4]

`--interval <duration>`
:   Specify the data collection interval, in seconds; the default is 5 seconds.

`--limit <number>`
:   Specify the number of updates to collect; by default, data is collected until interrupted by **Ctrl+C**.

`--normalized`
:   Normalize CPU usage values to a total of 100% across all CPUs on multi-CPU systems.


### Example [_example_10]

```shell
elastic-endpoint top --interval 10 --limit 5
```


### Example output [_example_output_2]

```txt
| PROCESS                                            | OVERALL | API | BHVR | DIAG BHVR | DNS | FILE   | LIB | MEM SCAN | MLWR  | NET | PROC | RANSOM | REG |
=============================================================================================================================================================
| MSBuild.exe                                        |  3146.0 | 0.0 |  0.8 |       0.7 | 0.0 | 2330.9 | 0.0 |    226.2 | 586.9 | 0.0 |  0.0 |    0.4 | 0.0 |
| Microsoft.Management.Services.IntuneWindowsAgen... |    30.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.2 |     29.8 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| svchost.exe                                        |    27.3 | 0.0 |  0.1 |       0.1 | 0.0 |    0.4 | 0.2 |      0.0 |  26.6 | 0.0 |  0.0 |    0.0 | 0.0 |
| LenovoVantage-(LenovoServiceBridgeAddin).exe       |     0.1 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.1 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| Lenovo.Modern.ImController.PluginHost.Device.exe   |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| msedgewebview2.exe                                 |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| msedge.exe                                         |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| powershell.exe                                     |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| WmiPrvSE.exe                                       |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| Lenovo.Modern.ImController.PluginHost.Device.exe   |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| Slack.exe                                          |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| uhssvc.exe                                         |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| explorer.exe                                       |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| taskhostw.exe                                      |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| Widgets.exe                                        |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| elastic-endpoint.exe                               |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |
| sppsvc.exe                                         |     0.0 | 0.0 |  0.0 |       0.0 | 0.0 |    0.0 | 0.0 |      0.0 |   0.0 | 0.0 |  0.0 |    0.0 | 0.0 |

Endpoint service (16 CPU): 113.0% out of 1600%

Collecting data.  Press Ctrl-C to cancel
```


#### Column abbreviations [_column_abbreviations]

* `API`: Event Tracing for Windows (ETW) API events
* `AUTH`: Authentication events
* `BHVR`: Malicious behavior protection
* `CRED`: Credential access events
* `DIAG BHVR`: Diagnostic malicious behavior protection
* `DNS`: DNS events
* `FILE`: File events
* `LIB`: Library load events
* `MEM SCAN`: Memory scanning
* `MLWR`: Malware protection
* `NET`: Network events
* `PROC`: Process events
* `PROC INJ`: Process injection
* `RANSOM`: Ransomware protection
* `REG`: Registry events


## elastic-endpoint uninstall [elastic-endpoint-uninstall-command]

Uninstall {{elastic-endpoint}}.

::::{note}
{{elastic-endpoint}} is managed by {{agent}}. To remove {{elastic-endpoint}} from the target machine permanently, remove the {{elastic-defend}} integration from the {{fleet}} policy. The [elastic-agent uninstall](docs-content://solutions/security/configure-elastic-defend/uninstall-elastic-agent.md) command also uninstalls {{elastic-endpoint}}; therefore, in practice, the `elastic-endpoint uninstall` command is used only to troubleshoot broken installations.
::::



### Options [_options_5]

`--uninstall-token <string>`
:   Provide the uninstall token. The token is required if [agent tamper protection](docs-content://solutions/security/configure-elastic-defend/prevent-elastic-agent-uninstallation.md) is enabled.


### Example [_example_11]

```shell
elastic-endpoint uninstall --uninstall-token 12345678901234567890123456789012
```


## elastic-endpoint version [elastic-endpoint-version-command]

Show the version of {{elastic-endpoint}}.


### Example [_example_12]

```shell
elastic-endpoint version
```
