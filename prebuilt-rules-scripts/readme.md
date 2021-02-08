# Create prebuilt rule documentation

There are two ways to run the doc-generating scripts, the [simplified method](#simplified-method) or the original
[multi-script method](#existing-multi-script-method)

## Simplified method

Within a virtual environment: 
   * run `pip install requirements-rules.txt`
   * run `python prebuilt-rules-scripts/generate.py generate 7.11.0`

The following still applies:

> After creating the documentation, you need to copy and paste the files in the generated-ascii-files folder to their 
> relevant location in the docs folder, and then manually edit the text of new rules added for the latest release. 
> This includes converting Markdown to AsciiDoc and editing the English.


> Additionally, when the script detects a rule name has been changed, it prints a list of the relevant rule-details 
> files to the terminal. These files will be deleted and printed

Basically, delete the old files for which new ones (the printed files) were generated. If you open the file, you can
see the previous filename


### Details
The previous existing scripts were combined into a single script for simplification and to eliminate the need to make
code changes for every release.

```console
Usage: generate generate [OPTIONS] PACKAGE_VERSION

  Generate pre-built rule documentation.

Options:
  -d, --rules-dir TEXT          Path of rules in Kibana repo
  -l, --local-kibana DIRECTORY  Location of local kibana repo
  -h, --help                    Show this message and exit.
```

So for generating docs for 7.11, run: `python prebuilt-rules-scripts/generate.py generate 7.11.0 -l ../kibana-fork`

The default for `--local-kibana` is `kibana` and so can be passed using `-l` or it will prompt if not detected.

Changelog entries are dependent on whether queries changed in rules. With the old method, this required updating the
`create_documentation.py` script. Now, releases will be tracked in `/prebuilt-rules-scripts/changelog-entries.yml`

## Existing multi-script method

Scripts are use to create the prebuilt rules documentation. Currently, five
scrips are used and they must be run in this order:

1. [`get-release-rules.py`](#get-release-rulespy)
2. [`create-json-from-docs.py`](#create-json-from-docspy)
3. [`update_current_text.py`](#update_current_textpy)
4. [`get-rule-diff.py`](#get-rule-diffpy)
5. [`create_documentation.py`](#create_documentationpy)

After creating the documentation, you need to copy and paste the files in the
`generated-ascii-files` folder to their relevant location in the `docs` folder,
and then manually edit the text of new rules added for the latest release. This
includes converting Markdown to AsciiDoc and editing the English.

*scripts must be run from `prebuilt-rules-scripts` directory*

### `get-release-rules.py`

Creates a JSON file containing all the prebuilt rules for the current release.
For this script to work:

* The `security-docs` and `kibana` local repo folders must reside in the same
  parent folder (sibling folders).
* You must checkout the relevant Kibana branch. For example, if you are
  creating documentation for 7.10, make sure you have checked out the Kibana
  7.10 branch before running the script.
* Update the `releaseVersion` (line 10) variable as required. For example, if
  you are creating docs for 7.10, the variable should be:

   `releaseVersion = "7.10.0"`

The generated JSON file's path name is:

`orig-rules-json-files/<releaseVersion>-prebuilt-rule.json`

Where `<releaseVersion>` is the release number defined in the `releaseVersion`
variable. Once this file is created, do not modify or delete it as it can be
used as a record of prebuilt rules from all releases (with all the other files
in the `orig-rules-json-files` folder).

### `create-json-from-docs.py`

This script creates a JSON file containing the current prebuilt rules
documentation. The is done to avoid updating the formatting or text of rules
that have already been documented in previous releases.

Before running the script, you need to update the `releaseVersion` variable (on
line 12 in the script) to the release number for which you are generating
docs. If you are generating a JSON file for the 7.10 documentation, the
variable should be:

`releaseVersion = "7.10.0"`

### `update_current_text.py`

This script creates a JSON file using the text from previously documented rules
(created with the `create-json-from-docs.py` script) and the (unedited) text for
the new rules added for the coming release. The generated file has an entry for
every prebuilt rule (pre-existing and new ones).

Before running the script, update the `releaseVersion` variable (line 9) to the
release number for which you are generating docs. If you are generating a JSON
file for the 7.10 documentation, the variable should be:

`releaseVersion = "7.10.0"`


### `get-rule-diff.py`

This script (finally) creates the JSON file that is actually used to generate the
documentation. It uses two previously created JSON files to do this: the file
created by the `update_current_text.py` script and the _final_ file created from
the previous time the prebuilt rule documentation was generated.

**IMPORTANT**: The _final_ files reside in the `diff-files/final-files` folder.
These files are generated by this script. They must be kept to ensure the rules'
version histories (rule version numbers and query changes) are documented
accurately. 

Before running the script, these variables must be updated: 

* `releaseVersion` (line 13): The version for which the docs are being generated.
* `previousReleaseVersion` (line 14): The previous version for which docs were
  generated. The variable points the script to the _final_ JSON file used to
  generate the previous release's documentation (in the `diff-files/final-files`
  folder).

For example, if you are generating documentation for 7.10.0:

* `releaseVersion = "7.10.0"` (line 13)
* `previousReleaseVersion = "7.9.0"` (line 14)

### `create_documentation.py`

This script creates the prebuilt rules documentation! It creates `asciidoc`
files for each rule, the ToC (index) file, the version history file, and the
overview (table) file. All files are saved in the `generated-ascii-files`
folder. Once the files are generated, you should be able to just copy and paste
them into the `detections/prebuilt-rules` documentation folder.

Additionally, when the script detects a rule name has been changed, it prints a
list of the relevant _rule-details_ files to the terminal. The text of these
`.asciidoc` files should be reviewed, as the `update_current_text.py` script
does not update the text with the existing documentation when a rule's name has
been changed.

Before running the script, these must be updated:

* `releaseVersion` variable (line 13): The version for which the docs are being
  generated.
* Call to the `addVersionUpdates` function (lines 314): Add a call for the
  new release immediately above the existing ones. For example, if you are
  generating documentation for 7.10.0:

  ```
  addVersionUpdates("7.10.0")
  addVersionUpdates("7.9.0")
  addVersionUpdates("7.8.0")
  addVersionUpdates("7.7.0")
  addVersionUpdates("7.6.2")
  addVersionUpdates("7.6.1")
  ```

  **NOTE**: Only update these lines in the script when at least one rule query
  has been updated.
