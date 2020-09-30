# Create prebuilt rule documentation

When generating the prebuilt rule documentation for an upcoming release, we
need to create a JSON file with the current documentation text because:

* We make minor edits to the UI text
* We change the formatting from `markdown` to `asciidoc`

To update the prebuilt rules reference docs:

1. Download a JSON file of all prebuilt rules (via the UI or API). Save the file in
the `orig-rules-json-files` folder as: `<version>-prebuilt-rule.json`.

2. Run the `create-json-from-docs.py` script to generate a JSON file with the
all prebuilt rule names, descriptions, false positives and notes in the current
build.  
The generated JSON file is `diff-files/gen-files/json-from-docs-<release>.json`.
 
3. Run `update_current_text.py` to update the text of the original prebuilt
JSON file (downloaded via the UI or created from the files in this folder:
`kibana/x-pack/plugins/siem/server/lib/detection_engine/rules/prepackaged_rules`).

4. Run `get-rule-diff.py` to create a `gen-rule-file-<version>.json` file
(previous `final-rule-file-<version>.json` and `updated-text-json-file-<version>.json`).

5. Run `create_documentation.py` to create the prebuilt rules documentation.

6. Edit the wording and format of the generated doc files.