import json
from pathlib import Path

releaseVersion = "7.11.0"  # Security app release version - update as required
ROOT = Path(__file__).resolve().parent.parent


def sort_by_name(rule):
    '''
    Helper to sort rule by name'''
    return rule['name']


# Path to latest prebuilt rules JSON file
rule_dump = ROOT.joinpath("prebuilt-rules-scripts", "orig-rules-json-files",  releaseVersion + "-prebuilt-rule.json")
with open(rule_dump, "r") as source:
    currentText = json.load(source)

# Path to JSON file generated from existing documentation

diff_file = ROOT.joinpath("prebuilt-rules-scripts/diff-files/gen-files/json-from-docs-" + releaseVersion + ".json")
with open(diff_file, "r") as source:
    updatedText = json.load(source)

for rule in currentText:
    for newText in updatedText:
        if rule['name'] == newText['name']:
            rule['description'] = newText['description']
            if 'false_positives' in newText and 'false_positives' in rule:
                rule['false_positives'][0] = newText['false_positives'][0]
            if 'note' in newText:
                rule['note'] = newText['note']

# Output file with updated text from the documentation for previously existing
# prebuilt rules. New rules are unchanged.

with open(diff_file, "w") as fp:
    json.dump(currentText, fp, indent=2)
