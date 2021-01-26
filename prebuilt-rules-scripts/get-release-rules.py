import json
from pathlib import Path

# Creates a JSON file with all the prebuilt rules for the release. Before  
# running this script make sure the correct Kibana branch is checkout out.

releaseVersion = "7.11.0"  # Security app release version - update as required
ROOT = Path(__file__).resolve().parent.parent
KIBANA = ROOT.parent.joinpath('kibana')
DEFAULT_KIBANA_RULES_DIR = str(Path().joinpath('x-pack', 'plugins', 'security_solution', 'server', 'lib',
                                               'detection_engine', 'rules', 'prepackaged_rules'))


def sort_by_name(rule):
    """Helper to sort rule by name"""
    return rule['name']


kibana = str(KIBANA) if KIBANA.exists() else input('Path of local Kibana repo: ').strip()
kibana_resource = Path(kibana).joinpath(DEFAULT_KIBANA_RULES_DIR)
assert kibana_resource.exists(), f'Rules directory not found at {kibana_resource}. Update path'
ruleSourceFolder = ROOT.joinpath(kibana, str(kibana_resource))

rule_dict = []

ruleFiles = ruleSourceFolder.glob('*.json')

for rule_file in ruleFiles:
    with open(rule_file, "r") as ruleFile:
        ruleJSON = json.load(ruleFile)
        rule_dict.append(ruleJSON)

rule_dict = sorted(rule_dict, key=sort_by_name)

rule_dump = ROOT.joinpath("prebuilt-rules-scripts", "orig-rules-json-files",  releaseVersion + "-prebuilt-rule.json")
with open(rule_dump, "w") as fp:
    json.dump(rule_dict, fp, indent=2)
