"""
Integrate executor/ActionLib/build_action_llm.py to extract actions from Atomic Red Team YAML
files and build the required JSON-format action library.
"""

import sys
import traceback


def reprocess_failed_yamls(api_key: str):
    """Reprocess the failed YAML files listed in debug.md.

    Args:
        api_key: API key

    Returns:
        list: the re-processed action list
    """
    import os
    import glob
    import build_action_llm

    # the failed-file list from debug.md
    failed_files = [
        "T1018.yaml", "T1053.005.yaml", "T1059.001.yaml",
        "T1078.003.yaml", "T1082.yaml", "T1087.002.yaml",
        "T1098.yaml", "T1112.yaml", "T1204.002.yaml",
        "T1218.yaml", "T1219.yaml", "T1547.001.yaml",
        "T1548.002.yaml", "T1552.001.yaml", "T1552.004.yaml",
        "T1555.003.yaml", "T1560.001.yaml", "T1562.004.yaml"
    ]

    # get the template and prompt
    action_template, extraction_prompt = build_action_llm.define_action_llm()
    atomics_dir = os.path.join(os.path.dirname(__file__), "atomics")

    all_actions = []

    for filename in failed_files:
        # locate the file path
        file_pattern = os.path.join(atomics_dir, "**", filename)
        matches = glob.glob(file_pattern, recursive=True)

        if not matches:
            print(f"File not found: {filename}")
            continue

        yaml_path = matches[0]
        print(f"Reprocessing: {filename}")

        try:
            actions = build_action_llm.process_single_yaml(
                yaml_path, api_key, action_template, extraction_prompt
            )

            if actions:
                all_actions.extend(actions)
                print(f"  extracted {len(actions)} action(s)")
            else:
                print(f"  no action extracted")

        except Exception as e:
            print(f"  processing failed: {e}")

    # save results
    if all_actions:
        output_path = os.path.join(os.path.dirname(__file__), "repaired_actions.jsonl")
        import json
        with open(output_path, 'w', encoding='utf-8') as f:
            for action in all_actions:
                f.write(json.dumps(action, ensure_ascii=False) + '\n')

        print(f"Reprocessing complete! Extracted {len(all_actions)} action(s)")
        print(f"Results saved to: {output_path}")

    return all_actions


def main():
    """
    Call the functions from build_action_llm.py to build the action library
    (API key read from the DEEPSEEK_API_KEY env var).
    """
    import os
    # API key read from the environment
    api_key = os.environ.get("DEEPSEEK_API_KEY") or ""

    print("Starting action-library build...")
    print("API key configured, will call the LLM API to process YAML files")

    try:
        # reprocess the failed files listed in debug.md
        print("Reprocessing the failed files from debug.md...")
        actions = reprocess_failed_yamls(api_key)

        print(f"Reprocessing complete! Extracted {len(actions)} action(s)")
        print("Results saved to the repair directory")

    except ImportError as e:
        print(f"Import failed: {e}")
        print("Make sure build_action_llm.py is in the same directory")
        sys.exit(1)
    except Exception as e:
        print(f"Error while building the action library: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
