"""
build_action_llm.py - module for building actions using an LLM
This script uses the LLM's analysis capability, referencing a defined action template, to
generate action JSON strings that meet the requirements.
Main functions:
1. Define the action template: specify the fields and format each action must include
2. Define the extraction prompt
3. Scan and read YAML files from the atomics folder and extract actions
"""

import time
import json

def define_action_llm():
    """Build the config function for using an LLM to extract actions from Atomic Red Team YAML.

    Returns:
        tuple: (action_template, extraction_prompt)
            action_template: dict, the JSON structure template for a single action entry
            extraction_prompt: str, the prompt that guides the LLM to parse YAML and output a JSON array
    """
    # 1. Define the action template (standard JSON schema, for the LLM's reference)
    action_template = {
        "action_id": "TXXXX.XXX-001",           # example value, the LLM replaces it as needed
        "technique_id": "TXXXX.XXX",
        "technique_name": "",
        "display_name": "",
        "platform": "windows/linux/macos",
        "executor": "sh/powershell/cmd/python/manual",
        "description": "",
        "command_template": "",
        "cleanup_template": None,               # null when there is no cleanup command
        "parameters": {
            "param_name": {
                "type": "string/path/integer/boolean",
                "default": None,
                "description": ""
            }
        },
        "preconditions": {
            "required_privilege": "user/admin/system",
            "dependencies": [],
            "ports_needed": []
        },
        "postconditions": {
            "effect": "",
            "files_created": [],
            "persistent": False
        },
        "tags": []
    }

    # 2. Define the detailed extraction prompt
    prompt = """
你是一位红队自动化专家。请将用户提供的YAML技术描述文件转换为标准化的“攻击动作”JSON 数组，用于后续自动化执行。

### 输入说明
用户会提供一段包含 `attack_technique` 和 `atomic_tests` 的 YAML 文本。

### 输出要求
- 为每个 `atomic_tests` 条目生成一个独立的 JSON 对象。
- 将所有对象放入一个 JSON 数组返回。输出必须是**纯 JSON 格式**，不包含任何额外解释或 Markdown 标记。
- 严格遵循下方提供的 JSON Schema，不要遗漏字段。
### 重要提示
- 最重要是command_template、parameters、preconditions和postconditions字段。攻击命令必须使用 {参数名} 作为占位符，参数说明必须清晰。
- 同时，commoned_template必须是有建设性的攻击命令，因为Atomic Red Team的YAML文件中有些命令是只为了测试而无实际攻击意义的，你需要进行改写。

### JSON Schema（每个动作对象必须遵守）
```json
{
  "action_id": "字符串，格式为 {technique_id}-{三位序号}，如 T1048.003-001",
  "technique_id": "字符串，来自 attack_technique",
  "technique_name": "字符串，来自 YAML 的 display_name 或自行根据技术ID推断",
  "display_name": "字符串，来自 atomic_tests 的 name 字段",
  "platform": "字符串，取值 windows/linux/macos。若支持多平台，优先选择主要平台(windows)，或创建多个条目分别表示不同平台",
  "executor": "字符串，取值 sh/powershell/cmd/python/manual，根据 YAML 的 executor.name 确定",
  "description": "字符串，简明描述该动作的目的和行为，可综合 YAML 的 description 字段",
  "command_template": "字符串，用以直接执行的命令模板，使用 {参数名} 作为占位符。若为 manual 类型，可留空字符串并在 description 中保留步骤",
  "cleanup_template": null, // 直接返回null即可，因为我们不需要清理命令
  "parameters": {
    "参数名": {
      "type": "string/path/integer/boolean",或者其他适合的类型，根据参数内容推断
      "default": "默认值或 null",
      "description": "参数说明"
    }
  },
  "preconditions": {
    "required_privilege": "user/admin/system，根据 executor.elevation_required 和命令内容推断",
    "dependencies": ["字符串数组，列出必需的外部工具（如 python3、powershell、rclone.exe）"],这部分需要根据命令内容进行分析，如果命令中调用了某些工具，就把这些工具添加到dependencies数组中
    "ports_needed": [整数数组，命令中监听的端口号，若无可为空数组]
  },
  "postconditions": {
    "effect": "字符串，概括执行后产生的效果（如 starts_http_server、creates_file、exfiltrates_data）",
    "files_created": ["文件路径模板数组，使用参数占位符"],详细描述effect中提到的效果，如果是creates_file，就列出文件路径，如果是starts_http_server，就列出监听的端口等
    "persistent": "布尔值，动作是否留下持久化后门"
  },
  "tags": ["字符串数组，如 exfiltration、credential_access、persistence 等"]
}
"""

    return action_template, prompt


def call_llm_api(api_key: str, prompt: str, api_base: str = "https://api.deepseek.com"):
    """Call the DeepSeek OpenAI-compatible API, with retry

    Args:
        api_key: DeepSeek API key
        prompt: prompt sent to the LLM
        api_base: API base URL, default DeepSeek

    Returns:
        str: text content returned by the LLM

    Raises:
        Exception: API call failed beyond the retry count
    """
    import openai

    max_retries = 3
    base_delay = 2  # seconds

    client = openai.OpenAI(
        api_key=api_key,
        base_url=api_base
    )

    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=4000
            )
            return response.choices[0].message.content
        except Exception as e:
            if attempt == max_retries - 1:
                raise Exception(f"API call failed after {max_retries} retries: {e}")
            delay = base_delay * (2 ** attempt)  # exponential backoff
            print(f"API call failed, retrying in {delay}s (attempt {attempt + 1}/{max_retries}): {e}")
            time.sleep(delay)


def repair_json_string(json_str: str) -> str:
    """Repair unterminated-string errors in a JSON string.
    Mainly fixes unclosed double quotes and brackets.
    """
    if not json_str:
        return json_str

    import json
    try:
        json.loads(json_str)
        return json_str
    except json.JSONDecodeError:
        pass

    fixed = json_str

    # fix unclosed double quotes
    if fixed.count('"') % 2 == 1:
        fixed = fixed + '"'

    # fix unclosed brackets
    if fixed.count('{') > fixed.count('}'):
        fixed = fixed + '}' * (fixed.count('{') - fixed.count('}'))
    if fixed.count('[') > fixed.count(']'):
        fixed = fixed + ']' * (fixed.count('[') - fixed.count(']'))

    try:
        json.loads(fixed)
        return fixed
    except json.JSONDecodeError:
        return json_str


def parse_llm_response(response: str):
    """Parse the JSON-array response returned by the LLM"""
    import json

    response = response.strip()
    if response.startswith("```json"):
        response = response[7:]
    if response.startswith("```"):
        response = response[3:]
    if response.endswith("```"):
        response = response[:-3]
    response = response.strip()

    fixed_response = repair_json_string(response)

    try:
        actions = json.loads(fixed_response)
        if not isinstance(actions, list):
            actions = [actions]
        return actions
    except json.JSONDecodeError as e:
        print(f"JSON parse failed: {e}")
        raise


def process_single_yaml(file_path: str, api_key: str, template: dict, prompt_template: str):
    """Process a single YAML file, call the LLM API to extract actions

    Args:
        file_path: YAML file path
        api_key: API key
        template: action template (for reference)
        prompt_template: prompt template

    Returns:
        list: the extracted action list, possibly empty
    """
    import os
    import yaml

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            yaml_content = f.read()

        # build the full prompt
        full_prompt = f"{prompt_template}\n\nYAML content:\n{yaml_content}"

        # call the LLM API
        llm_response = call_llm_api(api_key, full_prompt)

        # parse the response
        actions = parse_llm_response(llm_response)

        print(f"  {os.path.basename(file_path)}: extracted {len(actions)} action(s)")
        return actions

    except Exception as e:
        print(f"  {os.path.basename(file_path)}: processing failed - {e}")
        return []


def build_action_llm(api_key: str):
    """Build the LLM call to generate action JSON strings using the defined template and prompt.

    Args:
        api_key: DeepSeek API key
    """
    action_template, extraction_prompt = define_action_llm()

    # Call the processing function to implement the described functionality
    return process_yaml_files(api_key, action_template, extraction_prompt)


def process_yaml_files(api_key: str, action_template, extraction_prompt):
    """Process YAML files from the atomics folder, call the LLM API, filter Windows actions, save to JSONL.

    Args:
        api_key: DeepSeek API key
        action_template (dict): Action template structure for validation
        extraction_prompt (str): Prompt for the LLM to extract actions from YAML

    Returns:
        list: the Windows action list
    """
    import os
    import json
    import glob

    # 1. Scan and read YAML files from the atomics folder
    atomics_dir = os.path.join(os.path.dirname(__file__), "atomics")
    yaml_files = glob.glob(os.path.join(atomics_dir, "**", "*.yaml"), recursive=True)

    print(f"Found {len(yaml_files)} YAML files in atomics folder")

    all_actions = []
    processed_count = 0
    failed_count = 0

    # 2. Process each YAML file
    for idx, yaml_file in enumerate(yaml_files, 1):
        print(f"[{idx}/{len(yaml_files)}] Processing {os.path.basename(yaml_file)}...")

        # use process_single_yaml to process a single file
        actions = process_single_yaml(yaml_file, api_key, action_template, extraction_prompt)

        if actions:
            all_actions.extend(actions)
            processed_count += 1
        else:
            failed_count += 1

    print(f"processing done: {processed_count} files succeeded, {failed_count} files failed")

    # 3. Filter to keep only actions with "windows" in the platform field
    windows_actions = []
    for action in all_actions:
        platform = action.get("platform", "").lower()
        if "windows" in platform:
            windows_actions.append(action)
        # note: the LLM may return multi-platform actions; keep Windows only

    print(f"after filtering kept {len(windows_actions)} Windows actions (out of {len(all_actions)} total)")

    # 4. Save results to action_lib.jsonl
    output_file = os.path.join(os.path.dirname(__file__), "action_lib.jsonl")
    with open(output_file, 'w', encoding='utf-8') as f:
        for action in windows_actions:
            f.write(json.dumps(action, ensure_ascii=False) + '\n')

    print(f"saved {len(windows_actions)} actions to {output_file}")
    return windows_actions
