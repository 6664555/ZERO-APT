"""
action_sharpen.py - action-refinement module
The original action library - action_lib.jsonl - was extracted from Atomic Red Team YAML files,
but most of its actions lack obvious attack intent (they are just test commands).
This module refines the original library and produces a new library - Rat_lib.jsonl
where every action carries post-exploitation (after gaining a foothold) attack intent, with an
explicit attack description, attack preconditions, and attack postconditions.
Most importantly, each has an intent-bearing command template that directly guides the attacker
to execute the action in the post-exploitation phase.
"""


def define_sharpened_action():
    """Define the template and prompt for the sharpened actions.

    Returns:
        tuple: (action_template, extraction_prompt)
            action_template: dict, the JSON structure template for a single action entry
            extraction_prompt: str, the prompt that guides the LLM to parse YAML and output a JSON array
    """
    # 1. Define the action template (standard JSON schema, for the LLM's reference)
    action_template = {
        "action_id": "TXXXX.XXX-001",           # example value, the LLM replaces it as needed
        "technique_id": "TXXXX.XXX",
        "technique_name": "",           # usually fixed, since it is the technique name matching the ATT&CK technique ID
        "display_name": "",         # the LLM refines and rewrites this
        "platform": "windows/linux/macos",        # actually always windows
        "executor": "sh/powershell/cmd/python/manual",
        "description": "",  # the LLM refines and rewrites this, highlighting attack intent and behavior
        "command_template": "",     # the LLM refines this; must be an intent-bearing, feasible command template using {param} placeholders
        "cleanup_template": None,               # null when there is no cleanup command
        "parameters": {     # the LLM derives a parameter list from the command content, with type/default/description per parameter, matching the {param} placeholders in command_template
            "param_name": {
                "type": "string/path/integer/boolean",
                "default": None,
                "description": "",
            }
        },
        "preconditions": {  # the LLM derives attack preconditions from executor.elevation_required and the command content; they must be obtainable via commands
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
你是一位红队自动化专家。请基于提供的json动作列表，对现有动作进行逐条改写。

### 任务要求
1. **不要筛选动作**：为每个输入动作生成一个改写版本，不要合并、分类或抛弃任何动作
2. **增强攻击意图**：将原始测试命令改写为具有明确攻击意图的后渗透动作
3. **确保可行性**：命令必须能在后渗透阶段直接执行，实现攻击效果
4. **返回格式规范性**：输出的 JSON 数组长度必须与输入动作数量完全一致，顺序一一对应。

### 改写指南
- **display_name**：提炼简明的动作名称，突出攻击意图
- **description**：详细说明攻击意图和行为，强调后渗透实用性
- **command_template**：提供可直接执行的命令模板，使用{参数名}占位符
- **parameters**：为每个参数提供类型、默认值和获取方法说明，参数的默认值仅在运行时环境可稳定获取且不受具体主机配置影响时给出（如环境变量 $env:TEMP）。若非通用路径或依赖主机配置，请将默认值设为"无，靠探索获取"，并在 description 中说明获取方法。
- **preconditions**：根据命令内容分析所需权限、依赖工具和端口
- **postconditions**：描述攻击效果、生成文件和持久性
- **tags**：添加相关攻击标签（如exfiltration、credential_access等）
- **preconditions.dependencies**： 仅包含实际需要的外部工具或运行环境（如 powershell、python3）。关于参数是否已通过探索获得的约束，请放在 parameters 字段的 description 中说明前置条件，而不是写在 dependencies 里。

### 示例（改写前后对比）
**原始动作**：
```json
{
  "action_id": "T1001.002-001",
  "technique_id": "T1001.002",
  "technique_name": "Data Obfuscation via Steganography",
  "display_name": "Steganographic Tarball Embedding",
  "platform": "windows",
  "executor": "powershell",
  "description": "通过隐写术将包含敏感数据的TAR文件嵌入到图片文件中，实现数据混淆和隐蔽传输。",
  "command_template": "$imageBytes = [System.IO.File]::ReadAllBytes('{image_file}'); $tarBytes = [System.IO.File]::ReadAllBytes('{tar_file}'); $combinedBytes = $imageBytes + $tarBytes; [System.IO.File]::WriteAllBytes('{new_image_file}', $combinedBytes)",
  "cleanup_template": null,
  "parameters": {
    "image_file": {"type": "path", "default": "PathToAtomicsFolder\\\\T1001.002\\\\bin\\\\T1001.002.jpg", "description": "用于隐藏数据的原始图片文件路径。"},
    "tar_file": {"type": "path", "default": "$env:PUBLIC\\\\Downloads\\\\T1001.002.tarz", "description": "包含敏感数据的TAR文件路径。"},
    "new_image_file": {"type": "path", "default": "$env:PUBLIC\\\\Downloads\\\\T1001.002New.jpg", "description": "生成的、嵌入了TAR文件的新图片文件路径。"}
  },
  "preconditions": {"required_privilege": "admin", "dependencies": ["powershell"], "ports_needed": []},
  "postconditions": {"effect": "creates_file", "files_created": ["{new_image_file}"], "persistent": false},
  "tags": ["exfiltration", "defense-evasion"]
}
```

**改写后动作**：
```json
{
  "action_id": "T1001.002-001",
  "technique_id": "T1001.002",
  "technique_name": "Data Obfuscation via Steganography",
  "display_name": "隐蔽数据外泄：通过图片隐写术隐藏敏感文件",
  "platform": "windows",
  "executor": "powershell",
  "description": "在后渗透阶段，将窃取的敏感数据（如凭证文件、配置文件）打包为TAR文件，并嵌入到普通图片中，实现隐蔽外泄。攻击者可将生成的图片通过正常渠道传输，规避安全检测。",
  "command_template": "$stolenData = Get-ChildItem -Path '{source_dir}' -Recurse -Include *.txt,*.config,*.xml | Compress-Archive -DestinationPath '{tar_path}' -Force; $img = [System.IO.File]::ReadAllBytes('{cover_image}'); $data = [System.IO.File]::ReadAllBytes('{tar_path}'); $combined = $img + $data; [System.IO.File]::WriteAllBytes('{output_image}', $combined); Remove-Item -Path '{tar_path}' -Force",
  "cleanup_template": null,
  "parameters": {
    "source_dir": {"type": "path", "default": "无，靠探索获取", "description": "包含敏感数据的源目录，可通过命令`Get-ChildItem -Path C:\\\\Users -Directory | Select-Object Name`获取用户名列表;或可通过动作T1083-002获取到的目录路径"},
    "cover_image": {"type": "path", "default": "无，靠探索获取", "description": "用于隐藏数据的封面图片，通常使用系统自带的图片文件，可通过命令`Get-ChildItem -Path $env:PUBLIC\\\\Pictures\\\\ -Include *.jpg`获取常见图片路径；或可通过动作T1083-002获取到的图片文件路径"},
    "output_image": {"type": "path", "default": "$env:PUBLIC\\\\Pictures\\\\wallpaper.jpg", "description": "生成的隐藏数据图片路径，应选择常见图片位置避免怀疑"},
    "tar_path": {"type": "path", "default": "$env:TEMP\\\\data.tar", "description": "临时TAR文件路径，执行后会自动删除"}
  },
  "preconditions": {
    "dependencies": ["powershell", "environment_discovery_completed"],  # 需要powershell环境和完成环境侦察以获取参数
    "required_privilege": "user",
    "ports_needed": []
  },
  "postconditions": {
    "effect": "exfiltrates_data",
    "files_created": ["{output_image}"],
    "persistent": false
  },
  "tags": ["exfiltration", "defense-evasion", "data-theft"]
}
```

### 输出要求
- 为每个输入动作生成一个独立的JSON对象
- 将所有对象放入一个JSON数组返回
- 输出必须是**纯JSON格式**，不包含任何额外解释或Markdown标记
- 严格遵循示例中的字段格式，不要遗漏任何字段
- 所有字符串内部的双引号必须转义为 \"，换行符转义为 \n，确保输出是合法的 JSON，不得出现未转义的控制字符。
- 参数应由红队智能体在交互过程中通过侦察动作动态填充，而非静态绑定，并像示例一样提供获取参数的说明

### JSON字段说明
- **action_id, technique_id, technique_name, platform, executor**：直接继承原始值
- **display_name**：提炼简明的攻击动作名称
- **description**：突出攻击意图和在后渗透阶段的实用性
- **command_template**：可直接执行的命令模板，使用{参数名}占位符
- **cleanup_template**：始终返回null
- **parameters**：为命令中的每个参数提供详细说明
- **preconditions**：分析命令所需的权限、依赖工具和端口
- **postconditions**：描述攻击效果、生成文件和持久性
- **tags**：添加相关攻击标签

请基于以上指南和示例，对输入动作进行逐条改写。
"""

    return action_template, prompt

def sharpen_actions(api_key: str):
    """Rewrite and refine the original action library using the defined template and prompt, producing a new library.
    When reading the jsonl: per the prompt above, feed all action entries belonging to one attack technique to the
    LLM as a whole for rewriting, rather than processing each action entry separately.
    Args:
        api_key: API key, used to call the LLM API
    """
    import json
    import requests
    import time
    import os
    from typing import List, Dict, Any
    def _read_jsonl_file(file_path: str) -> List[Dict[str, Any]]:
        """Read a JSONL file, return the action list"""
        actions = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        action = json.loads(line)
                        actions.append(action)
                    except json.JSONDecodeError as e:
                        print(f"  warning: line {line_num} JSON parse failed: {e}")
        except IOError as e:
            print(f"error: cannot read file {file_path}: {e}")
            raise
        return actions
    def _group_by_technique(actions: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group actions by technique_id"""
        groups = {}
        for action in actions:
            tech_id = action.get('technique_id', 'UNKNOWN')
            if tech_id not in groups:
                groups[tech_id] = []
            groups[tech_id].append(action)
        return groups
    def _build_llm_prompt(base_prompt: str, technique_id: str, actions: List[Dict[str, Any]]) -> str:
        """Build the LLM prompt"""
        actions_json = json.dumps(actions, ensure_ascii=False, indent=2)
        prompt = f"""{base_prompt}
请基于以下动作列表进行改写，这些动作都属于技术ID: {technique_id}
动作列表:
```json
{actions_json}
```
请输出纯JSON数组:"""
        return prompt
    def _call_llm_api(api_key: str, prompt: str, max_retries: int = 3) -> str:
        """Call the DeepSeek API"""
        url = "https://api.deepseek.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        payload = {
            "model": "deepseek-v4-flash",  # use the deepseek-v4 model
            "messages": [
                {"role": "system", "content": "你是一位红队自动化专家，严格按照要求输出纯JSON格式。"},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.05,  # low temperature for consistency
            "max_tokens": 20000
        }
        for attempt in range(max_retries):
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=60)
                response.raise_for_status()
                result = response.json()
                return result["choices"][0]["message"]["content"]
            except requests.exceptions.RequestException as e:
                print(f"  API call failed (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # exponential backoff
                else:
                    raise
        return ""
    def _parse_llm_response(response_text: str) -> List[Dict[str, Any]]:
        """Parse the JSON array returned by the LLM"""
        try:
            response_text = response_text.strip()
            start_idx = response_text.find('[')
            end_idx = response_text.rfind(']')
            if start_idx == -1 or end_idx == -1:
                raise ValueError("no JSON array found")
            json_str = response_text[start_idx:end_idx+1]
            result = json.loads(json_str)
            if not isinstance(result, list):
                raise ValueError("LLM did not return a JSON array")
            return result
        except (json.JSONDecodeError, ValueError) as e:
            print(f"  parsing LLM response failed: {e}")
            print(f"  response text: {response_text[:200]}...")
            return []
    def _process_technique_group(api_key: str, base_prompt: str,
                                technique_id: str, actions: List[Dict[str, Any]], retry = 0) -> List[Dict[str, Any]]:
        """Process all actions in one technique group"""
        if not actions:
            return []
        prompt = _build_llm_prompt(base_prompt, technique_id, actions)
        print(f"  calling LLM API...")
        response_text = _call_llm_api(api_key, prompt)
        sharpened_actions = _parse_llm_response(response_text)
        if not sharpened_actions and retry < 2:
            print(f"    parse failed, retrying ({retry+1})...")
            time.sleep(2)
            return _process_technique_group(api_key, base_prompt, technique_id, actions, retry+1)
        return sharpened_actions
    def _write_jsonl_file(file_path: str, actions: List[Dict[str, Any]]):
        """Write a JSONL file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                for action in actions:
                    json_line = json.dumps(action, ensure_ascii=False)
                    f.write(json_line + '\n')
            print(f"  wrote {len(actions)} actions to {file_path}")
        except IOError as e:
            print(f"error: cannot write file {file_path}: {e}")
            raise
    input_file = os.path.join(os.path.dirname(__file__), "action_lib.jsonl")
    output_file = os.path.join(os.path.dirname(__file__), "Rat_lib.jsonl")
    print(f"starting action-library rewrite...")
    print(f"input file: {input_file}")
    print(f"output file: {output_file}")
    print("step 1: reading the original action library...")
    original_actions = _read_jsonl_file(input_file)
    print(f"read {len(original_actions)} original actions")
    print("step 2: grouping by attack technique...")
    grouped_actions = _group_by_technique(original_actions)
    print(f"grouping done, {len(grouped_actions)} attack techniques total")
    action_template, base_prompt = define_sharpened_action()
    sharpened_actions = []
    total_groups = len(grouped_actions)
    for idx, (technique_id, actions) in enumerate(grouped_actions.items(), 1):
        print(f"processing technique group {idx}/{total_groups}: {technique_id} ({len(actions)} actions)")
        try:
            result = _process_technique_group(api_key, base_prompt, technique_id, actions)
            if result:
                sharpened_actions.extend(result)
                print(f"  rewritten {len(result)} action(s)")
            else:
                print(f"  no valid rewrite result for this group")
        except Exception as e:
            print(f"  processing failed: {e}")
            continue
    print(f"step 5: writing the output file...")
    _write_jsonl_file(output_file, sharpened_actions)
    print(f"done! rewrote {len(sharpened_actions)} actions")
    print(f"output file: {output_file}")
