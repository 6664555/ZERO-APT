"""
llm.py - LLM connection interface
Unified LLM connection supporting deepseek (OpenAI-compatible), claude, and mock (dry-run, no network).

API keys are read only from call args or environment variables
(DEEPSEEK_API_KEY / CLAUDE_API_KEY, see .env.example).
"""

import json
import os


def connect_llm(prompt, api_key=None, LLM_type='deepseek'):
    """Unified LLM interface: pass prompt and api key, return the LLM response as a string."""

    if LLM_type == 'mock':
        return _mock_response(prompt)
    if LLM_type == 'deepseek':
        api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            print("  [LLM error] DEEPSEEK_API_KEY not set (env var or api_key arg)")
            return None
        return call_deepseek_api(api_key=api_key, prompt=prompt)
    elif LLM_type == 'claude':
        api_key = api_key or os.getenv("CLAUDE_API_KEY")
        if not api_key:
            print("  [LLM error] CLAUDE_API_KEY not set (env var or api_key arg)")
            return None
        return call_claude_api(api_key=api_key, prompt=prompt)


def _mock_response(prompt):
    """Dry-run mode: return each module's minimal valid response based on prompt features, no network call."""
    if "MonoReAct" in prompt:
        return json.dumps({"thought": "mock", "action": "finalize", "command": "",
                           "discoveries": {}, "analysis_feedback": "mock: mono-react done"})
    if "senior commander" in prompt:  # Planner
        return json.dumps({"plan": [{"step1": "mock subgoal", "reasoning": "mock", "max_retries": 3}],
                           "current_subgoal": "mock_subgoal", "reasoning": "mock",
                           "goal_achieved": False})
    if "armorer" in prompt:  # Dispatcher P1/P2
        if "AttackPlan" in prompt:
            return json.dumps({"despatcher_plan": "true",
                               "AttackPlan": [{"step1": "whoami", "reasoning": "mock", "max_retries": 3}],
                               "needs_feedback": False, "feedback_reason": ""})
        return json.dumps({"despatcher_plan": "true",
                           "selected_actions": [{"action_id": ["T1053.005-002"], "reasoning": "mock"}],
                           "needs_feedback": False, "feedback_reason": ""})
    if "front-line operator" in prompt:  # Executor
        return json.dumps({"thought": "mock", "action": "finalize", "command": "",
                           "executor": "powershell", "target_ip": "", "target_user": "",
                           "target_password": "", "completed_steps": [],
                           "discoveries": {}, "analysis_feedback": "mock: step completed"})
    if "Judge report writer" in prompt:  # Summary (must be checked before Judge: Summary opens with "You are the Judge")
        return "## Mock CTI Report\n\nDry-run experiment completed."
    if "You are the Judge" in prompt:  # Judge
        return json.dumps({"blue_evidence_score": 40, "winner": "red_win",
                           "reasoning": "mock", "observation": "mock: attacker succeeded",
                           "environment_update": {"files_found": [], "credentials": [],
                                                  "other": {}, "forbidden_actions": []}})
    if "Defender security analyst" in prompt:  # Monitor
        return json.dumps({"has_intrusion": False, "detected_techniques": [],
                           "confidence": 10, "evidence": [], "attack_intent": "",
                           "analysis": "mock: no intrusion"})
    return "mock"


def call_deepseek_api(api_key, prompt):
    """Call the DeepSeek API (OpenAI-compatible format), return the response text."""
    from openai import OpenAI
    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
    try:
        response = client.chat.completions.create(
            model="deepseek-v4-flash",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"  [LLM error] DeepSeek API call failed: {type(e).__name__}: {str(e)[:200]}")
        return None


def call_claude_api(api_key, prompt):
    """Call Claude via an OpenAI-compatible gateway; endpoint and model come from env vars:
    CLAUDE_BASE_URL (required) + CLAUDE_MODEL (default claude-opus-4-6).
    Anthropic's native API is not OpenAI-compatible, so this targets a compatible gateway;
    unconfigured -> explicit error, not silent failure."""
    from openai import OpenAI
    base_url = os.getenv("CLAUDE_BASE_URL", "")
    model = os.getenv("CLAUDE_MODEL", "claude-opus-4-6")
    if not base_url:
        print("  [LLM error] Claude backend needs CLAUDE_BASE_URL (OpenAI-compatible gateway address, see .env.example)")
        return None
    client = OpenAI(api_key=api_key, base_url=base_url)
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"  [LLM error] Claude API call failed: {type(e).__name__}: {str(e)[:200]}")
        return None


def connect_llm_json(prompt, api_key=None, LLM_type='deepseek'):
    """Call the LLM and parse the JSON response. On parse failure, retry once; still failing -> return _raw."""
    text = connect_llm(prompt, api_key, LLM_type)
    if not text:
        return {"_raw": ""}
    result = _parse_json(text)
    if "_raw" not in result:
        return result
    # retry: demand strict JSON output
    retry_prompt = prompt + "\n\n[Important] Output strict JSON only, no markdown fences or other text."
    text2 = connect_llm(retry_prompt, api_key, LLM_type)
    if not text2:
        return {"_raw": text}
    return _parse_json(text2)


def _parse_json(text):
    """Extract JSON from an LLM response; success -> dict, failure -> {"_raw": text}"""
    text_clean = text.strip()
    if "```json" in text_clean:
        text_clean = text_clean.split("```json")[1].split("```")[0].strip()
    elif "```" in text_clean:
        text_clean = text_clean.split("```")[1].split("```")[0].strip()
    try:
        return json.loads(text_clean)
    except json.JSONDecodeError:
        return {"_raw": text}
