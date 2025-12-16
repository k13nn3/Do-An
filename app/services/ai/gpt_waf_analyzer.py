# app/services/ai/gpt_waf_analyzer.py
import json
import os
from app.services.ai.gpt_client import ask_gpt

MODEL_NAME = "gpt-5.1"


# ============================================================
# LOAD PROMPT (TÁCH RA FILE)
# ============================================================
PROMPT_PATH = os.path.join(
    os.path.dirname(__file__),
    "prompts",
    "waf_behavior_v14.txt",
)

with open(PROMPT_PATH, "r", encoding="utf-8") as f:
    PROMPT_V14 = f.read()


# ============================================================
# PROMPT BUILDER (GIỮ NGUYÊN LOGIC)
# ============================================================
def _build_prompt(alert_id: str, logs: list) -> str:
    return PROMPT_V14 + json.dumps(
        {"alert_id": alert_id, "logs": logs},
        indent=2,
        ensure_ascii=False,
    )


# ============================================================
# MAIN ANALYZER (GIỮ NGUYÊN HÀNH VI)
# ============================================================
def analyze_waf_with_gpt(alert_id: str, logs: list) -> dict:
    try:
        prompt = _build_prompt(alert_id, logs)

        raw_output = ask_gpt(
            prompt=prompt,
        )

        try:
            return json.loads(raw_output)
        except json.JSONDecodeError:
            return {
                "error": "AI output is not valid JSON",
                "raw_output": raw_output[:4000],
            }

    except Exception as e:
        return {"error": f"AI ERROR: {e}"}
