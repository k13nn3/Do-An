import os
from openai import OpenAI

# ❌ TUYỆT ĐỐI KHÔNG load_dotenv ở đây

BASE_DIR = os.path.dirname(__file__)
PROMPT_PATH = os.path.join(BASE_DIR, "prompts", "fp_methods.txt")

def load_system_prompt() -> str:
    try:
        with open(PROMPT_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        print("[WARN] Cannot load SYSTEM_FP:", e)
        return "You are a security analysis assistant."

SYSTEM_FP = load_system_prompt()

OPENAI_KEY = os.getenv("OPENAI_API_KEY", "").strip()
if not OPENAI_KEY:
    raise RuntimeError("OPENAI_API_KEY missing (check .env path)")

client = OpenAI(api_key=OPENAI_KEY)

def ask_gpt(prompt: str) -> str:
    res = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-5.1"),
        temperature=0,
        messages=[
            {"role": "system", "content": SYSTEM_FP},
            {"role": "user", "content": prompt}
        ]
    )
    return (res.choices[0].message.content or "").strip()
