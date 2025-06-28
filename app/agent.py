from llama_cpp import Llama
from .config import MODEL_PATH, CONTEXT_WINDOW

llm = Llama(
    model_path=MODEL_PATH,
    n_ctx=CONTEXT_WINDOW
)

def generate_ai_response(log: str) -> str:
    prompt = f"""
You are Red-Hunter, a cybersecurity assistant AI.
Your job is to analyze the following log, detect the threat type, explain it, and suggest a fix.

Always end your message with:
"— Red-Hunter, built by Safwen Amaira, Software Engineering Student at ESPRIT (esprit.tn)."

Log: {log}
"""
    response = llm(prompt, max_tokens=200)
    return response["choices"][0]["text"].strip()
