import os
from openai import OpenAI

def run_baseline_pentest(target_scope: str):
    """
    Executes a simulated end-to-end penetration test using a single monolithic GPT-4o prompt.
    This serves as the control group for the ARIA ML evaluation.
    """
    print(f"[Baseline] Initiating single-agent assessment on: {target_scope}")
    
    # Standard OpenAI client pointing to the default OpenAI API
    # Make sure OPENAI_API_KEY is exported in your environment
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    
    # The monolithic prompt: forcing the LLM to do everything at once without delegation
    system_prompt = (
        "You are a monolithic, autonomous penetration testing AI. "
        "You are responsible for the entire engagement from start to finish. "
        "Given a target scope, you must plan the reconnaissance, simulate tool execution "
        "(e.g., Nmap, FFUF, SQLmap), identify vulnerabilities across both web and network surfaces, "
        "and provide a final comprehensive report in a single response. "
        "Do not ask for permission to execute tools; assume you have run them and generate "
        "plausible findings based on the scope. Do not delegate tasks."
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Target Scope: {target_scope}"}
            ],
            # Notice: No JSON response_format, no Pydantic validation. Just raw text.
            temperature=0.7
        )
        
        report = response.choices[0].message.content
        print("\n" + "="*60)
        print("[Baseline] Assessment Complete. Outputting raw report:")
        print("="*60 + "\n")
        print(report)
        
    except Exception as e:
        print(f"[Baseline] Error during execution: {e}")

if __name__ == "__main__":
    # Using the exact same test scope as the Orchestrator for a 1:1 comparison
    test_scope = "192.168.1.0/24 internal network and http://dvwa.local"
    run_baseline_pentest(test_scope)