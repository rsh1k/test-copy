import json, os, sys
from anthropic import Anthropic

# VERSION 2.0 - HAIKU ONLY
def run_analysis():
    print("--- RUNNING SCRIPT VERSION 2.0 (HAIKU) ---")
    MODEL = "claude-3-haiku-20240307"
    print(f"DEBUG: Target Model is {MODEL}")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    client = Anthropic(api_key=api_key)

    try:
        # We are intentionally using a very small request to test the connection
        message = client.messages.create(
            model=MODEL,
            max_tokens=10,
            messages=[{"role": "user", "content": "Hello"}]
        )
        print("Success! Connection verified.")
        print(f"Claude said: {message.content[0].text}")
    except Exception as e:
        print(f"STILL FAILING: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_analysis()
