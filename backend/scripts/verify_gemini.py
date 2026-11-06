"""Verification script for Google Gemini API integration in SwarmGuard.

Tests connectivity, model configuration, and response generation safely
without exposing API keys or secrets in logs.

Usage:
    python backend/scripts/verify_gemini.py
"""
import os
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.adapters.gemini_adapter import GeminiAdapter, mask_secret
from app.config import get_settings


def main() -> int:
    print("=" * 65)
    print("  SWARMGUARD - Google Gemini API Connectivity Verification")
    print("=" * 65)

    settings = get_settings()
    api_key = os.getenv("GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL") or settings.gemini_model

    print(f"Target Model:  {model}")
    print(f"API Key Found: {'YES' if api_key else 'NO'}")
    print(f"Masked Key:    {mask_secret(api_key)}")
    print("-" * 65)

    if not api_key:
        print("[!] GEMINI_API_KEY is not set.")
        print("    To configure your key:")
        print("    1. Copy .env.example to .env (or backend/.env)")
        print("    2. Add: GEMINI_API_KEY=your_actual_api_key_here")
        print("    3. (Optional) Add: GEMINI_MODEL=gemini-3.5-flash-lite")
        print("    4. Re-run this verification script.")
        print("=" * 65)
        return 1

    print("[*] Probing Gemini API with minimal test prompt...")
    result = GeminiAdapter.check_connection(api_key=api_key, model=model, timeout=30.0)

    if result.get("connected"):
        print("[+] SUCCESS: Gemini API connection verified successfully!")
        print(f"    Model:     {result['model']}")
        print(f"    Response:  '{result.get('response')}'")
        print(f"    Status:    {result['status'].upper()}")
        print("=" * 65)
        return 0
    else:
        print("[-] FAILED: Could not complete Gemini API request.")
        print(f"    Error:     {result.get('error')}")
        print("    Check that your key is valid and has Gemini API enabled in Google AI Studio.")
        print("=" * 65)
        return 1


if __name__ == "__main__":
    sys.exit(main())
