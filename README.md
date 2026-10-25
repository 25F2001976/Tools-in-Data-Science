# GA5 Incident Agent API

A FastAPI service implementing the `/v2/incidents` API, receipt-driven retries/approval handling, SQLite persistence, and OTLP JSON spans.

## Deploy
1. Create a GitHub repository and upload these files.
2. Create a Render Web Service from the repository using the included `render.yaml`/Dockerfile.
3. Attach a persistent disk mounted at `/data` (the included Render blueprint requests one).
4. Set environment variables:
   - `AIPIPE_TOKEN` = your AI Pipe token (keep secret; never put it in code)
   - `AIPIPE_BASE_URL` = `https://aipipe.org/openrouter/v1` (or your compatible OpenAI-style endpoint)
   - `AI_MODEL` = `openai/gpt-4.1-nano` (or another model available to your token)
5. Wait until `/health` returns `{"ok":true}`. Submit the service base URL, e.g. `https://YOUR-SERVICE.onrender.com`, without a path/query/fragment.

## Local run
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
set AIPIPE_TOKEN=...   # PowerShell: $env:AIPIPE_TOKEN="..."
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Important
- Never commit a token or any sensitive incident content.
- The grader supplies authoritative receipts; this service does not call the catalog tools directly.
- Keep the Render disk mounted at `/data`, or configure `DB_PATH` to a persistent writable path.
- Test the deployment before spending a Check; the task states that only the last check should be used for Save.
