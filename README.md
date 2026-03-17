## PhishGuard AI

URL phishing detection project with:
- `milestone1/API`: FastAPI backend (auth + URL prediction)
- `milestone1/MODEL`: model training scripts/artifacts
- `milestone2`: frontend (login/signup/dashboard)

## Run backend

```powershell
cd milestone1/API
pip install -r ../../requirements.txt
uvicorn app:app --reload
```

Optional environment variables:
- `TOKEN_SECRET`: signing key for access tokens (set this in production)
- `FRONTEND_ORIGINS`: comma-separated allowed frontend origins
- `GEMINI_API_KEY`: enables AI chatbot responses on `/chat`
- `GEMINI_CHAT_MODEL`: chat model name (default `gemini-2.0-flash`)
- `CHAT_MEMORY_TURNS`: short-term per-user memory turns (default `8`)

Example:

```powershell
$env:TOKEN_SECRET="replace-with-strong-secret"
$env:FRONTEND_ORIGINS="http://127.0.0.1:5500,http://localhost:5500"
$env:GEMINI_API_KEY="your-api-key"
uvicorn app:app --reload
```

## Frontend

Serve `milestone2` from a local static server (for example VS Code Live Server) and open:
- `index.html` for login
- `signup.html` for registration

Backend default URL in frontend scripts is `http://127.0.0.1:8000`.
You can override it in the browser console before login:

```js
sessionStorage.setItem("backendUrl", "http://127.0.0.1:8000");
```
