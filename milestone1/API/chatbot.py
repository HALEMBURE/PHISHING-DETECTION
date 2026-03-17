import os
import random
import threading
import time
from typing import Callable

import httpx
from fastapi import Depends, Header, HTTPException, status
from pydantic import BaseModel
from collections import deque


class ChatPayload(BaseModel):
    message: str


class _RetryableGeminiError(Exception):
    pass


_chat_memory_lock = threading.Lock()
_chat_memory: dict[str, deque[dict[str, str]]] = {}
_chat_memory_meta: dict[str, float] = {}

COMMON_QUESTIONS_CACHE = {
    "what is phishing": "Phishing is a scam where attackers try to trick you into giving passwords or data.",
    "how to spot phishing": "Check the sender, URL, spelling, and avoid clicking suspicious links.",
    "is this url safe": "I can help analyze a URL. Please paste the full link.",
    "how to reset password": "Use the login page reset option, or contact support if you are locked out.",
}


def _call_gemini_with_retry(payload: dict, api_key: str, timeout_seconds: float) -> httpx.Response:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{_get_model_name()}:generateContent"
    headers = {"Content-Type": "application/json"}
    backoff = 0.6
    for attempt in range(3):
        try:
            res = httpx.post(
                url,
                headers=headers,
                json=payload,
                params={"key": api_key},
                timeout=timeout_seconds,
            )
            if res.status_code == 429:
                raise _RetryableGeminiError("rate_limited")
            return res
        except _RetryableGeminiError:
            if attempt < 2:
                time.sleep(backoff + random.uniform(0, 0.2))
                backoff *= 2
                continue
            raise
        except (httpx.TimeoutException, httpx.RequestError):
            if attempt < 2:
                time.sleep(backoff + random.uniform(0, 0.2))
                backoff *= 2
                continue
            raise


def _get_model_name() -> str:
    return os.environ.get("GEMINI_CHAT_MODEL", "gemini-1.5-flash").strip()


def _get_timeout_seconds() -> float:
    return float(os.environ.get("GEMINI_TIMEOUT_SECONDS", "30"))


def _get_max_input_chars() -> int:
    return int(os.environ.get("CHAT_MAX_INPUT_CHARS", "1200"))


def _get_memory_turns() -> int:
    return int(os.environ.get("CHAT_MEMORY_TURNS", "8"))


def _get_memory_ttl_seconds() -> int:
    return int(os.environ.get("CHAT_MEMORY_TTL_SECONDS", "7200"))


def _get_rate_window() -> int:
    return int(os.environ.get("CHAT_WINDOW_SECONDS", "60"))


def _get_rate_limit() -> int:
    return int(os.environ.get("CHAT_MAX_ATTEMPTS", "25"))


def _system_prompt() -> str:
    return (
        "You are PhishGuard AI Assistant. Help users with phishing detection, URL safety, "
        "dashboard usage, and account/login issues. Be concise, clear, and practical. "
        "If uncertain, say what you do not know."
    )


def _build_payload(message: str) -> dict:
    return {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": f"System: {_system_prompt()}\nUser: {message}"}],
            }
        ],
        "generationConfig": {
            "maxOutputTokens": 350,
            "temperature": 0.4,
        },
    }


def _normalize_cache_key(message: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() or ch.isspace() else " " for ch in message)
    return " ".join(cleaned.split())


def _cleanup_chat_memory() -> None:
    now = time.time()
    ttl = _get_memory_ttl_seconds()
    with _chat_memory_lock:
        to_remove = [email for email, ts in _chat_memory_meta.items() if now - ts > ttl]
        for email in to_remove:
            _chat_memory.pop(email, None)
            _chat_memory_meta.pop(email, None)


def _get_cached_answer(message: str) -> str | None:
    key = _normalize_cache_key(message)
    return COMMON_QUESTIONS_CACHE.get(key)


def _fallback_reply(message: str) -> str:
    cached = _get_cached_answer(message)
    if cached:
        return cached
    return "I’m temporarily unable to reach the chat service. You can still use scan and history."


def _parse_reply(data: dict) -> str:
    for candidate in data.get("candidates", []):
        content = candidate.get("content", {})
        parts = content.get("parts", [])
        chunks = []
        for part in parts:
            text = part.get("text")
            if isinstance(text, str) and text.strip():
                chunks.append(text.strip())
        if chunks:
            return "\n".join(chunks)
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="Empty response from LLM",
    )


def register_chat_routes(
    app,
    get_current_user: Callable,
    check_rate_limit: Callable,
    client_identity: Callable,
    db_session_factory: Callable,
    ChatMessage,
):
    def _store_message(email: str, role: str, content: str):
        db = db_session_factory()
        try:
            db.add(ChatMessage(user_email=email, role=role, content=content, ts=int(time.time())))
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    @app.get("/chat/history")
    def chat_history(current_user: dict = Depends(get_current_user)):
        email = str(current_user.get("sub") or "anonymous").lower()
        _cleanup_chat_memory()
        db = db_session_factory()
        try:
            rows = (
                db.query(ChatMessage)
                .filter(ChatMessage.user_email == email)
                .order_by(ChatMessage.id.asc())
                .all()
            )
            history = [{"role": r.role, "content": r.content, "ts": r.ts} for r in rows]
            return {"history": history}
        finally:
            db.close()

    @app.post("/chat")
    def chat(
        payload: ChatPayload,
        current_user: dict = Depends(get_current_user),
        x_forwarded_for: str | None = Header(default=None),
    ):
        _cleanup_chat_memory()
        message = (payload.message or "").strip()
        if not message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty message",
            )
        if len(message) > _get_max_input_chars():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Message too long (max {_get_max_input_chars()} characters)",
            )

        check_rate_limit(
            endpoint="chat",
            identity=client_identity(x_forwarded_for, "unknown", str(current_user.get("sub") or "")),
            window_seconds=_get_rate_window(),
            max_attempts=_get_rate_limit(),
        )

        api_key = os.environ.get("GEMINI_API_KEY", "").strip()
        if not api_key:
            return {
                "reply": _fallback_reply(message)
            }

        email = str(current_user.get("sub") or "anonymous").lower()
        payload = _build_payload(message)
        with _chat_memory_lock:
            history = _chat_memory.setdefault(email, deque(maxlen=_get_memory_turns() * 2))
            messages = [{"role": "system", "content": _system_prompt()}]
            messages.extend(list(history))
            messages.append({"role": "user", "content": message})
            _chat_memory_meta[email] = time.time()

        try:
            payload = {
                "contents": [
                    {
                        "role": "user",
                        "parts": [{"text": "\n".join([f"{m['role'].title()}: {m['content']}" for m in messages])}],
                    }
                ],
                "generationConfig": {
                    "maxOutputTokens": 350,
                    "temperature": 0.4,
                },
            }
            res = _call_gemini_with_retry(payload, api_key, _get_timeout_seconds())
            if res.status_code >= 400:
                detail = "LLM request failed"
                try:
                    err_json = res.json()
                    detail = err_json.get("error", {}).get("message") or detail
                except Exception:
                    pass
                lowered = detail.lower()
                if "quota" in lowered or "exceeded" in lowered or "resource_exhausted" in lowered:
                    return {"reply": _fallback_reply(message)}
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=detail,
                )
            data = res.json()
            reply = _parse_reply(data)
            with _chat_memory_lock:
                history.append({"role": "user", "content": message, "ts": time.time()})
                history.append({"role": "assistant", "content": reply, "ts": time.time()})
                _chat_memory_meta[email] = time.time()
            _store_message(email, "user", message)
            _store_message(email, "assistant", reply)
            return {"reply": reply}
        except HTTPException:
            raise
        except _RetryableGeminiError:
            reply = _fallback_reply(message)
            _store_message(email, "user", message)
            _store_message(email, "assistant", reply)
            return {"reply": reply}
        except Exception:
            reply = _fallback_reply(message)
            _store_message(email, "user", message)
            _store_message(email, "assistant", reply)
            return {"reply": reply}
