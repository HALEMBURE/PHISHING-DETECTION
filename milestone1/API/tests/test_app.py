import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from milestone1.API import app as app_module


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test_users.db"
    test_engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=test_engine)

    app_module.Base.metadata.drop_all(bind=test_engine)
    app_module.Base.metadata.create_all(bind=test_engine)
    monkeypatch.setattr(app_module, "SessionLocal", testing_session_local)

    return TestClient(app_module.app)


def signup_and_login(client: TestClient, email: str = "user@example.com", password: str = "StrongPass123"):
    signup_res = client.post(
        "/signup",
        json={"name": "User", "email": email, "password": password},
    )
    assert signup_res.status_code == 200

    login_res = client.post(
        "/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200
    return login_res.json()["access_token"]


def test_login_success_and_failure(client: TestClient):
    token = signup_and_login(client)
    assert isinstance(token, str) and token

    bad_login = client.post(
        "/login",
        json={"email": "user@example.com", "password": "wrong-password"},
    )
    assert bad_login.status_code == 401
    assert bad_login.json()["detail"] == "Invalid credentials"


def test_predict_requires_token(client: TestClient):
    res = client.post("/predict", json={"url": "google.com"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Missing token"


def test_predict_valid_url_with_token(client: TestClient):
    token = signup_and_login(client, email="predict@example.com")
    res = client.post(
        "/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={"url": "https://google.com"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["prediction"] == "safe"
    assert data["source"] == "rule"
    assert data["url"] == "https://google.com"


def test_predict_empty_url_with_token(client: TestClient):
    token = signup_and_login(client, email="empty@example.com")
    res = client.post(
        "/predict",
        headers={"Authorization": f"Bearer {token}"},
        json={"url": "   "},
    )
    assert res.status_code == 400
    assert res.json()["detail"] == "Empty URL"


def test_chat_without_gemini_key_returns_guidance(client: TestClient, monkeypatch):
    token = signup_and_login(client, email="chatnokey@example.com")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    res = client.post(
        "/chat",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "hello"},
    )
    assert res.status_code == 200
    assert "GEMINI_API_KEY" in res.json()["reply"]


def test_chat_with_gemini_key_uses_llm_path(client: TestClient, monkeypatch):
    token = signup_and_login(client, email="chatok@example.com")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    class DummyResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "candidates": [
                    {"content": {"parts": [{"text": "This is an AI reply."}]}}
                ]
            }

    def fake_post(url, headers, json, params, timeout):
        assert "generativelanguage.googleapis.com/v1beta/models/" in url
        assert params["key"] == "test-key"
        assert isinstance(json["contents"], list)
        return DummyResponse()

    monkeypatch.setattr(app_module.httpx, "post", fake_post)

    res = client.post(
        "/chat",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "How do I scan URL?"},
    )
    assert res.status_code == 200
    assert res.json()["reply"] == "This is an AI reply."
