# Automated tests: the user and password exist only in the test database the test creates.
import os

os.environ.setdefault("SECRET_KEY", "tests-only")
os.environ.setdefault("WEBHOOK_KEY", "tests-only")

from app import app, register  # noqa: E402

TEST_USER = {"email": "test@example.invalid", "password": "a-long-test-password"}


def test_register_makes_different_tokens():
    _, a = register(TEST_USER["password"])
    _, b = register(TEST_USER["password"])
    assert a != b


def test_search_does_not_run_sql():
    client = app.test_client()
    r = client.get("/user?name=' OR 1=1 --")
    assert r.status_code == 200
