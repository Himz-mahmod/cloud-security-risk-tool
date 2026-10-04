"""
End-to-end checks that drive the real Streamlit app (login, form, pages)
against a temporary SQLite database, using Streamlit's AppTest runner.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from streamlit.testing.v1 import AppTest

APP = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("RISK_TOOL_DB", str(tmp_path / "ui.db"))
    return AppTest.from_file(APP, default_timeout=30).run()


def login(at, username="admin", password="changeme123"):
    at.text_input[0].set_value(username)
    at.text_input[1].set_value(password)
    at.button[0].click()
    return at.run()


def submit_form(at):
    next(b for b in at.button if b.label == "Add Assessment").click()
    return at.run()


def test_login_screen_blocks_everything_else(app):
    assert [t.value for t in app.title] == ["Cloud Security Risk Tool -- Login"]
    assert len(app.sidebar.radio) == 0


def test_wrong_password_is_rejected(app):
    app = login(app, password="wrong-password")
    assert [e.value for e in app.error] == ["Invalid username or password."]


def test_login_then_add_assessment_stores_it_in_the_database(app):
    app = login(app)
    assert not app.exception
    app = submit_form(app)
    assert len(app.success) == 1 and "Added" in app.success[0].value
    # A fresh page load reads the saved row back from SQLite.
    app.sidebar.radio[0].set_value("2. Risk Register")
    app = app.run()
    assert len(app.dataframe) == 1
    assert len(app.dataframe[0].value) == 1


def test_duplicate_submission_is_rejected(app):
    app = login(app)
    app = submit_form(app)
    app = submit_form(app)
    assert len(app.warning) == 1
    assert "already been assessed" in app.warning[0].value


@pytest.mark.parametrize(
    "page", ["2. Risk Register", "3. Priority Dashboard", "4. Assessment Summary"]
)
def test_every_page_renders_with_and_without_data(app, page):
    app = login(app)
    app.sidebar.radio[0].set_value(page)
    assert not app.run().exception  # empty database

    app.sidebar.radio[0].set_value("1. Security Assessment Form")
    app = submit_form(app.run())
    app.sidebar.radio[0].set_value(page)
    assert not app.run().exception  # one row stored
