def set_csrf(client, token="test-csrf-token"):
    with client.session_transaction() as sess:
        sess["_csrf_token"] = token
    return token


def test_healthz(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json["status"] == "ok"


def test_register_login_logout_flow(client):
    csrf = set_csrf(client)
    register = client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "user_one",
            "email": "user1@gmail.com",
            "password": "strong-pass-123",
        },
        follow_redirects=False,
    )
    assert register.status_code == 302

    csrf = set_csrf(client)
    login = client.post(
        "/login",
        data={"csrf_token": csrf, "username": "user_one", "password": "strong-pass-123"},
        follow_redirects=False,
    )
    assert login.status_code == 302
    assert "/dashboard" in login.headers["Location"]

    csrf = set_csrf(client)
    logout = client.post("/logout", data={"csrf_token": csrf}, follow_redirects=False)
    assert logout.status_code == 302
    assert "/login" in logout.headers["Location"]


def test_create_publish_and_delete_quiz(client):
    csrf = set_csrf(client)
    client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "quiz_admin",
            "email": "quiz_admin@gmail.com",
            "password": "strong-pass-123",
        },
        follow_redirects=False,
    )

    csrf = set_csrf(client)
    client.post(
        "/login",
        data={"csrf_token": csrf, "username": "quiz_admin", "password": "strong-pass-123"},
        follow_redirects=False,
    )

    csrf = set_csrf(client)
    create = client.post(
        "/create_quiz",
        data={"csrf_token": csrf, "title": "Security Quiz", "description": "test quiz"},
        follow_redirects=False,
    )
    assert create.status_code == 302
    assert "/add_question/" in create.headers["Location"]
    quiz_id = int(create.headers["Location"].rstrip("/").split("/")[-1])

    csrf = set_csrf(client)
    add_q = client.post(
        f"/add_question/{quiz_id}",
        data={
            "csrf_token": csrf,
            "question": "Which protocol is secure?",
            "options": ["HTTP", "FTP", "SSH", "Telnet"],
            "correct": "2",
        },
        follow_redirects=False,
    )
    assert add_q.status_code == 200

    csrf = set_csrf(client)
    publish = client.post(f"/publish_quiz/{quiz_id}", data={"csrf_token": csrf}, follow_redirects=False)
    assert publish.status_code == 302

    csrf = set_csrf(client)
    delete = client.post(f"/delete_quiz/{quiz_id}", data={"csrf_token": csrf}, follow_redirects=False)
    assert delete.status_code == 302

    dashboard = client.get("/dashboard")
    assert b"Security Quiz" not in dashboard.data
