def test_root_redirects_to_login(anon):
    r = anon.get("/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login.html")


def test_login_page_served_same_origin(anon):
    r = anon.get("/login.html")
    assert r.status_code == 200 and b"<html" in r.data.lower()


def test_unknown_api_path_returns_json_404(anon):
    r = anon.get("/api/does-not-exist")
    assert r.status_code == 404 and r.get_json()["success"] is False
