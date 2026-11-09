import io, os, importlib
import pytest

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTVAULT_DB", str(tmp_path/"test.sqlite3"))
    monkeypatch.setenv("TRUSTVAULT_DATA", str(tmp_path/"files"))
    monkeypatch.setenv("TRUSTVAULT_SECRET", "test-secret-key-123456789012345")
    monkeypatch.setenv("TRUSTVAULT_AUDIT_KEY", "test-audit-key-123456789012345")
    import app as appmod
    importlib.reload(appmod)
    appmod.init_db()
    conn=appmod.sqlite3.connect(appmod.DB_PATH)
    from werkzeug.security import generate_password_hash
    from datetime import datetime, timezone
    for username,password,role in [
        ("owner_a","OwnerPassword!123","owner"),
        ("viewer_a","ViewerPassword!123","viewer"),
        ("viewer_b","ViewerPassword!123","viewer"),
        ("admin_a","AdminPassword!123","admin")]:
        conn.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                     (username,generate_password_hash(password),role,datetime.now(timezone.utc).isoformat()))
    conn.commit(); conn.close()
    appmod.app.config.update(TESTING=True)
    return appmod.app.test_client(), appmod

def login(client, username, password):
    with client.session_transaction() as s: token=s.get("_csrf")
    if not token:
        client.get("/login")
        with client.session_transaction() as s: token=s.get("_csrf")
    return client.post("/login",data={"_csrf":token,"username":username,"password":password},follow_redirects=True)

def token(client):
    with client.session_transaction() as s: return s.get("_csrf")

def upload_as_owner(client):
    login(client,"owner_a","OwnerPassword!123")
    return client.post("/upload",data={"_csrf":token(client),"category":"Contracts",
        "file":(io.BytesIO(b"%PDF-1.4\\nhello"),"contract.pdf")},content_type="multipart/form-data",follow_redirects=True)

def get_doc_id(appmod):
    c=appmod.sqlite3.connect(appmod.DB_PATH)
    row=c.execute("SELECT id FROM documents").fetchone(); c.close()
    return row[0]

def test_other_user_cannot_view_or_download(client):
    c,m=client; upload_as_owner(c); did=get_doc_id(m)
    c.get("/logout")
    login(c,"viewer_b","ViewerPassword!123")
    assert c.get(f"/document/{did}").status_code==404
    assert c.get(f"/document/{did}/download").status_code==404

def test_viewer_cannot_upload(client):
    c,m=client
    login(c,"viewer_a","ViewerPassword!123")
    r=c.post("/upload",data={"_csrf":token(c),"category":"x",
      "file":(io.BytesIO(b"%PDF-1.4\\nx"),"x.pdf")},content_type="multipart/form-data")
    assert r.status_code==403

def test_grant_and_revoke_immediate(client):
    c,m=client; upload_as_owner(c); did=get_doc_id(m)
    c.post(f"/document/{did}/grant",data={"_csrf":token(c),"user_id":2,"permission":"read"})
    c.get("/logout"); login(c,"viewer_a","ViewerPassword!123")
    assert c.get(f"/document/{did}/download").status_code==200
    c.get("/logout"); login(c,"owner_a","OwnerPassword!123")
    c.post(f"/document/{did}/revoke",data={"_csrf":token(c),"user_id":2})
    c.get("/logout"); login(c,"viewer_a","ViewerPassword!123")
    assert c.get(f"/document/{did}/download").status_code==404

def test_viewer_cannot_grant_or_delete(client):
    c,m=client; upload_as_owner(c); did=get_doc_id(m)
    c.get("/logout"); login(c,"viewer_b","ViewerPassword!123")
    assert c.post(f"/document/{did}/grant",data={"_csrf":token(c),"user_id":2,"permission":"read"}).status_code==403
    assert c.post(f"/document/{did}/delete",data={"_csrf":token(c)}).status_code==403

def test_invalid_file_signature_rejected(client):
    c,m=client; login(c,"owner_a","OwnerPassword!123")
    r=c.post("/upload",data={"_csrf":token(c),"category":"x",
      "file":(io.BytesIO(b"not a pdf"),"bad.pdf")},content_type="multipart/form-data",follow_redirects=True)
    assert b"does not match" in r.data
    assert m.sqlite3.connect(m.DB_PATH).execute("SELECT COUNT(*) FROM documents").fetchone()[0]==0
