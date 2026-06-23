"""Backend API tests for Murthy Real Estate."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://realestate-legal-pro.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@murthy.com"
ADMIN_PASSWORD = "Admin@123"


@pytest.fixture(scope="session")
def client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


@pytest.fixture(scope="session")
def admin_session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    r = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, f"Admin login failed: {r.status_code} {r.text}"
    return s


# ---- Auth ----
class TestAuth:
    def test_login_success(self, client):
        r = client.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == ADMIN_EMAIL
        assert data["role"] == "admin"
        assert "id" in data
        # httpOnly cookie set
        assert "access_token" in r.cookies

    def test_login_wrong_password(self, client):
        r = client.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": "WrongPass"})
        assert r.status_code == 401

    def test_me_with_cookie(self, admin_session):
        r = admin_session.get(f"{API}/auth/me")
        assert r.status_code == 200
        assert r.json()["email"] == ADMIN_EMAIL

    def test_me_without_auth(self, client):
        s = requests.Session()
        r = s.get(f"{API}/auth/me")
        assert r.status_code == 401


# ---- Properties (public) ----
class TestProperties:
    def test_list_all(self, client):
        r = client.get(f"{API}/properties")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) >= 6, f"Expected >=6 seeded properties, got {len(data)}"
        # Validate fields
        p = data[0]
        for k in ["id", "title", "type", "price", "location", "featured"]:
            assert k in p

    def test_filter_plot(self, client):
        r = client.get(f"{API}/properties", params={"type": "plot"})
        assert r.status_code == 200
        data = r.json()
        assert len(data) > 0
        assert all(p["type"] == "plot" for p in data)

    def test_filter_featured(self, client):
        r = client.get(f"{API}/properties", params={"featured": "true"})
        assert r.status_code == 200
        data = r.json()
        assert len(data) > 0
        assert all(p["featured"] is True for p in data)

    def test_get_single(self, client):
        all_props = client.get(f"{API}/properties").json()
        pid = all_props[0]["id"]
        r = client.get(f"{API}/properties/{pid}")
        assert r.status_code == 200
        assert r.json()["id"] == pid

    def test_get_invalid_id(self, client):
        r = client.get(f"{API}/properties/invalidid123")
        assert r.status_code == 404

    def test_get_nonexistent(self, client):
        r = client.get(f"{API}/properties/507f1f77bcf86cd799439011")
        assert r.status_code == 404


# ---- Reviews ----
class TestReviews:
    def test_list_reviews(self, client):
        r = client.get(f"{API}/reviews")
        assert r.status_code == 200
        data = r.json()
        assert len(data) >= 6
        names = [d["name"] for d in data]
        assert "Sougandh Ar" in names
        assert "Sundeep Sodhi" in names
        assert "Darsan Krishnan" in names


# ---- Leads ----
class TestLeads:
    def test_create_lead_minimal(self, client):
        payload = {"name": "TEST_LeadOne", "phone": "9876543210"}
        r = client.post(f"{API}/leads", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "TEST_LeadOne"
        assert data["phone"] == "9876543210"
        assert data["status"] == "new"
        assert "id" in data

    def test_create_lead_missing_required(self, client):
        r = client.post(f"{API}/leads", json={"name": "OnlyName"})
        assert r.status_code == 422
        r = client.post(f"{API}/leads", json={"phone": "9999999999"})
        assert r.status_code == 422

    def test_list_leads_unauthenticated(self, client):
        s = requests.Session()
        r = s.get(f"{API}/admin/leads")
        assert r.status_code == 401

    def test_list_leads_authenticated(self, admin_session, client):
        # Create a fresh lead
        unique_phone = "9000000001"
        client.post(f"{API}/leads", json={"name": "TEST_AdminFetch", "phone": unique_phone})
        r = admin_session.get(f"{API}/admin/leads")
        assert r.status_code == 200
        leads = r.json()
        assert any(l["phone"] == unique_phone for l in leads)


# ---- Admin properties CRUD ----
class TestAdminProperties:
    def test_unauth_create(self, client):
        s = requests.Session()
        r = s.post(f"{API}/admin/properties", json={
            "title": "x", "type": "villa", "price": 1, "location": "x", "locality": "x"
        })
        assert r.status_code == 401

    def test_unauth_update(self, client):
        s = requests.Session()
        r = s.put(f"{API}/admin/properties/507f1f77bcf86cd799439011", json={
            "title": "x", "type": "villa", "price": 1, "location": "x", "locality": "x"
        })
        assert r.status_code == 401

    def test_unauth_delete(self, client):
        s = requests.Session()
        r = s.delete(f"{API}/admin/properties/507f1f77bcf86cd799439011")
        assert r.status_code == 401

    def test_create_update_delete_flow(self, admin_session):
        payload = {
            "title": "TEST_AdminProp",
            "type": "flat", "listing": "sale", "price": 5000000,
            "location": "Test Loc", "locality": "TestLoc",
            "bhk": 2, "area_sqft": 1000, "featured": False,
            "description": "test desc", "image_url": "https://example.com/a.jpg",
            "gallery": [],
        }
        r = admin_session.post(f"{API}/admin/properties", json=payload)
        assert r.status_code == 200
        prop = r.json()
        pid = prop["id"]
        assert prop["title"] == "TEST_AdminProp"

        # Verify GET
        r2 = admin_session.get(f"{API}/properties/{pid}")
        assert r2.status_code == 200
        assert r2.json()["title"] == "TEST_AdminProp"

        # Update
        payload["title"] = "TEST_AdminProp_Updated"
        payload["price"] = 6000000
        r3 = admin_session.put(f"{API}/admin/properties/{pid}", json=payload)
        assert r3.status_code == 200
        assert r3.json()["title"] == "TEST_AdminProp_Updated"
        assert r3.json()["price"] == 6000000

        # Verify persistence
        r4 = admin_session.get(f"{API}/properties/{pid}")
        assert r4.json()["title"] == "TEST_AdminProp_Updated"

        # Delete
        r5 = admin_session.delete(f"{API}/admin/properties/{pid}")
        assert r5.status_code == 200

        # Verify gone
        r6 = admin_session.get(f"{API}/properties/{pid}")
        assert r6.status_code == 404
