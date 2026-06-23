from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Annotated, Any

import bcrypt
import jwt
from bson import ObjectId
from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, ConfigDict, EmailStr, BeforeValidator

# ---------------- Config ----------------
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_MINUTES = 60 * 12  # 12h for admin convenience
REFRESH_TOKEN_TTL_DAYS = 7

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("murthy")


# ---------------- Helpers ----------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


def create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_TTL_DAYS),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def set_auth_cookies(response: Response, access: str, refresh: str) -> None:
    response.set_cookie(
        "access_token", access, httponly=True, secure=False, samesite="lax",
        max_age=ACCESS_TOKEN_TTL_MINUTES * 60, path="/",
    )
    response.set_cookie(
        "refresh_token", refresh, httponly=True, secure=False, samesite="lax",
        max_age=REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60, path="/",
    )


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload["sub"]
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["id"] = str(user["_id"])
        user.pop("_id", None)
        user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------- Models ----------------
def _id_to_str(v: Any) -> str:
    if isinstance(v, ObjectId):
        return str(v)
    return str(v)


PyObjectId = Annotated[str, BeforeValidator(_id_to_str)]


class UserOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: EmailStr
    name: str
    role: str


class LoginInput(BaseModel):
    email: EmailStr
    password: str


class PropertyIn(BaseModel):
    title: str
    title_kn: Optional[str] = ""
    type: str  # villa | plot | flat | commercial
    listing: str = "sale"  # sale | rent
    price: float  # in INR
    location: str
    locality: str
    bhk: Optional[int] = None
    area_sqft: Optional[float] = None
    description: str = ""
    description_kn: Optional[str] = ""
    image_url: str = ""
    gallery: List[str] = Field(default_factory=list)
    featured: bool = False
    status: str = "available"  # available | sold


class PropertyOut(PropertyIn):
    id: str
    created_at: str


class LeadIn(BaseModel):
    name: str
    phone: str
    email: Optional[EmailStr] = None
    interest: Optional[str] = ""
    budget: Optional[str] = ""
    message: Optional[str] = ""
    property_id: Optional[str] = None


class LeadOut(LeadIn):
    id: str
    created_at: str
    status: str = "new"


# ---------------- App ----------------
app = FastAPI(title="Murthy Real Estate API")
api = APIRouter(prefix="/api")


@api.get("/")
async def root():
    return {"message": "Murthy Real Estate API", "ok": True}


# ---------- Auth ----------
@api.post("/auth/login", response_model=UserOut)
async def login(payload: LoginInput, response: Response):
    email = payload.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    user_id = str(user["_id"])
    access = create_access_token(user_id, email)
    refresh = create_refresh_token(user_id)
    set_auth_cookies(response, access, refresh)
    return UserOut(id=user_id, email=email, name=user.get("name", "Admin"), role=user.get("role", "admin"))


@api.post("/auth/logout")
async def logout(response: Response, _: dict = Depends(get_current_user)):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"ok": True}


@api.get("/auth/me", response_model=UserOut)
async def me(current: dict = Depends(get_current_user)):
    return UserOut(id=current["id"], email=current["email"], name=current.get("name", "Admin"), role=current.get("role", "admin"))


# ---------- Properties (public) ----------
def _prop_doc_to_out(doc: dict) -> PropertyOut:
    out = {
        "id": str(doc["_id"]),
        "title": doc.get("title", ""),
        "title_kn": doc.get("title_kn", ""),
        "type": doc.get("type", "villa"),
        "listing": doc.get("listing", "sale"),
        "price": float(doc.get("price", 0)),
        "location": doc.get("location", ""),
        "locality": doc.get("locality", ""),
        "bhk": doc.get("bhk"),
        "area_sqft": doc.get("area_sqft"),
        "description": doc.get("description", ""),
        "description_kn": doc.get("description_kn", ""),
        "image_url": doc.get("image_url", ""),
        "gallery": doc.get("gallery", []) or [],
        "featured": bool(doc.get("featured", False)),
        "status": doc.get("status", "available"),
        "created_at": doc.get("created_at", datetime.now(timezone.utc).isoformat()),
    }
    return PropertyOut(**out)


@api.get("/properties", response_model=List[PropertyOut])
async def list_properties(
    type: Optional[str] = None,
    locality: Optional[str] = None,
    listing: Optional[str] = None,
    featured: Optional[bool] = None,
    limit: int = 50,
):
    q: dict = {}
    if type:
        q["type"] = type
    if locality:
        q["locality"] = locality
    if listing:
        q["listing"] = listing
    if featured is not None:
        q["featured"] = featured
    docs = await db.properties.find(q).sort("created_at", -1).to_list(length=limit)
    return [_prop_doc_to_out(d) for d in docs]


@api.get("/properties/{prop_id}", response_model=PropertyOut)
async def get_property(prop_id: str):
    try:
        doc = await db.properties.find_one({"_id": ObjectId(prop_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Property not found")
    if not doc:
        raise HTTPException(status_code=404, detail="Property not found")
    return _prop_doc_to_out(doc)


# ---------- Properties (admin) ----------
@api.post("/admin/properties", response_model=PropertyOut)
async def create_property(payload: PropertyIn, _: dict = Depends(get_current_user)):
    doc = payload.model_dump()
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.properties.insert_one(doc)
    doc["_id"] = res.inserted_id
    return _prop_doc_to_out(doc)


@api.put("/admin/properties/{prop_id}", response_model=PropertyOut)
async def update_property(prop_id: str, payload: PropertyIn, _: dict = Depends(get_current_user)):
    try:
        oid = ObjectId(prop_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Property not found")
    update = payload.model_dump()
    res = await db.properties.find_one_and_update({"_id": oid}, {"$set": update}, return_document=True)
    if not res:
        raise HTTPException(status_code=404, detail="Property not found")
    return _prop_doc_to_out(res)


@api.delete("/admin/properties/{prop_id}")
async def delete_property(prop_id: str, _: dict = Depends(get_current_user)):
    try:
        oid = ObjectId(prop_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Property not found")
    res = await db.properties.delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Property not found")
    return {"ok": True}


# ---------- Leads ----------
def _lead_doc_to_out(doc: dict) -> LeadOut:
    return LeadOut(
        id=str(doc["_id"]),
        name=doc.get("name", ""),
        phone=doc.get("phone", ""),
        email=doc.get("email"),
        interest=doc.get("interest", ""),
        budget=doc.get("budget", ""),
        message=doc.get("message", ""),
        property_id=doc.get("property_id"),
        status=doc.get("status", "new"),
        created_at=doc.get("created_at", datetime.now(timezone.utc).isoformat()),
    )


async def send_lead_email_mocked(lead: dict) -> None:
    """MOCKED email dispatch. Logs to console until RESEND_API_KEY is provided."""
    target = os.environ.get("LEAD_EMAIL", "info@murthyrealestate.com")
    if not os.environ.get("RESEND_API_KEY"):
        logger.info(
            "[MOCKED EMAIL] New lead → %s | name=%s phone=%s interest=%s budget=%s msg=%s",
            target, lead.get("name"), lead.get("phone"),
            lead.get("interest"), lead.get("budget"), lead.get("message"),
        )
        return
    # Real Resend call would go here when key is provided.
    logger.info("[EMAIL] Would dispatch to %s via Resend", target)


@api.post("/leads", response_model=LeadOut)
async def create_lead(payload: LeadIn):
    doc = payload.model_dump()
    doc["status"] = "new"
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.leads.insert_one(doc)
    doc["_id"] = res.inserted_id
    await send_lead_email_mocked(doc)
    return _lead_doc_to_out(doc)


@api.get("/admin/leads", response_model=List[LeadOut])
async def list_leads(_: dict = Depends(get_current_user)):
    docs = await db.leads.find().sort("created_at", -1).to_list(length=500)
    return [_lead_doc_to_out(d) for d in docs]


@api.put("/admin/leads/{lead_id}/status")
async def update_lead_status(lead_id: str, status: str, _: dict = Depends(get_current_user)):
    try:
        oid = ObjectId(lead_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Lead not found")
    res = await db.leads.update_one({"_id": oid}, {"$set": {"status": status}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Lead not found")
    return {"ok": True}


# ---------- Reviews (public + seeded) ----------
@api.get("/reviews")
async def list_reviews():
    docs = await db.reviews.find().to_list(length=50)
    out = []
    for d in docs:
        out.append({
            "id": str(d["_id"]),
            "name": d.get("name", ""),
            "rating": d.get("rating", 5),
            "text": d.get("text", ""),
            "text_kn": d.get("text_kn", ""),
            "source": d.get("source", "Google"),
            "verified": d.get("verified", False),
        })
    return out


# Register router
app.include_router(api)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- Seeding ----------------
SEED_REVIEWS = [
    {"name": "Sougandh Ar", "rating": 5, "verified": True, "source": "Google",
     "text": "Extraordinary support rendered by Murthy sir for the sale of our plot. End to end support in each aspect and very fair and transparent communication. Highly recommended."},
    {"name": "Sundeep Sodhi", "rating": 5, "verified": True, "source": "Google",
     "text": "Mr. Murthy is one of the best real estate consultant I met in Bangalore. He understood my requirement and shortlisted many properties and showed me around."},
    {"name": "Darsan Krishnan", "rating": 5, "verified": True, "source": "Google",
     "text": "Mr Murthy recently helped with my property sale in the Hennur area. Since I’m based abroad, there was a lot of paperwork that had to be taken care of locally. Mr Murthy helped with all of it efficiently. Very professional, courteous and experienced."},
    {"name": "Anitha Rao", "rating": 5, "verified": False, "source": "Client",
     "text": "Smooth transactions and humble staff. Murthy sir guided us through every legal formality of our flat purchase in Hennur. Pleasant experience throughout."},
    {"name": "Rakesh Iyer", "rating": 5, "verified": False, "source": "Client",
     "text": "As an NRI buying a site near Bagalur, I needed someone trustworthy. Murthy sir handled documentation, registration and even the bank coordination."},
    {"name": "Lakshmi Narayan", "rating": 5, "verified": False, "source": "Client",
     "text": "Honest, transparent and fair pricing. We sold our plot through Murthy Real Estate and got a great deal without any hidden costs."},
]

SEED_PROPERTIES = [
    {
        "title": "Luxury 4BHK Villa in Hennur",
        "title_kn": "ಹೆಣ್ಣೂರಿನಲ್ಲಿ ಐಷಾರಾಮಿ 4BHK ವಿಲ್ಲಾ",
        "type": "villa", "listing": "sale", "price": 32500000,
        "location": "Hennur Bagalur Road, Bengaluru", "locality": "Hennur",
        "bhk": 4, "area_sqft": 3200, "featured": True, "status": "available",
        "description": "A premium 4 BHK villa with private garden, modern Italian kitchen, double-height living room and a quiet community. Walking distance to Manyata Tech Park feeder road.",
        "description_kn": "ಪ್ರೀಮಿಯಂ 4 BHK ವಿಲ್ಲಾ, ಖಾಸಗಿ ಉದ್ಯಾನ, ಆಧುನಿಕ ಅಡುಗೆಮನೆ ಮತ್ತು ಶಾಂತ ಸಮುದಾಯ.",
        "image_url": "https://images.pexels.com/photos/16573669/pexels-photo-16573669.jpeg",
        "gallery": [
            "https://images.pexels.com/photos/16573669/pexels-photo-16573669.jpeg",
            "https://images.pexels.com/photos/31737842/pexels-photo-31737842.jpeg",
        ],
    },
    {
        "title": "Premium Residential Plot near Bagalur",
        "title_kn": "ಬಾಗಲೂರು ಬಳಿ ಪ್ರೀಮಿಯಂ ವಸತಿ ಪ್ಲಾಟ್",
        "type": "plot", "listing": "sale", "price": 8500000,
        "location": "Bagalur, North Bengaluru", "locality": "Bagalur",
        "bhk": None, "area_sqft": 2400, "featured": True, "status": "available",
        "description": "BMRDA approved 2400 sqft east-facing plot in a gated layout. Clear title, all approvals in place. Ideal for villa construction.",
        "description_kn": "BMRDA ಅನುಮೋದಿತ 2400 ಚದರ ಅಡಿ ಪೂರ್ವಮುಖ ಪ್ಲಾಟ್, ಗೇಟೆಡ್ ಲೇಔಟ್.",
        "image_url": "https://images.unsplash.com/photo-1694011772133-dc4b3ff3f24f",
        "gallery": ["https://images.unsplash.com/photo-1694011772133-dc4b3ff3f24f"],
    },
    {
        "title": "Spacious 3BHK Flat in BDS Garden",
        "title_kn": "BDS ಗಾರ್ಡನ್‌ನಲ್ಲಿ ವಿಶಾಲ 3BHK ಫ್ಲ್ಯಾಟ್",
        "type": "flat", "listing": "sale", "price": 11500000,
        "location": "BDS Garden, Hennur", "locality": "Hennur",
        "bhk": 3, "area_sqft": 1650, "featured": True, "status": "available",
        "description": "Light filled 3 BHK apartment with two balconies, covered parking, lift, 24x7 security and a clubhouse. Ready to move in.",
        "description_kn": "2 ಬಾಲ್ಕನಿಗಳು, ಪಾರ್ಕಿಂಗ್, ಲಿಫ್ಟ್, ಕ್ಲಬ್‌ಹೌಸ್‌ನೊಂದಿಗೆ ಸಿದ್ಧ-ಪ್ರವೇಶ 3BHK.",
        "image_url": "https://images.pexels.com/photos/31737842/pexels-photo-31737842.jpeg",
        "gallery": ["https://images.pexels.com/photos/31737842/pexels-photo-31737842.jpeg"],
    },
    {
        "title": "Commercial Shop on Hennur Main Road",
        "title_kn": "ಹೆಣ್ಣೂರು ಮುಖ್ಯ ರಸ್ತೆಯಲ್ಲಿ ವಾಣಿಜ್ಯ ಅಂಗಡಿ",
        "type": "commercial", "listing": "sale", "price": 6500000,
        "location": "Hennur Main Road", "locality": "Hennur",
        "bhk": None, "area_sqft": 600, "featured": False, "status": "available",
        "description": "Ground-floor 600 sqft commercial shop with high footfall. Suitable for retail, clinic or office.",
        "description_kn": "ಹೆಚ್ಚಿನ ಜನಸಂಚಾರವಿರುವ 600 ಚದರ ಅಡಿ ವಾಣಿಜ್ಯ ಅಂಗಡಿ.",
        "image_url": "https://images.pexels.com/photos/8815819/pexels-photo-8815819.jpeg",
        "gallery": [],
    },
    {
        "title": "Independent House for Rent",
        "title_kn": "ಬಾಡಿಗೆಗೆ ಸ್ವತಂತ್ರ ಮನೆ",
        "type": "villa", "listing": "rent", "price": 55000,
        "location": "Kothanur, Hennur", "locality": "Kothanur",
        "bhk": 3, "area_sqft": 1800, "featured": False, "status": "available",
        "description": "Charming 3 BHK independent house with private terrace garden. Family preferred. Available immediately.",
        "description_kn": "3 BHK ಸ್ವತಂತ್ರ ಮನೆ, ಖಾಸಗಿ ತಾರಸಿ ಉದ್ಯಾನ, ಕುಟುಂಬಗಳಿಗೆ ಆದ್ಯತೆ.",
        "image_url": "https://images.pexels.com/photos/16573669/pexels-photo-16573669.jpeg",
        "gallery": [],
    },
    {
        "title": "Corner Plot in Premium Layout",
        "title_kn": "ಪ್ರೀಮಿಯಂ ಲೇಔಟ್‌ನಲ್ಲಿ ಮೂಲೆ ಪ್ಲಾಟ್",
        "type": "plot", "listing": "sale", "price": 12500000,
        "location": "Yelahanka extension", "locality": "Yelahanka",
        "bhk": None, "area_sqft": 3000, "featured": True, "status": "available",
        "description": "Rare corner plot of 3000 sqft in a fully developed gated layout with parks, roads, drainage and street lighting.",
        "description_kn": "ಸಂಪೂರ್ಣ ಅಭಿವೃದ್ಧಿಗೊಂಡ ಗೇಟೆಡ್ ಲೇಔಟ್‌ನಲ್ಲಿ 3000 ಚದರ ಅಡಿ ಮೂಲೆ ಪ್ಲಾಟ್.",
        "image_url": "https://images.unsplash.com/photo-1694011772133-dc4b3ff3f24f",
        "gallery": [],
    },
]


@app.on_event("startup")
async def on_startup():
    # Indexes
    try:
        await db.users.create_index("email", unique=True)
        await db.properties.create_index("locality")
        await db.properties.create_index("type")
    except Exception as e:
        logger.warning("Index creation: %s", e)

    # Seed admin
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@murthy.com").lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin@123")
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({
            "email": admin_email,
            "password_hash": hash_password(admin_password),
            "name": "Admin",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        logger.info("Seeded admin %s", admin_email)
    elif not verify_password(admin_password, existing.get("password_hash", "")):
        await db.users.update_one(
            {"email": admin_email},
            {"$set": {"password_hash": hash_password(admin_password)}},
        )
        logger.info("Updated admin password for %s", admin_email)

    # Seed reviews if empty
    if await db.reviews.count_documents({}) == 0:
        await db.reviews.insert_many(SEED_REVIEWS)
        logger.info("Seeded %d reviews", len(SEED_REVIEWS))

    # Seed properties if empty
    if await db.properties.count_documents({}) == 0:
        now = datetime.now(timezone.utc).isoformat()
        docs = []
        for p in SEED_PROPERTIES:
            p = {**p, "created_at": now}
            docs.append(p)
        await db.properties.insert_many(docs)
        logger.info("Seeded %d properties", len(docs))


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
