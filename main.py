import os, re, hmac, hashlib, json, secrets, html, uuid, time
from typing import List
from datetime import datetime, timezone, timedelta
import requests
from pydantic import BaseModel
from supabase import create_client
from fastapi import FastAPI, Request, HTTPException, Depends, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

app = FastAPI()

PAYMONGO_SECRET = os.getenv("PAYMONGO_SECRET", "")
WEBHOOK_SECRET = os.getenv("PAYMONGO_WEBHOOK_SECRET", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
ADMIN_KEY = os.getenv("ADMIN_KEY", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")  # public ito; galing sa Google Cloud Console
MAX_IMAGES = 5

RESERVE_MINUTES = 30      # gaano katagal naka-reserve ang stock habang nagbabayad ang buyer
MIN_PRICE = 1             # minimum na presyo ng produkto (pesos)
FEE_CENTAVOS = 100        # ₱1 bawat produkto na ipa-publish ng seller (libre ang paggawa ng shop)
PENDING_SHOP_MINUTES = 180
MIN_PAYOUT_CENTAVOS = 100  # minimum na puwedeng i-withdraw (₱1; itaas mo kung gusto)
MAIN_SLUG = "main"        # ang sarili mong shop (login: ADMIN_KEY)
RESERVED = {"admin", "api", "s", "signup", "main", "webhook", "success", "cancel", "fee", "static", "www"}
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,29}$")

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
supabase = create_client(SUPABASE_URL, os.environ["SUPABASE_KEY"])
BUCKET = "product-images"
MAX_IMAGE = 8 * 1024 * 1024
security = HTTPBasic(auto_error=False)
e = html.escape


def now_dt():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="seconds")


def check_uuid(value):
    try:
        uuid.UUID(value)
    except ValueError:
        raise HTTPException(400, "Mali ang ID.")


# ---------- Stock (atomic, sa pamamagitan ng SQL functions) ----------
def reserve_stock(product_id) -> bool:
    return bool(supabase.rpc("reserve_stock", {"p_id": product_id}).execute().data)


def release_stock(product_id, n=1):
    supabase.rpc("release_stock", {"p_id": product_id, "p_n": n}).execute()


def release_expired():
    """Ibalik ang stock ng mga order na hindi binayaran sa loob ng RESERVE_MINUTES."""
    cutoff = iso(now_dt() - timedelta(minutes=RESERVE_MINUTES))
    rows = (
        supabase.table("orders").update({"status": "expired"})
        .eq("status", "pending").lt("created_at", cutoff).execute().data
    )
    for o in rows:
        release_stock(o["product_id"])


# ---------- PayMongo ----------
def create_checkout(amount, name, description, success_url, cancel_url, metadata,
                    methods=("gcash", "paymaya", "qrph", "card")):
    payload = {"data": {"attributes": {
        "line_items": [{"currency": "PHP", "amount": amount, "name": name, "quantity": 1}],
        "payment_method_types": list(methods),
        "success_url": success_url,
        "cancel_url": cancel_url,
        "description": description,
        "metadata": metadata,
    }}}
    r = requests.post(
        "https://api.paymongo.com/v1/checkout_sessions",
        json=payload, auth=(PAYMONGO_SECRET, ""), timeout=30,
    )
    if r.status_code != 200:
        print("PAYMONGO ERROR:", r.status_code, r.text)
        raise RuntimeError("paymongo")
    d = r.json()["data"]
    return d["id"], d["attributes"]["checkout_url"]


# ---------- Password ----------
def hash_pw(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return salt.hex(), h.hex()


def verify_pw(password, salt_hex, hash_hex):
    _, h = hash_pw(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(h, hash_hex)


FAILS = {}  # slug -> (bilang ng mali, hanggang kailan naka-lock)


def is_locked(key):
    n, until = FAILS.get(key, (0, 0))
    if time.time() > until:
        FAILS.pop(key, None)
        return False
    return n >= 8


def note_fail(key):
    n, _ = FAILS.get(key, (0, 0))
    FAILS[key] = (n + 1, time.time() + 300)


# ---------- Pera ng seller ----------
def net_of(o):
    return o["net_centavos"] if o.get("net_centavos") is not None else o["amount_centavos"]


def money_summary(paid_orders, payouts):
    gross = sum(o["amount_centavos"] for o in paid_orders)
    fees = sum(o.get("fee_centavos") or 0 for o in paid_orders)
    net = sum(net_of(o) for o in paid_orders)
    approved = sum(p["amount_centavos"] for p in payouts if p["status"] == "approved")
    pending = sum(p["amount_centavos"] for p in payouts if p["status"] == "pending")
    return {
        "count": len(paid_orders), "gross": gross, "fees": fees, "net": net,
        "approved": approved, "pending": pending, "available": net - approved - pending,
        "est": any(o.get("net_centavos") is None for o in paid_orders),
    }


def peso(c):
    return f"₱{c / 100:,.2f}"


# ---------- Session (login gamit ang form sa homepage) ----------
COOKIE = "shop_session"
SESSION_DAYS = 7


def _sig(slug, exp, fp):
    return hmac.new(ADMIN_KEY.encode(), f"{slug}|{exp}|{fp}".encode(), hashlib.sha256).hexdigest()


def make_token(shop):
    exp = int(time.time()) + SESSION_DAYS * 86400
    fp = (shop.get("pw_hash") or "main")[:16]  # kapag nagbago ang password, invalid ang lumang session
    return f"{shop['slug']}|{exp}|{_sig(shop['slug'], exp, fp)}"


def read_session(request):
    """Ibalik ang shop kung may valid na session cookie, kung hindi ay None."""
    if not ADMIN_KEY:
        return None
    parts = (request.cookies.get(COOKIE) or "").split("|")
    if len(parts) != 3 or not parts[1].isdigit() or int(parts[1]) < time.time():
        return None
    shop = get_shop(parts[0])
    if not shop:
        return None
    fp = (shop.get("pw_hash") or "main")[:16]
    if not hmac.compare_digest(parts[2], _sig(shop["slug"], parts[1], fp)):
        return None
    return shop


def with_session(payload, shop):
    resp = JSONResponse(payload)
    resp.set_cookie(
        COOKIE, make_token(shop), max_age=SESSION_DAYS * 86400, httponly=True,
        secure=BASE_URL.startswith("https"), samesite="lax", path="/",
    )
    return resp


# ---------- Google user session ----------
UCOOKIE = "user_session"


def _usig(uid, exp):
    return hmac.new(ADMIN_KEY.encode(), f"u|{uid}|{exp}".encode(), hashlib.sha256).hexdigest()


def read_user(request):
    """Ibalik ang naka-sign in na Google user (dict) o None."""
    if not ADMIN_KEY:
        return None
    parts = (request.cookies.get(UCOOKIE) or "").split("|")
    if len(parts) != 3 or not parts[1].isdigit() or int(parts[1]) < time.time():
        return None
    if not hmac.compare_digest(parts[2], _usig(parts[0], parts[1])):
        return None
    try:
        rows = supabase.table("app_users").select("*").eq("id", parts[0]).limit(1).execute().data
    except Exception:
        return None
    return rows[0] if rows else None


def with_user_session(payload, user):
    exp = int(time.time()) + SESSION_DAYS * 86400
    resp = JSONResponse(payload)
    resp.set_cookie(
        UCOOKIE, f"{user['id']}|{exp}|{_usig(user['id'], exp)}", max_age=SESSION_DAYS * 86400,
        httponly=True, secure=BASE_URL.startswith("https"), samesite="lax", path="/",
    )
    return resp


# ---------- Shops ----------
def get_shop(slug):
    rows = supabase.table("seller_shops").select("*").eq("slug", slug).limit(1).execute().data
    return rows[0] if rows else None


def get_shop_by_id(sid):
    rows = supabase.table("seller_shops").select("*").eq("id", sid).limit(1).execute().data
    return rows[0] if rows else None


# ====================== PUBLIC ======================
@app.get("/")
def home():
    return FileResponse("index.html")


@app.get("/p/{pid}")
def product_page(pid: str):
    return FileResponse("index.html")


@app.get("/s/{slug}")
def shop_page(slug: str):
    shop = get_shop(slug)
    if not shop or shop["status"] != "active":
        return HTMLResponse("<h2>Walang ganitong shop.</h2><a href='/'>Balik</a>", status_code=404)
    return FileResponse("index.html")


@app.get("/api/shop/{slug}/products")
def api_shop_products(slug: str):
    shop = get_shop(slug)
    if not shop or shop["status"] != "active":
        raise HTTPException(404, "Walang ganitong shop.")
    release_expired()
    products = (
        supabase.table("products")
        .select("id,name,description,image_url,images,price_centavos,stock,sold_count,rating_sum,rating_count,require_name,require_id,require_email,id_label")
        .eq("seller_shop_id", shop["id"]).eq("status", "active")
        .order("sold_count", desc=True).order("created_at", desc=True).execute().data
    )
    return {"shop": {"name": shop["name"], "slug": slug}, "products": products}


@app.get("/api/products")
def api_all_products():
    """Homepage: lahat ng produkto mula sa lahat ng aktibong shop."""
    release_expired()
    shops = supabase.table("seller_shops").select("id,name,slug").eq("status", "active").execute().data
    info = {sh["id"]: sh for sh in shops}
    if not info:
        return {"shop": {"name": "Tindahan", "slug": ""}, "products": []}
    products = (
        supabase.table("products")
        .select("seller_shop_id,id,name,description,image_url,images,price_centavos,stock,sold_count,rating_sum,rating_count,require_name,require_id,require_email,id_label")
        .in_("seller_shop_id", list(info)).eq("status", "active")
        .order("sold_count", desc=True).order("created_at", desc=True).limit(500).execute().data
    )
    for p in products:
        sh = info[p["seller_shop_id"]]
        p["shop_name"], p["shop_slug"] = sh["name"], sh["slug"]
    return {"shop": {"name": "Tindahan", "slug": ""}, "products": products}


def first_name(name):
    return (name or "Buyer").strip().split(" ")[0][:20] or "Buyer"


@app.get("/api/product/{pid}")
def api_product(pid: str, request: Request):
    check_uuid(pid)
    release_expired()
    rows = supabase.table("products").select("*").eq("id", pid).eq("status", "active").limit(1).execute().data
    if not rows:
        raise HTTPException(404, "Wala nang ganitong produkto.")
    p = rows[0]
    shop = get_shop_by_id(p["seller_shop_id"])
    if not shop or shop["status"] != "active":
        raise HTTPException(404, "Wala nang ganitong produkto.")

    revs = (
        supabase.table("product_reviews").select("rating,comment,created_at,user_id")
        .eq("product_id", pid).order("created_at", desc=True).limit(50).execute().data
    )
    names = {}
    if revs:
        users = supabase.table("app_users").select("id,name,picture").in_("id", list({r["user_id"] for r in revs})).execute().data
        names = {u["id"]: u for u in users}
    reviews = [
        {"rating": r["rating"], "comment": r["comment"], "created_at": r["created_at"][:10],
         "name": first_name(names.get(r["user_id"], {}).get("name")),
         "picture": names.get(r["user_id"], {}).get("picture", "")}
        for r in revs
    ]

    me = read_user(request)
    can_review = False
    if me:
        can_review = bool(
            supabase.table("orders").select("id").eq("product_id", pid).eq("user_id", me["id"])
            .eq("status", "paid").limit(1).execute().data
        )
    images = p.get("images") or ([p["image_url"]] if p.get("image_url") else [])
    return {
        "id": p["id"], "name": p["name"], "description": p["description"], "images": images,
        "price_centavos": p["price_centavos"], "stock": p["stock"], "sold_count": p["sold_count"],
        "rating_sum": p["rating_sum"], "rating_count": p["rating_count"],
        "require_name": p["require_name"], "require_id": p["require_id"], "require_email": p["require_email"],
        "id_label": p["id_label"], "shop": {"name": shop["name"], "slug": shop["slug"]},
        "reviews": reviews, "signed_in": bool(me), "can_review": can_review,
    }


class ReviewIn(BaseModel):
    rating: int
    comment: str = ""


@app.post("/api/product/{pid}/review")
def api_review(pid: str, body: ReviewIn, request: Request):
    same_origin(request)
    check_uuid(pid)
    me = read_user(request)
    if not me:
        raise HTTPException(401, "Mag-sign in muna gamit ang Google.")
    if not (1 <= body.rating <= 5):
        raise HTTPException(400, "Ang rating ay 1 hanggang 5.")
    comment = CTRL.sub("", body.comment).strip()[:500]
    res = supabase.rpc("submit_review", {
        "p_product": pid, "p_user": me["id"], "p_rating": body.rating, "p_comment": comment,
    }).execute().data
    if res == "not_buyer":
        raise HTTPException(403, "Ang mga nakabili lang ng produktong ito ang makakapag-rate.")
    if res != "ok":
        raise HTTPException(400, "Hindi na-save ang rating.")
    return {"ok": True}


class CheckoutIn(BaseModel):
    product_id: str
    buyer_name: str = ""
    buyer_id: str = ""
    email: str = ""


EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$")
CTRL = re.compile(r"[\x00-\x1f\x7f]")


@app.post("/api/checkout")
def api_checkout(body: CheckoutIn, request: Request):
    check_uuid(body.product_id)
    me = read_user(request)
    release_expired()

    rows = (
        supabase.table("products").select("*")
        .eq("id", body.product_id).eq("status", "active").limit(1).execute().data
    )
    if not rows:
        raise HTTPException(404, "Wala nang ganitong produkto.")
    product = rows[0]
    shop = get_shop_by_id(product["seller_shop_id"])
    if not shop or shop["status"] != "active":
        raise HTTPException(404, "Wala nang ganitong produkto.")

    name = CTRL.sub("", body.buyer_name).strip()
    bid = CTRL.sub("", body.buyer_id).strip()
    email = body.email.strip()
    if product["require_name"] and not (1 <= len(name) <= 60):
        raise HTTPException(400, "Ilagay ang pangalan (hanggang 60 letra).")
    if product["require_id"] and not (1 <= len(bid) <= 60):
        raise HTTPException(400, f"Ilagay ang {product['id_label']} (hanggang 60 letra).")
    if product["require_email"] and not EMAIL.match(email):
        raise HTTPException(400, "Mali ang email.")
    name = name if product["require_name"] else None
    bid = bid if product["require_id"] else None
    email = email if product["require_email"] else None

    if not reserve_stock(product["id"]):
        raise HTTPException(409, "Pasensya, sold out na ito.")

    order_id = secrets.token_urlsafe(8)

    def fail():
        release_stock(product["id"])
        supabase.table("orders").update({"status": "failed"}).eq("id", order_id).execute()
        raise HTTPException(502, "Hindi nagawa ang checkout. Subukan ulit.")

    try:
        supabase.table("orders").insert({
            "id": order_id,
            "seller_shop_id": shop["id"],
            "product_id": product["id"],
            "product_name": product["name"],
            "amount_centavos": product["price_centavos"],
            "buyer_name": name,
            "buyer_id": bid,
            "email": email,
            "user_id": me["id"] if me else None,
        }).execute()
        session_id, url = create_checkout(
            product["price_centavos"], product["name"],
            f"{product['name']} (order {order_id})",
            f"{BASE_URL}/success?order={order_id}",
            f"{BASE_URL}/cancel?order={order_id}",
            {"order_id": order_id},
        )
    except Exception as ex:
        print("CHECKOUT ERROR:", ex)
        fail()

    supabase.table("orders").update({"session_id": session_id}).eq("id", order_id).execute()
    return {"checkout_url": url}


@app.get("/api/order/{order_id}")
def order_status(order_id: str):
    res = supabase.table("orders").select("status").eq("id", order_id).limit(1).execute()
    if not res.data:
        raise HTTPException(404, "Not found")
    return {"status": res.data[0]["status"]}


POLL_JS = """
let tries = 0;
async function check() {
  try {
    const r = await fetch(API + encodeURIComponent(ID));
    const d = await r.json();
    if (d.status === "paid") { done(d); return; }
    if (d.status === "paid_conflict") { document.getElementById("msg").textContent = "Bayad na, pero may problema sa stock. Kokontakin ka ng admin para sa refund."; return; }
  } catch (e) {}
  if (++tries < 40) setTimeout(check, 3000);
  else document.getElementById("msg").textContent = "Matagal ang proseso. I-refresh o kontakin ang admin.";
}
check();
"""


@app.get("/success", response_class=HTMLResponse)
def success(order: str = ""):
    return f"""<!DOCTYPE html><html lang="fil"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Bayad</title></head>
<body style="font-family:sans-serif;text-align:center;padding:40px">
<h2 id="msg">Pinoproseso ang bayad mo...</h2><p>Order: {e(order)}</p><a href="/">Balik sa shop</a>
<script>const API="/api/order/", ID={json.dumps(order)};
function done() {{ document.getElementById("msg").textContent = "Bayad na! Salamat."; }}
{POLL_JS}</script></body></html>"""


@app.get("/cancel", response_class=HTMLResponse)
def cancel(order: str = ""):
    res = (
        supabase.table("orders").update({"status": "cancelled"})
        .eq("id", order).eq("status", "pending").execute()
    )
    if res.data:
        release_stock(res.data[0]["product_id"])
    return "<h2>Na-cancel ang bayad.</h2><a href='/'>Balik sa shop</a>"


# ---------- Seller signup (₱1) ----------
@app.get("/signup")
def signup_page():
    return RedirectResponse("/?open=1")


def start_fee(shop, qty):
    """Bayad na ₱1 bawat slot ng produkto."""
    fee_id = secrets.token_urlsafe(8)
    supabase.table("seller_fees").insert(
        {"id": fee_id, "seller_shop_id": shop["id"], "kind": "unlock", "qty": qty}
    ).execute()
    label = f"Bayad sa pag-publish ng produkto (x{qty})"
    done = f"{BASE_URL}/fee/done?fee={fee_id}"
    session_id, url = create_checkout(
        FEE_CENTAVOS * qty, label, f"{label} ({shop['slug']})", done, done,
        {"fee_id": fee_id}, methods=("gcash", "paymaya", "qrph"),  # walang card: malulugi sa fixed fee
    )
    supabase.table("seller_fees").update({"session_id": session_id}).eq("id", fee_id).execute()
    return url


class GoogleIn(BaseModel):
    credential: str


@app.post("/api/auth/google")
def api_auth_google(body: GoogleIn):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(503, "Hindi pa naka-set ang Google sign-in.")
    try:
        info = google_id_token.verify_oauth2_token(body.credential, google_requests.Request(), GOOGLE_CLIENT_ID)
    except Exception as ex:
        print("GOOGLE VERIFY ERROR:", ex)
        raise HTTPException(401, "Hindi ma-verify ang Google sign-in. Subukan ulit.")
    if not info.get("email_verified"):
        raise HTTPException(401, "Hindi verified ang email ng Google account.")
    data = {
        "email": (info.get("email") or "")[:200],
        "name": (info.get("name") or "")[:100],
        "picture": (info.get("picture") or "")[:500],
    }
    found = supabase.table("app_users").select("*").eq("google_sub", info["sub"]).limit(1).execute().data
    if found:
        user = supabase.table("app_users").update(data).eq("id", found[0]["id"]).execute().data[0]
    else:
        user = supabase.table("app_users").insert({"google_sub": info["sub"], **data}).execute().data[0]
    return with_user_session({"ok": True}, user)


class NewShopIn(BaseModel):
    name: str
    username: str


@app.post("/api/shops")
def api_create_shop(body: NewShopIn, request: Request):
    """Libre ang paggawa ng shop. Kailangang naka-sign in gamit ang Google."""
    same_origin(request)
    me = read_user(request)
    if not me:
        raise HTTPException(401, "Mag-sign in muna gamit ang Google.")
    name = CTRL.sub("", body.name).strip()
    slug = body.username.strip().lower()
    if not (1 <= len(name) <= 60):
        raise HTTPException(400, "Ilagay ang pangalan ng shop (hanggang 60 letra).")
    if not SLUG_RE.match(slug) or slug in RESERVED:
        raise HTTPException(400, "Username: 3-30 letra/numero/gitling (a-z, 0-9, -), at hindi puwede ang mga nakareserba.")
    if supabase.table("seller_shops").select("id").eq("owner_user_id", me["id"]).limit(1).execute().data:
        raise HTTPException(409, "May shop ka na. Buksan ang admin panel mo.")
    if get_shop(slug):
        raise HTTPException(409, "Ginagamit na ang username na ito.")
    try:
        supabase.table("seller_shops").insert(
            {"slug": slug, "name": name, "status": "active", "owner_user_id": me["id"]}
        ).execute()
    except Exception:
        raise HTTPException(409, "Ginagamit na ang username na ito.")
    return {"slug": slug}


@app.get("/api/fee/{fee_id}")
def fee_status(fee_id: str):
    rows = supabase.table("seller_fees").select("status,kind,qty,seller_shop_id").eq("id", fee_id).limit(1).execute().data
    if not rows:
        raise HTTPException(404, "Not found")
    shop = get_shop_by_id(rows[0]["seller_shop_id"])
    return {"status": rows[0]["status"], "kind": rows[0]["kind"], "qty": rows[0]["qty"], "slug": shop["slug"] if shop else ""}


@app.get("/fee/done", response_class=HTMLResponse)
def fee_done(fee: str = ""):
    return f"""<!DOCTYPE html><html lang="fil"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Bayad</title></head>
<body style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px 18px;line-height:1.5">
<h2 id="msg">Kinukumpirma ang bayad mo...</h2><div id="sub"></div>
<script>const API="/api/fee/", ID={json.dumps(fee)};
function line(label, href, text) {{
  const p = document.createElement("p");
  p.append(label + " ");
  const a = document.createElement("a"); a.href = href; a.textContent = text; p.append(a);
  return p;
}}
function done(d) {{
  document.getElementById("msg").textContent = "Bayad na! May dagdag kang " + d.qty + " slot para sa produkto.";
  const sub = document.getElementById("sub");
  sub.append(line("Admin panel mo:", "/s/" + d.slug + "/admin", location.origin + "/s/" + d.slug + "/admin"));
  sub.append(line("Link ng shop mo:", "/s/" + d.slug, location.origin + "/s/" + d.slug));
  const next = document.createElement("p");
  next.textContent = "Susunod: buksan ang admin panel mo at idagdag ang produkto. Bawat produkto ay gumagamit ng 1 slot.";
  sub.append(next);
}}
{POLL_JS}</script></body></html>"""


class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def api_login(body: LoginIn):
    slug = body.username.strip().lower()
    key = f"login:{slug}"
    if is_locked(key):
        raise HTTPException(429, "Maraming maling subok. Subukan ulit pagkalipas ng 5 minuto.")
    shop = get_shop(slug) if slug else None
    ok = False
    if shop:
        if slug == MAIN_SLUG:
            ok = bool(ADMIN_KEY) and hmac.compare_digest(body.password.encode(), ADMIN_KEY.encode())
        else:
            ok = bool(shop["pw_hash"]) and verify_pw(body.password, shop["pw_salt"], shop["pw_hash"])
    if not ok:
        note_fail(key)
        raise HTTPException(401, "Mali ang username o password.")
    FAILS.pop(key, None)
    if shop["status"] != "active":
        raise HTTPException(403, "Na-suspend ang shop na ito. Makipag-ugnayan sa admin.")
    return with_session({"slug": slug}, shop)


@app.get("/api/me")
def api_me(request: Request):
    user = read_user(request)
    shop = None
    if user:
        rows = supabase.table("seller_shops").select("slug,name").eq("owner_user_id", user["id"]).limit(1).execute().data
        shop = rows[0] if rows else None
    if not shop:
        legacy = read_session(request)  # lumang shop na may password
        if legacy:
            shop = {"slug": legacy["slug"], "name": legacy["name"]}
    return {
        "google_client_id": GOOGLE_CLIENT_ID,
        "user": {"name": user["name"], "picture": user["picture"]} if user else None,
        "shop": shop,
    }


@app.post("/logout")
def logout(request: Request):
    same_origin(request)
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie(COOKIE, path="/")
    resp.delete_cookie(UCOOKIE, path="/")
    return resp


# ====================== WEBHOOK ======================
@app.post("/webhook")
async def webhook(request: Request):
    raw = await request.body()
    sig_header = request.headers.get("Paymongo-Signature", "")
    parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)
    timestamp = parts.get("t", "")
    expected = hmac.new(
        WEBHOOK_SECRET.encode(), f"{timestamp}.{raw.decode()}".encode(), hashlib.sha256
    ).hexdigest()
    received = parts.get("li") or parts.get("te") or ""
    if not WEBHOOK_SECRET or not hmac.compare_digest(expected, received):
        raise HTTPException(400, "Invalid signature")

    event = json.loads(raw)
    if event["data"]["attributes"]["type"] != "checkout_session.payment.paid":
        return {"ok": True}

    session = event["data"]["attributes"]["data"]
    meta = session["attributes"].get("metadata") or {}

    # --- ₱1 na bayad ng seller ---
    fee_id = meta.get("fee_id")
    if fee_id:
        upd = (
            supabase.table("seller_fees")
            .update({"status": "paid", "paid_at": iso(now_dt()), "session_id": session["id"]})
            .eq("id", fee_id).neq("status", "paid").execute()
        )
        if upd.data:
            fee = upd.data[0]
            if fee["kind"] == "shop":  # luma, noong may bayad pa ang paggawa ng shop
                supabase.table("seller_shops").update({"status": "active"}) \
                    .eq("id", fee["seller_shop_id"]).eq("status", "pending").execute()
            else:
                supabase.rpc("add_product_credits", {
                    "p_shop": fee["seller_shop_id"], "p_n": fee.get("qty") or 1,
                }).execute()
            print("FEE PAID:", fee_id, fee["kind"], fee.get("qty"))
        return {"ok": True}

    # --- bayad ng buyer sa produkto ---
    order_id = meta.get("order_id")
    if not order_id:
        return {"ok": True}
    found = supabase.table("orders").select("*").eq("id", order_id).limit(1).execute().data
    if not found or found[0]["status"] in ("paid", "paid_conflict"):
        return {"ok": True}  # idempotent
    order = found[0]
    prev = order["status"]
    # Kung nasa event ang fee at net amount ng PayMongo, itabi ito (ang seller ang sumasalo ng fee)
    pay = ((session["attributes"].get("payments") or [{}])[0].get("attributes")) or {}
    money = {}
    for key, col in (("fee", "fee_centavos"), ("net_amount", "net_centavos")):
        if isinstance(pay.get(key), int):
            money[col] = pay[key]
    upd = (
        supabase.table("orders")
        .update({"status": "paid", "paid_at": iso(now_dt()), "session_id": session["id"], **money})
        .eq("id", order_id).eq("status", prev).execute()
    )
    conflict = False
    if upd.data and prev != "pending":
        # Nabalik na dati ang stock (expired/cancelled). Kunin ulit; kung wala na, i-flag para sa refund.
        if not reserve_stock(order["product_id"]):
            conflict = True
            supabase.table("orders").update({
                "status": "paid_conflict",
                "note": "Sold out na ang produkto nang dumating ang bayad. I-refund ang customer na ito.",
            }).eq("id", order_id).execute()
    if upd.data and not conflict:
        supabase.rpc("bump_sold", {"p_id": order["product_id"]}).execute()
    print("PAID:", order_id)
    return {"ok": True}


# ====================== AUTH ======================
def unauthorized(realm):
    return HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": f'Basic realm="{realm}"'})


def shop_admin(slug: str, request: Request):
    shop = get_shop(slug)
    allowed = False
    legacy = read_session(request)
    if legacy and legacy["slug"] == slug:
        allowed = True
    elif shop:
        user = read_user(request)
        allowed = bool(user and shop.get("owner_user_id") == user["id"])
    if not shop or not allowed:
        # Hindi naka-login: ibalik sa homepage at buksan ang sign-in
        raise HTTPException(303, "Login required", headers={"Location": "/?login=1"})
    if shop["status"] != "active":
        raise HTTPException(403, "Na-suspend ang shop na ito. Makipag-ugnayan sa admin.")
    return shop


def platform_admin(request: Request, creds: HTTPBasicCredentials = Depends(security)):
    owner = read_session(request)
    if owner and owner["slug"] == MAIN_SLUG:  # naka-login bilang "main" sa homepage
        return True
    if creds is None:
        raise unauthorized("platform")
    if is_locked("__platform__"):
        raise HTTPException(429, "Maraming maling subok. Subukan ulit pagkalipas ng 5 minuto.")
    if not ADMIN_KEY or not hmac.compare_digest(creds.password.encode(), ADMIN_KEY.encode()):
        note_fail("__platform__")
        raise unauthorized("platform")
    return True


def same_origin(request: Request):
    src = request.headers.get("origin") or request.headers.get("referer") or ""
    if not src.startswith(BASE_URL):
        raise HTTPException(403, "Bad origin")


# ====================== ADMIN UI ======================
CSS = """
body{font-family:system-ui,sans-serif;margin:0;padding:16px;background:#f3f6f9;color:#14202b}
h1,h2{margin:.4em 0}.card{background:#fff;border:1px solid #d6e0e8;border-radius:12px;padding:14px;margin-bottom:16px;overflow-x:auto}
input,textarea,button{font:inherit;padding:8px;border:1px solid #b9c8d4;border-radius:8px;width:100%;margin:4px 0 10px}
input[type=checkbox]{width:auto;margin:0 8px 0 0}label.chk{display:flex;align-items:center;margin:4px 0}
button,a.btn{background:#0b6bcb;color:#fff;border:0;cursor:pointer;width:auto;padding:8px 14px;border-radius:8px;text-decoration:none;display:inline-block;font-size:1rem}
button.red{background:#c0392b}button.gray,a.btn.gray{background:#5b6f80}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border-bottom:1px solid #e3ebf1;padding:6px;text-align:left;vertical-align:top}
.tag{padding:2px 8px;border-radius:99px;background:#e3ebf1;font-size:.8rem}
.paid,.active,.approved{background:#cdf3e1}.paid_conflict,.soldout,.suspended,.rejected{background:#ffd6d2}.pending{background:#fff0c2}
form.inline{display:inline}form.inline button{margin:0;padding:4px 10px}
form.inline input{width:70px;display:inline;margin:0 4px 0 0;padding:4px}
"""

ADMIN_JS = """
function copyLink() {
  const i = document.getElementById('shoplink');
  i.select();
  try { navigator.clipboard.writeText(i.value); } catch (err) { document.execCommand('copy'); }
  document.getElementById('copied').textContent = 'Nakopya na!';
}
const img = document.getElementById('img');
if (img) img.addEventListener('change', async ev => {
  const files = Array.from(ev.target.files).slice(0, 5);
  const dt = new DataTransfer();
  try {
    for (const f of files) {
      if (!f.type.startsWith('image/')) continue;
      const bmp = await createImageBitmap(f);
      const k = Math.min(1, 900 / Math.max(bmp.width, bmp.height));
      const c = document.createElement('canvas');
      c.width = Math.round(bmp.width * k); c.height = Math.round(bmp.height * k);
      const x = c.getContext('2d');
      x.fillStyle = '#fff'; x.fillRect(0, 0, c.width, c.height);
      x.drawImage(bmp, 0, 0, c.width, c.height);
      const blob = await new Promise(r => c.toBlob(r, 'image/jpeg', 0.85));
      dt.items.add(new File([blob], 'photo.jpg', {type: 'image/jpeg'}));
    }
    ev.target.files = dt.files;
    document.getElementById('imgnote').textContent = dt.files.length + ' larawan (na-resize)';
  } catch (err) {}
});
"""


def shell(title, body):
    return HTMLResponse(
        f"""<!DOCTYPE html><html lang="fil"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title><style>{CSS}</style></head><body>
{body}<script>{ADMIN_JS}</script></body></html>""",
        headers={"Cache-Control": "no-store"},
    )


def tag(status, label=None):
    return f"<span class='tag {e(status)}'>{e(label or status)}</span>"


def product_form(action, p=None):
    p = p or {}
    chk = lambda k: "checked" if p.get(k, True) else ""
    price = p["price_centavos"] / 100 if p else ""
    hint = " — kapag may in-upload ka, papalitan nito ang lahat ng dating larawan" if p.get("image_url") else ""
    return f"""<form method="post" action="{action}" enctype="multipart/form-data">
<label>Pangalan ng produkto</label><input name="name" required maxlength="100" value="{e(p.get('name', ''))}">
<label>Presyo (₱, minimum {MIN_PRICE})</label><input name="price" type="number" step="0.01" min="{MIN_PRICE}" required value="{price}">
<label>Ilan ang available (stock)</label><input name="stock" type="number" min="0" step="1" required value="{p.get('stock', 1)}">
<label>Description (optional)</label><textarea name="description" maxlength="500" rows="2">{e(p.get('description', ''))}</textarea>
<label>Mga larawan (hanggang 5, JPG/PNG/WEBP){hint}</label>
<input id="img" name="images" type="file" accept="image/*" multiple><small id="imgnote"></small>
<p><b>Ano ang hihingin sa buyer?</b></p>
<label class="chk"><input type="checkbox" name="require_name" {chk('require_name')}> Pangalan</label>
<label class="chk"><input type="checkbox" name="require_id" {chk('require_id')}> ID / Username</label>
<label>Tawag sa ID field (hal. Game ID, Username, Account No.)</label>
<input name="id_label" maxlength="30" value="{e(p.get('id_label', 'ID'))}">
<label class="chk"><input type="checkbox" name="require_email" {chk('require_email')}> Email</label>
<button>I-save</button></form>"""


@app.get("/s/{slug}/admin", response_class=HTMLResponse)
def admin_page(slug: str, shop=Depends(shop_admin)):
    release_expired()
    sid = shop["id"]
    base = f"/s/{slug}/admin"
    is_main = slug == MAIN_SLUG
    prods = (
        supabase.table("products").select("*").eq("seller_shop_id", sid).neq("status", "removed")
        .order("created_at", desc=True).execute().data
    )
    ords = (
        supabase.table("orders").select("*").eq("seller_shop_id", sid).neq("status", "failed")
        .order("created_at", desc=True).limit(200).execute().data
    )

    def needs(p):
        parts = []
        if p["require_name"]: parts.append("Pangalan")
        if p["require_id"]: parts.append(e(p["id_label"]))
        if p["require_email"]: parts.append("Email")
        return ", ".join(parts) or "Wala"

    prod_rows = "".join(
        "<tr><td>"
        + (f"<img src='{e(p['image_url'])}' width='48' height='48' style='object-fit:cover;border-radius:8px;vertical-align:middle;margin-right:8px'>"
           if p.get("image_url") else "")
        + f"<b>{e(p['name'])}</b><br><small>{e(p.get('description') or '')}</small></td>"
        f"<td>₱{p['price_centavos'] / 100:.2f}</td>"
        f"<td><form class='inline' method='post' action='{base}/products/{e(p['id'])}/stock'>"
        f"<input name='stock' type='number' min='0' step='1' value='{p['stock']}' aria-label='Stock'>"
        f"<button>OK</button></form>"
        + (" " + tag("soldout", "sold out") if p["stock"] <= 0 else "")
        + f"</td><td>{needs(p)}</td><td>"
        f"<a class='btn gray' href='{base}/products/{e(p['id'])}/edit'>I-edit</a> "
        f"<form class='inline' method='post' action='{base}/products/{e(p['id'])}/remove' "
        f"onsubmit=\"return confirm('Alisin sa shop ang produktong ito?')\"><button class='red'>Alisin</button></form>"
        "</td></tr>"
        for p in prods
    ) or "<tr><td colspan=5>Wala pang produkto.</td></tr>"

    def order_row(o):
        action = ""
        if o["status"] in ("paid", "paid_conflict"):
            action = (
                "Na-deliver na" if o.get("delivered") else
                f"<form class='inline' method='post' action='{base}/orders/{e(o['id'])}/delivered'>"
                f"<button class='gray'>Markahan: Na-deliver</button></form>"
            )
        return (
            f"<tr><td>{e(o['created_at'][:16].replace('T', ' '))}</td>"
            f"<td>{e(o['product_name'])}<br>₱{o['amount_centavos'] / 100:.2f}</td>"
            f"<td>{e(o.get('buyer_name') or '—')}<br>ID: {e(o.get('buyer_id') or '—')}<br>{e(o.get('email') or '—')}</td>"
            f"<td>{tag(o['status'])}<br>{e(o.get('note') or '')}</td><td>{action}</td></tr>"
        )

    order_rows = "".join(order_row(o) for o in ords) or "<tr><td colspan=5>Wala pang order.</td></tr>"

    credits = shop.get("product_credits") or 0
    buy_form = f"""<form method="post" action="{base}/slots">
<label>Ilang produkto ang gusto mong i-publish? (₱1 bawat produkto)</label>
<input name="qty" type="number" min="1" max="20" value="1" required>
<button>Magbayad (GCash / Maya / QR Ph)</button></form>"""
    if is_main:
        add_card = f'<div class="card"><h2>Magdagdag ng produkto</h2>{product_form(base + "/products")}</div>'
    elif credits > 0:
        add_card = f"""<div class="card"><h2>Magdagdag ng produkto</h2>
<p><b>Natitirang slot: {credits}</b> (1 slot = 1 produkto)</p>{product_form(base + "/products")}
<h3>Bumili ng dagdag na slot</h3>{buy_form}</div>"""
    else:
        add_card = f"""<div class="card"><h2>Magdagdag ng produkto</h2>
<p>Wala ka nang slot. Bawat produktong ipa-publish mo ay <b>₱1</b>. Magbayad muna para makapagdagdag.</p>{buy_form}</div>"""

    money_card = ""
    if not is_main:
        paid_orders = (
            supabase.table("orders").select("amount_centavos,fee_centavos,net_centavos")
            .eq("seller_shop_id", sid).eq("status", "paid").limit(10000).execute().data
        )
        payouts = (
            supabase.table("seller_payouts").select("*").eq("seller_shop_id", sid)
            .order("created_at", desc=True).limit(50).execute().data
        )
        m = money_summary(paid_orders, payouts)
        waiting = next((p for p in payouts if p["status"] == "pending"), None)

        if waiting:
            payout_box = (
                f"<p style='background:#fff0c2;padding:10px;border-radius:8px'><b>Please wait for approval of admin.</b><br>"
                f"Hiniling mo: {peso(waiting['amount_centavos'])}</p>"
            )
        elif m["available"] < MIN_PAYOUT_CENTAVOS:
            payout_box = f"<p><small>Wala pang puwedeng i-withdraw (minimum {peso(MIN_PAYOUT_CENTAVOS)}).</small></p>"
        else:
            payout_box = f"""<h3>Mag-withdraw</h3>
<form method="post" action="{base}/payout">
<label>Halaga (₱) — hanggang {peso(m['available'])}</label>
<input name="amount" type="number" step="0.01" min="{MIN_PAYOUT_CENTAVOS / 100}" max="{m['available'] / 100:.2f}" required>
<label>ID number mo</label><input name="id_number" maxlength="40" required>
<label>GCash account (number)</label><input name="gcash" maxlength="40" inputmode="tel" required>
<label>Email mo</label><input name="email" type="email" maxlength="120" required>
<button>OK</button></form>"""

        status_label = {"pending": "Naghihintay ng approval", "approved": "Naipadala / approved", "rejected": "Na-reject (ibinalik sa balanse)"}
        hist = "".join(
            f"<tr><td>{e(p['created_at'][:16].replace('T', ' '))}</td><td>{peso(p['amount_centavos'])}</td>"
            f"<td>{tag(p['status'], status_label.get(p['status'], p['status']))}</td></tr>"
            for p in payouts
        )
        hist_html = f"<h3>Mga withdraw mo</h3><table><tr><th>Petsa (UTC)</th><th>Halaga</th><th>Status</th></tr>{hist}</table>" if hist else ""

        money_card = f"""<div class="card"><h2>Pera mo</h2>
<table>
<tr><td>Bilang ng nabenta</td><td>{m['count']}</td></tr>
<tr><td>Kabuuang nabenta</td><td>{peso(m['gross'])}</td></tr>
<tr><td>Fees ng PayMongo (ikaw ang sumasalo)</td><td>-{peso(m['fees'])}</td></tr>
<tr><td>Net na pera mo</td><td>{peso(m['net'])}</td></tr>
<tr><td>Naipadala na sa iyo</td><td>{peso(m['approved'])}</td></tr>
<tr><td>Naghihintay ng approval</td><td>{peso(m['pending'])}</td></tr>
<tr><td><b>Natitira (puwede mong i-withdraw)</b></td><td><b>{peso(m['available'])}</b></td></tr>
</table>
{"<p><small>May mga order na hindi pa alam ang eksaktong fee, kaya buong halaga ang ipinapakita para sa mga iyon.</small></p>" if m['est'] else ""}
{payout_box}{hist_html}</div>"""

    credits = shop.get("product_credits") or 0
    steps_card = ""
    if not is_main:
        shop_url = f"{BASE_URL}/s/{slug}"
        mark = lambda ok: "✅" if ok else "⬜"
        steps_card = f"""<div class="card"><h2>Mga hakbang</h2>
<p>{mark(True)} 1. Ginawa na ang shop mo<br>
{mark(credits > 0 or len(prods) > 0)} 2. Magbayad ng ₱1 bawat produkto (natitirang slot: {credits})<br>
{mark(len(prods) > 0)} 3. Magdagdag ng produkto<br>
⬜ 4. Ibahagi ang link ng shop mo sa mga bibili</p>
<label for="shoplink"><b>Link ng shop mo</b></label>
<input id="shoplink" readonly value="{e(shop_url)}">
<button type="button" onclick="copyLink()">Kopyahin</button>
<a class="btn gray" href="/s/{e(slug)}" target="_blank">Buksan ang shop</a> <small id="copied"></small>
<p><small>Lalabas din ang mga produkto mo sa unang page ng site.</small></p></div>"""

    top = (f"<p><a href='/admin'>Platform admin</a> · " if is_main else "<p>") + \
          f"<a href='/s/{e(slug)}' target='_blank'>Tingnan ang shop ko</a> · <a href='/'>Homepage</a> " \
          f"<form class='inline' method='post' action='/logout'><button class='gray'>Mag-logout</button></form></p>"
    body = f"""<h1>{e(shop['name'])} — Admin</h1>{top}{steps_card}{money_card}{add_card}
<div class="card"><h2>Mga produkto</h2><table><tr><th>Produkto</th><th>Presyo</th><th>Stock</th><th>Hinihingi</th><th></th></tr>{prod_rows}</table></div>
<div class="card"><h2>Mga order</h2><table><tr><th>Petsa (UTC)</th><th>Produkto</th><th>Buyer</th><th>Status</th><th></th></tr>{order_rows}</table></div>"""
    return shell("Admin", body)


def save_image(image):
    """I-upload ang larawan sa Supabase Storage at ibalik ang public URL ('' kung walang larawan)."""
    if image is None or not image.filename:
        return ""
    data = image.file.read(MAX_IMAGE + 1)
    if len(data) > MAX_IMAGE:
        raise HTTPException(400, "Masyadong malaki ang larawan (max 8 MB).")
    if data[:3] == b"\xff\xd8\xff":
        ext, ctype = "jpg", "image/jpeg"
    elif data[:4] == b"\x89PNG":
        ext, ctype = "png", "image/png"
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        ext, ctype = "webp", "image/webp"
    else:
        raise HTTPException(400, "JPG, PNG, o WEBP lang ang tinatanggap.")
    path = f"{uuid.uuid4().hex}.{ext}"
    try:
        supabase.storage.from_(BUCKET).upload(path, data, {"content-type": ctype})
    except Exception as ex:
        print("UPLOAD ERROR:", ex)
        raise HTTPException(502, "Hindi na-upload ang larawan. Subukan ulit.")
    return f"{SUPABASE_URL}/storage/v1/object/public/{BUCKET}/{path}"


def save_images(files):
    urls = []
    for f in (files or [])[:MAX_IMAGES]:
        url = save_image(f)
        if url:
            urls.append(url)
    return urls


def clean_fields(name, price, stock, description, id_label, require_name, require_id, require_email):
    name = name.strip()[:100]
    centavos = int(round(price * 100))
    if not name or centavos < MIN_PRICE * 100:
        raise HTTPException(400, f"Kailangan ng pangalan at presyong hindi bababa sa ₱{MIN_PRICE}.")
    if stock < 0 or stock > 100000:
        raise HTTPException(400, "Mali ang stock.")
    return {
        "name": name,
        "price_centavos": centavos,
        "stock": stock,
        "description": description.strip()[:500],
        "id_label": (id_label.strip()[:30] or "ID"),
        "require_name": bool(require_name),
        "require_id": bool(require_id),
        "require_email": bool(require_email),
    }


@app.post("/s/{slug}/admin/slots")
def admin_slots(slug: str, request: Request, qty: int = Form(1), shop=Depends(shop_admin)):
    same_origin(request)
    if slug == MAIN_SLUG:
        return RedirectResponse(f"/s/{slug}/admin", status_code=303)
    if not (1 <= qty <= 20):
        raise HTTPException(400, "Ang bilang ay 1 hanggang 20.")
    try:
        url = start_fee(shop, qty)
    except Exception as ex:
        print("SLOT FEE ERROR:", ex)
        raise HTTPException(502, "Hindi nagawa ang bayad. Subukan ulit.")
    return RedirectResponse(url, status_code=303)


@app.post("/s/{slug}/admin/products")
def admin_add_product(
    slug: str, request: Request,
    name: str = Form(...), price: float = Form(...), stock: int = Form(...),
    description: str = Form(""), id_label: str = Form("ID"),
    images: List[UploadFile] = File(default=[]),
    require_name: str = Form(None), require_id: str = Form(None), require_email: str = Form(None),
    shop=Depends(shop_admin),
):
    same_origin(request)
    row = clean_fields(name, price, stock, description, id_label, require_name, require_id, require_email)
    row["seller_shop_id"] = shop["id"]

    # 1 slot (₱1) bawat produkto. Ang shop mo (main) ay walang bayad.
    consumed = False
    if slug != MAIN_SLUG:
        if not supabase.rpc("use_product_credit", {"p_shop": shop["id"]}).execute().data:
            raise HTTPException(402, "Wala ka nang slot. Magbayad muna ng ₱1 para sa produktong ito.")
        consumed = True
    try:
        row["images"] = save_images(images)
        row["image_url"] = row["images"][0] if row["images"] else ""
        supabase.table("products").insert(row).execute()
    except Exception as ex:
        if consumed:  # ibalik ang slot kung hindi na-save ang produkto
            supabase.rpc("add_product_credits", {"p_shop": shop["id"], "p_n": 1}).execute()
        if isinstance(ex, HTTPException):
            raise
        print("ADD PRODUCT ERROR:", ex)
        raise HTTPException(502, "Hindi nai-save ang produkto. Subukan ulit.")
    return RedirectResponse(f"/s/{slug}/admin", status_code=303)


@app.get("/s/{slug}/admin/products/{pid}/edit", response_class=HTMLResponse)
def admin_edit_page(slug: str, pid: str, shop=Depends(shop_admin)):
    check_uuid(pid)
    rows = (
        supabase.table("products").select("*")
        .eq("id", pid).eq("seller_shop_id", shop["id"]).limit(1).execute().data
    )
    if not rows:
        raise HTTPException(404, "Wala")
    p = rows[0]
    urls = p.get("images") or ([p["image_url"]] if p.get("image_url") else [])
    img = "<p>" + "".join(f"<img src='{e(u)}' width='80' style='border-radius:8px;margin-right:6px'>" for u in urls) + "</p>"
    action = f"/s/{e(slug)}/admin/products/{e(pid)}/edit"
    return shell("I-edit", f"<p><a href='/s/{e(slug)}/admin'>← Balik</a></p><div class='card'><h2>I-edit ang produkto</h2>{img}{product_form(action, p)}</div>")


@app.post("/s/{slug}/admin/products/{pid}/edit")
def admin_edit_product(
    slug: str, pid: str, request: Request,
    name: str = Form(...), price: float = Form(...), stock: int = Form(...),
    description: str = Form(""), id_label: str = Form("ID"),
    images: List[UploadFile] = File(default=[]),
    require_name: str = Form(None), require_id: str = Form(None), require_email: str = Form(None),
    shop=Depends(shop_admin),
):
    same_origin(request)
    check_uuid(pid)
    row = clean_fields(name, price, stock, description, id_label, require_name, require_id, require_email)
    new_images = save_images(images)  # kapag may in-upload, ito na ang papalit sa lahat ng larawan
    if new_images:
        row["images"] = new_images
        row["image_url"] = new_images[0]
    supabase.table("products").update(row).eq("id", pid).eq("seller_shop_id", shop["id"]).execute()
    return RedirectResponse(f"/s/{slug}/admin", status_code=303)


@app.post("/s/{slug}/admin/products/{pid}/stock")
def admin_set_stock(slug: str, pid: str, request: Request, stock: int = Form(...), shop=Depends(shop_admin)):
    same_origin(request)
    check_uuid(pid)
    if stock < 0 or stock > 100000:
        raise HTTPException(400, "Mali ang stock.")
    supabase.table("products").update({"stock": stock}).eq("id", pid).eq("seller_shop_id", shop["id"]).execute()
    return RedirectResponse(f"/s/{slug}/admin", status_code=303)


@app.post("/s/{slug}/admin/products/{pid}/remove")
def admin_remove_product(slug: str, pid: str, request: Request, shop=Depends(shop_admin)):
    same_origin(request)
    check_uuid(pid)
    supabase.table("products").update({"status": "removed"}).eq("id", pid).eq("seller_shop_id", shop["id"]).execute()
    return RedirectResponse(f"/s/{slug}/admin", status_code=303)


@app.post("/s/{slug}/admin/orders/{oid}/delivered")
def admin_delivered(slug: str, oid: str, request: Request, shop=Depends(shop_admin)):
    same_origin(request)
    supabase.table("orders").update({"delivered": True}).eq("id", oid).eq("seller_shop_id", shop["id"]).execute()
    return RedirectResponse(f"/s/{slug}/admin", status_code=303)


@app.post("/s/{slug}/admin/payout")
def admin_payout(
    slug: str, request: Request,
    amount: float = Form(...), id_number: str = Form(...), gcash: str = Form(...), email: str = Form(...),
    shop=Depends(shop_admin),
):
    same_origin(request)
    if slug == MAIN_SLUG:
        raise HTTPException(400, "Hindi para sa shop na ito.")
    centavos = int(round(amount * 100))
    id_number, gcash, email = CTRL.sub("", id_number).strip(), CTRL.sub("", gcash).strip(), email.strip()
    if centavos < MIN_PAYOUT_CENTAVOS:
        raise HTTPException(400, f"Minimum na withdraw: {peso(MIN_PAYOUT_CENTAVOS)}.")
    if not (1 <= len(id_number) <= 40) or not (1 <= len(gcash) <= 40):
        raise HTTPException(400, "Ilagay ang ID number at GCash account (hanggang 40 letra).")
    if not EMAIL.match(email):
        raise HTTPException(400, "Mali ang email.")
    result = supabase.rpc("request_payout", {
        "p_shop": shop["id"], "p_amount": centavos, "p_id": id_number, "p_gcash": gcash, "p_email": email,
    }).execute().data
    if result == "pending":
        raise HTTPException(409, "May naghihintay ka pang request. Hintayin ang approval ng admin.")
    if result != "ok":
        raise HTTPException(400, "Lagpas sa natitirang pera mo ang halagang iyon.")
    return RedirectResponse(f"/s/{slug}/admin", status_code=303)


# ====================== PLATFORM ADMIN (ikaw lang) ======================
@app.get("/admin", response_class=HTMLResponse)
def platform_page(_: bool = Depends(platform_admin)):
    shops = supabase.table("seller_shops").select("*").order("created_at", desc=True).execute().data
    by_id = {sh["id"]: sh for sh in shops}
    orders_paid = (
        supabase.table("orders").select("seller_shop_id,amount_centavos,fee_centavos,net_centavos")
        .eq("status", "paid").limit(10000).execute().data
    )
    payouts = supabase.table("seller_payouts").select("*").order("created_at", desc=True).limit(1000).execute().data

    def summary(sid):
        return money_summary(
            [o for o in orders_paid if o["seller_shop_id"] == sid],
            [p for p in payouts if p["seller_shop_id"] == sid],
        )

    def row(sh):
        is_main = sh["slug"] == MAIN_SLUG
        acts = ""
        if not is_main and sh["status"] in ("active", "suspended"):
            new = "suspended" if sh["status"] == "active" else "active"
            acts = (f"<form class='inline' method='post' action='/admin/shops/{e(sh['id'])}/status'>"
                    f"<input type='hidden' name='status' value='{new}'>"
                    f"<button class='{'red' if new == 'suspended' else 'gray'}'>"
                    f"{'I-suspend' if new == 'suspended' else 'I-activate'}</button></form>")
        if is_main:
            money = "—"
        else:
            m = summary(sh["id"])
            money = (f"Net: {peso(m['net'])}<br>Naipadala: {peso(m['approved'])}<br>"
                     f"<b>Utang pa: {peso(m['net'] - m['approved'])}</b>")
        return (
            f"<tr><td><b>{e(sh['name'])}</b><br><a href='/s/{e(sh['slug'])}' target='_blank'>/s/{e(sh['slug'])}</a></td>"
            f"<td>{tag(sh['status'])}</td><td>{sh.get('product_credits') or 0}</td>"
            f"<td>{money}</td><td>{acts}</td></tr>"
        )

    shop_rows = "".join(row(sh) for sh in shops)

    pend = [p for p in payouts if p["status"] == "pending"]
    pend_rows = "".join(
        f"<tr><td>{e(p['created_at'][:16].replace('T', ' '))}</td>"
        f"<td><b>{e(by_id.get(p['seller_shop_id'], {}).get('name', '?'))}</b></td>"
        f"<td><b>{peso(p['amount_centavos'])}</b></td>"
        f"<td>GCash: {e(p['gcash_account'])}<br>ID: {e(p['id_number'])}<br>{e(p['email'])}</td>"
        f"<td><form class='inline' method='post' action='/admin/payouts/{e(p['id'])}/approve' "
        f"onsubmit=\"return confirm('Naipadala mo na ba ang {peso(p['amount_centavos'])}?')\"><button>Approve</button></form> "
        f"<form class='inline' method='post' action='/admin/payouts/{e(p['id'])}/reject' "
        f"onsubmit=\"return confirm('I-reject at ibalik sa balanse ng seller?')\"><button class='red'>Reject</button></form></td></tr>"
        for p in pend
    ) or "<tr><td colspan=5>Walang naghihintay na request.</td></tr>"

    done = [p for p in payouts if p["status"] != "pending"][:20]
    done_rows = "".join(
        f"<tr><td>{e(p['created_at'][:16].replace('T', ' '))}</td>"
        f"<td>{e(by_id.get(p['seller_shop_id'], {}).get('name', '?'))}</td>"
        f"<td>{peso(p['amount_centavos'])}</td><td>{tag(p['status'])}</td></tr>"
        for p in done
    )
    done_html = (f"<div class='card'><h2>Mga nakaraang payout</h2><table><tr><th>Petsa</th><th>Shop</th>"
                 f"<th>Halaga</th><th>Status</th></tr>{done_rows}</table></div>") if done_rows else ""

    body = f"""<h1>Platform Admin</h1>
<p><a class="btn" href="/s/{MAIN_SLUG}/admin">Ang shop ko</a></p>
<div class="card"><h2>Mga payout request ({len(pend)})</h2>
<p><small>Ipadala muna ang pera sa GCash ng seller, tapos i-tap ang <b>Approve</b>. Mawawala ang "Please wait" sa panel niya.</small></p>
<table><tr><th>Petsa (UTC)</th><th>Shop</th><th>Halaga</th><th>Detalye</th><th></th></tr>{pend_rows}</table></div>
<div class="card"><h2>Mga shop</h2>
<p><small>Net = pagkatapos ng fees ng PayMongo (kung naibigay ng PayMongo ang fee).</small></p>
<table><tr><th>Shop</th><th>Status</th><th>Slot</th><th>Pera</th><th></th></tr>{shop_rows}</table></div>{done_html}"""
    return shell("Platform Admin", body)


@app.post("/admin/shops/{sid}/status")
def platform_status(sid: str, request: Request, status: str = Form(...), _: bool = Depends(platform_admin)):
    same_origin(request)
    check_uuid(sid)
    if status not in ("active", "suspended"):
        raise HTTPException(400, "Mali ang status.")
    shop = get_shop_by_id(sid)
    if not shop or shop["slug"] == MAIN_SLUG or shop["status"] == "pending":
        raise HTTPException(400, "Hindi puwede.")
    supabase.table("seller_shops").update({"status": status}).eq("id", sid).execute()
    return RedirectResponse("/admin", status_code=303)


def decide_payout(pid, status):
    check_uuid(pid)
    supabase.table("seller_payouts").update({"status": status, "decided_at": iso(now_dt())}) \
        .eq("id", pid).eq("status", "pending").execute()


@app.post("/admin/payouts/{pid}/approve")
def platform_approve(pid: str, request: Request, _: bool = Depends(platform_admin)):
    same_origin(request)
    decide_payout(pid, "approved")
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/payouts/{pid}/reject")
def platform_reject(pid: str, request: Request, _: bool = Depends(platform_admin)):
    same_origin(request)
    decide_payout(pid, "rejected")
    return RedirectResponse("/admin", status_code=303)
