import os, re, hmac, hashlib, json, secrets, html, uuid, time
from typing import List
from urllib.parse import urlparse
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
MIN_PRICE = 10            # minimum na presyo ng produkto ng seller (pesos)
MAIN_MIN_PRICE = 1        # ang sarili mong shop (main) ay puwede ng mas mababa
PLATFORM_FEE_CENTAVOS = 100  # ₱1 na bawas sa kita ng seller sa bawat benta
SLOT_PACKAGES = {"1": (1, 1000), "3": (3, 3000), "6": (6, 5000)}  # slot: (bilang, presyo sa centavos) = ₱10 / ₱30 / ₱50
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
    platform = sum(o.get("platform_fee_centavos") or 0 for o in paid_orders)
    net = sum(net_of(o) for o in paid_orders) - platform
    approved = sum(p["amount_centavos"] for p in payouts if p["status"] == "approved")
    pending = sum(p["amount_centavos"] for p in payouts if p["status"] == "pending")
    return {
        "count": len(paid_orders), "gross": gross, "fees": fees, "platform": platform, "net": net,
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


@app.get("/profile")
def profile_page():
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
    return {"shop": {"name": shop["name"], "slug": slug, "avatar_url": shop.get("avatar_url") or "",
                     "cover_url": shop.get("cover_url") or "", "description": shop.get("description") or ""}, "products": products}


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


CARD_COLS = "id,seller_shop_id,name,image_url,images,price_centavos,stock,sold_count,rating_sum,rating_count"


def more_products(shop, pid):
    """Iba pang produkto ng seller, at produkto ng ibang shop (pinakamabenta muna)."""
    mine = (
        supabase.table("products").select(CARD_COLS)
        .eq("seller_shop_id", shop["id"]).eq("status", "active").neq("id", pid)
        .order("sold_count", desc=True).limit(8).execute().data
    )
    other_shops = supabase.table("seller_shops").select("id,name,slug").eq("status", "active").neq("id", shop["id"]).execute().data
    info = {sh["id"]: sh for sh in other_shops}
    others = []
    if info:
        others = (
            supabase.table("products").select(CARD_COLS)
            .in_("seller_shop_id", list(info)).eq("status", "active")
            .order("sold_count", desc=True).limit(12).execute().data
        )
        for o in others:
            o["shop_name"], o["shop_slug"] = info[o["seller_shop_id"]]["name"], info[o["seller_shop_id"]]["slug"]
    return mine, others


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
    more_shop, more_others = more_products(shop, pid)
    return {
        "id": p["id"], "name": p["name"], "description": p["description"],
        "main_image": p.get("image_url") or "", "images": images,
        "price_centavos": p["price_centavos"], "stock": p["stock"], "sold_count": p["sold_count"],
        "rating_sum": p["rating_sum"], "rating_count": p["rating_count"],
        "require_name": p["require_name"], "require_id": p["require_id"], "require_email": p["require_email"],
        "id_label": p["id_label"], "shop": {"name": shop["name"], "slug": shop["slug"]},
        "reviews": reviews, "signed_in": bool(me), "can_review": can_review,
        "more_shop": more_shop, "more_others": more_others,
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


def start_fee(shop, package):
    """Bayad sa slot ng produkto: ₱10 (1), ₱30 (3), ₱50 (6)."""
    qty, amount = SLOT_PACKAGES[package]
    fee_id = secrets.token_urlsafe(8)
    supabase.table("seller_fees").insert(
        {"id": fee_id, "seller_shop_id": shop["id"], "kind": "unlock", "qty": qty, "amount_centavos": amount}
    ).execute()
    label = f"Slot para sa produkto (x{qty})"
    done = f"{BASE_URL}/fee/done?fee={fee_id}"
    session_id, url = create_checkout(
        amount, label, f"{label} ({shop['slug']})", done, done,
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
        "user": {"name": user["name"], "picture": user["picture"], "email": user["email"]} if user else None,
        "shop": shop,
    }


@app.get("/api/my/orders")
def api_my_orders(request: Request):
    me = read_user(request)
    if not me:
        raise HTTPException(401, "Mag-sign in muna.")
    return (
        supabase.table("orders").select("product_id,product_name,amount_centavos,paid_at")
        .eq("user_id", me["id"]).eq("status", "paid").order("paid_at", desc=True).limit(50).execute().data
    )


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
    seller = get_shop_by_id(order["seller_shop_id"]) if order.get("seller_shop_id") else None
    money["platform_fee_centavos"] = 0 if (not seller or seller["slug"] == MAIN_SLUG) else PLATFORM_FEE_CENTAVOS
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
:root{--bg:#f4f6f8;--surface:#fff;--ink:#14212d;--muted:#5f7283;--line:#dbe3ea;--accent:#f26b1d;--accent-ink:#fff;--ok:#12805c;--bad:#c0392b;--soft:#fff3ea}
@media (prefers-color-scheme:dark){:root{--bg:#0e1822;--surface:#16252f;--ink:#e9f0f5;--muted:#94a8b7;--line:#2a4050;--accent:#ff8a4c;--accent-ink:#1a0d04;--ok:#4cc99b;--bad:#ff8a7a;--soft:#2a1d14}}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}
.app{max-width:820px;margin:0 auto;padding:12px 14px 90px}
.hdr{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin:4px 0 8px}
.hdr h1{font-size:1.3rem;margin:0;word-break:break-word}.hdr small{color:var(--muted)}
.hact{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.tabs{display:flex;gap:6px;overflow-x:auto;position:sticky;top:0;z-index:5;background:var(--bg);padding:8px 0 10px;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tabs button{flex:none;border:1px solid var(--line);background:var(--surface);color:var(--ink);border-radius:99px;padding:8px 14px;font:inherit;font-weight:600;font-size:.9rem;cursor:pointer}
.tabs button[aria-selected="true"]{background:var(--accent);color:var(--accent-ink);border-color:var(--accent)}
h1,h2,h3{margin:0}h2{font-size:1.1rem;margin-bottom:10px}h3{font-size:1rem;margin:16px 0 8px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px;margin-bottom:14px;overflow-x:auto}
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:14px}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:12px}
.stat span{display:block;color:var(--muted);font-size:.8rem}.stat b{font-size:1.35rem}
.stat.hi{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}.stat.hi span{color:inherit;opacity:.9}
.muted{color:var(--muted);font-size:.88rem}
.field{margin-bottom:12px}.field>label,.lbl{display:block;font-weight:600;font-size:.9rem;margin-bottom:4px}
input,textarea,select{width:100%;font:inherit;padding:10px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--ink)}
input[type=checkbox],input[type=radio]{width:auto}
.chk{display:flex;align-items:center;gap:8px;margin:6px 0;font-size:.95rem}
button,a.btn{font:inherit;font-weight:600;background:var(--accent);color:var(--accent-ink);border:0;border-radius:10px;padding:10px 16px;cursor:pointer;text-decoration:none;display:inline-block}
button.sec,a.btn.sec,button.gray,a.btn.gray{background:transparent;color:var(--ink);border:1px solid var(--line)}
button.red{background:var(--bad);color:#fff}
.sm{padding:6px 12px!important;font-size:.85rem!important}
button:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.pcard{display:flex;gap:12px;padding:12px 0;border-top:1px solid var(--line)}.pcard:first-of-type{border-top:0}
.pcard img,.pcard .ph{width:72px;height:72px;border-radius:10px;object-fit:cover;background:var(--bg);flex:none;display:grid;place-items:center;font-size:1.8rem}
.pinfo{flex:1;min-width:0}.pinfo b{word-break:break-word}
.acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
form.inline{display:inline-flex;gap:6px;align-items:center;margin:0}form.inline input{width:76px;padding:6px}
.pkgs{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px}
.pkg{position:relative;display:block}.pkg input{position:absolute;opacity:0}
.pkg span{display:block;text-align:center;border:2px solid var(--line);border-radius:12px;padding:10px 4px;cursor:pointer}
.pkg b{display:block;font-size:1.05rem}.pkg small{color:var(--muted)}
.pkg input:checked+span{border-color:var(--accent);background:var(--soft)}
.pkg input:focus-visible+span{outline:3px solid var(--accent);outline-offset:2px}
.sum{width:100%;border-collapse:collapse}.sum td{padding:8px 0;border-bottom:1px solid var(--line)}.sum td:last-child{text-align:right;white-space:nowrap}
.sum tr.total td{font-weight:800;font-size:1.05rem;border-bottom:0}.sum tr.neg td:last-child{color:var(--bad)}
.ocard{border-top:1px solid var(--line);padding:12px 0}.ocard:first-of-type{border-top:0}
.ocard .top{display:flex;justify-content:space-between;gap:8px}
.note{background:var(--soft);border-radius:10px;padding:10px 12px;font-size:.9rem;margin-bottom:12px}
.steps{list-style:none;margin:0 0 12px;padding:0}.steps li{padding:4px 0}
.imgs{display:grid;grid-template-columns:repeat(auto-fill,minmax(96px,1fr));gap:10px;margin:6px 0 12px}
.imgx{display:block;font-size:.78rem}.imgx img{width:100%;aspect-ratio:1;object-fit:cover;border-radius:10px;display:block;margin-bottom:4px}
.cover-prev{height:100px;border-radius:12px;background:var(--bg) center/cover no-repeat;margin-bottom:8px}
.linkbox{display:flex;gap:6px}.linkbox input{flex:1}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border-bottom:1px solid var(--line);padding:6px;text-align:left;vertical-align:top}
.tag{padding:2px 8px;border-radius:99px;background:var(--line);font-size:.78rem}
.paid,.active,.approved{background:#cdf3e1;color:#064b36}.paid_conflict,.soldout,.suspended,.rejected{background:#ffd6d2;color:#7a1d14}.pending{background:#fff0c2;color:#5c4400}
"""

ADMIN_JS = """
const TABS = ['buod', 'produkto', 'order', 'kita', 'profile'];
function showTab(t) {
  if (!TABS.includes(t)) t = 'buod';
  TABS.forEach(x => { const s = document.getElementById('t_' + x); if (s) s.hidden = x !== t; });
  document.querySelectorAll('.tabs button').forEach(b => b.setAttribute('aria-selected', String(b.dataset.t === t)));
}
if (document.querySelector('.tabs')) {
  document.querySelectorAll('.tabs button').forEach(b => b.addEventListener('click', () => {
    history.replaceState(null, '', '#' + b.dataset.t); showTab(b.dataset.t); window.scrollTo(0, 0);
  }));
  window.addEventListener('hashchange', () => showTab(location.hash.slice(1)));
  showTab(location.hash.slice(1));
}
function copyLink() {
  const i = document.getElementById('shoplink');
  i.select();
  try { navigator.clipboard.writeText(i.value); } catch (err) { document.execCommand('copy'); }
  document.getElementById('copied').textContent = 'Nakopya na!';
}
function setupResize(id, max, noteId, dim) {
  const input = document.getElementById(id);
  if (!input) return;
  dim = dim || 900;
  input.addEventListener('change', async ev => {
    const files = Array.from(ev.target.files).slice(0, max);
    const dt = new DataTransfer();
    try {
      for (const f of files) {
        if (!f.type.startsWith('image/')) continue;
        const bmp = await createImageBitmap(f);
        const k = Math.min(1, dim / Math.max(bmp.width, bmp.height));
        const c = document.createElement('canvas');
        c.width = Math.round(bmp.width * k); c.height = Math.round(bmp.height * k);
        const x = c.getContext('2d');
        x.fillStyle = '#fff'; x.fillRect(0, 0, c.width, c.height);
        x.drawImage(bmp, 0, 0, c.width, c.height);
        const blob = await new Promise(r => c.toBlob(r, 'image/jpeg', 0.85));
        dt.items.add(new File([blob], 'photo.jpg', {type: 'image/jpeg'}));
      }
      ev.target.files = dt.files;
      const n = document.getElementById(noteId);
      if (n) n.textContent = dt.files.length + ' larawan (na-resize)';
    } catch (err) {}
  });
}
setupResize('img_main', 1, 'note_main');
setupResize('img', 5, 'imgnote');
setupResize('img_avatar', 1, 'note_avatar');
setupResize('img_cover', 1, 'note_cover', 1200);
"""


def shell(title, body):
    return HTMLResponse(
        f"""<!DOCTYPE html><html lang="fil"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>{e(title)}</title><style>{CSS}</style></head><body>
{body}<script>{ADMIN_JS}</script></body></html>""",
        headers={"Cache-Control": "no-store"},
    )


def tag(status, label=None):
    return f"<span class='tag {e(status)}'>{e(label or status)}</span>"


def back(slug, tab):
    return RedirectResponse(f"/s/{slug}/admin#{tab}", status_code=303)


def product_form(action, p=None, min_price=MIN_PRICE):
    p = p or {}
    editing = bool(p)
    chk = lambda k: "checked" if p.get(k, True) else ""
    price = f"{p['price_centavos'] / 100:.2f}" if editing else ""
    existing = ""
    if editing:
        main = p.get("image_url") or ""
        car = p.get("images") or []
        if main:
            existing += (f"<div class='lbl'>Kasalukuyang main image</div><div class='imgs'><label class='imgx'>"
                         f"<img src='{e(main)}' alt=''><span class='chk'><input type='checkbox' name='remove_main'> Alisin</span></label></div>")
        if car:
            existing += "<div class='lbl'>Kasalukuyang carousel (lagyan ng check ang aalisin)</div><div class='imgs'>" + "".join(
                f"<label class='imgx'><img src='{e(u)}' alt=''><span class='chk'><input type='checkbox' name='remove_img' value='{e(u)}'> Alisin</span></label>"
                for u in car) + "</div>"
    return f"""<form method="post" action="{action}" enctype="multipart/form-data">
<div class="field"><label>Pangalan ng produkto</label><input name="name" required maxlength="100" value="{e(p.get('name', ''))}"></div>
<div class="field"><label>Presyo (₱, hindi bababa sa {min_price})</label>
<input name="price" type="number" inputmode="decimal" step="0.01" min="{min_price}" required value="{price}"></div>
<div class="field"><label>Ilan ang available (stock)</label><input name="stock" type="number" min="0" step="1" required value="{p.get('stock', 1)}"></div>
<div class="field"><label>Description</label><textarea name="description" maxlength="500" rows="4">{e(p.get('description', ''))}</textarea></div>
{existing}
<div class="field"><label>{'Palitan ang main image' if editing else 'Main image'} (1 larawan, lalabas sa homepage)</label>
<input id="img_main" name="main_image" type="file" accept="image/*"><small id="note_main" class="muted"></small></div>
<div class="field"><label>{'Magdagdag ng larawan sa carousel' if editing else 'Mga larawan ng carousel'} (hanggang 5 lahat, lalabas sa product page)</label>
<input id="img" name="images" type="file" accept="image/*" multiple><small id="imgnote" class="muted"></small></div>
<div class="field"><span class="lbl">Ano ang hihingin sa buyer?</span>
<label class="chk"><input type="checkbox" name="require_name" {chk('require_name')}> Pangalan</label>
<label class="chk"><input type="checkbox" name="require_id" {chk('require_id')}> ID / Username</label>
<label class="chk"><input type="checkbox" name="require_email" {chk('require_email')}> Email</label></div>
<div class="field"><label>Tawag sa ID field (hal. Game ID, Username, Account No.)</label>
<input name="id_label" maxlength="30" value="{e(p.get('id_label', 'ID'))}"></div>
<button>I-save</button></form>"""


def slot_packages_form(base):
    pk = lambda key, qty, price, extra="": (
        f"<label class='pkg'><input type='radio' name='package' value='{key}' {'checked' if key == '1' else ''}>"
        f"<span><b>{qty} slot</b><small>₱{price}</small>{extra}</span></label>")
    return f"""<form method="post" action="{base}/slots">
<div class="pkgs">{pk('1', 1, 10)}{pk('3', 3, 30)}{pk('6', 6, 50, '<br><small>Tipid</small>')}</div>
<button>Magbayad (GCash / Maya / QR Ph)</button></form>"""


@app.get("/s/{slug}/admin", response_class=HTMLResponse)
def admin_page(slug: str, shop=Depends(shop_admin)):
    release_expired()
    sid = shop["id"]
    base = f"/s/{slug}/admin"
    is_main = slug == MAIN_SLUG
    min_price = MAIN_MIN_PRICE if is_main else MIN_PRICE
    credits = shop.get("product_credits") or 0
    shop_url = f"{BASE_URL}/s/{slug}"

    prods = (
        supabase.table("products").select("*").eq("seller_shop_id", sid).neq("status", "removed")
        .order("created_at", desc=True).execute().data
    )
    ords = (
        supabase.table("orders").select("*").eq("seller_shop_id", sid).neq("status", "failed")
        .order("created_at", desc=True).limit(200).execute().data
    )
    m = None
    payouts = []
    if not is_main:
        paid_all = (
            supabase.table("orders").select("amount_centavos,fee_centavos,net_centavos,platform_fee_centavos")
            .eq("seller_shop_id", sid).eq("status", "paid").limit(10000).execute().data
        )
        payouts = (
            supabase.table("seller_payouts").select("*").eq("seller_shop_id", sid)
            .order("created_at", desc=True).limit(50).execute().data
        )
        m = money_summary(paid_all, payouts)
    sold = m["count"] if m else len([o for o in ords if o["status"] == "paid"])

    stat = lambda label, value, hi=False: f"<div class='stat{' hi' if hi else ''}'><span>{label}</span><b>{value}</b></div>"

    # ---------- Buod ----------
    stats = "".join([
        stat("Kita na puwedeng i-withdraw", peso(m["available"]), True) if m else stat("Mga produkto", len(prods), True),
        stat("Mga nabenta", sold),
        stat("Kabuuang benta", peso(m["gross"])) if m else stat("Mga order", len(ords)),
        stat("Natitirang slot", credits) if not is_main else stat("Mga produkto", len(prods)),
    ])
    mark = lambda ok: "✅" if ok else "⬜"
    steps = f"""<ul class="steps">
<li>{mark(is_main or credits > 0 or len(prods) > 0)} Bumili ng slot para sa produkto</li>
<li>{mark(len(prods) > 0)} Magdagdag ng unang produkto</li>
<li>{mark(bool(shop.get('description') or shop.get('avatar_url') or shop.get('cover_url')))} Lagyan ng profile ang shop</li>
<li>⬜ Ibahagi ang link ng shop mo</li></ul>"""
    t_buod = f"""<div class="stats">{stats}</div>
<div class="card"><h2>Mga hakbang</h2>{steps}
<label class="lbl" for="shoplink">Link ng shop mo</label>
<div class="linkbox"><input id="shoplink" readonly value="{e(shop_url)}"><button type="button" onclick="copyLink()">Kopyahin</button></div>
<p class="muted"><span id="copied"></span> Lalabas din ang mga produkto mo sa unang page ng site.</p></div>"""

    # ---------- Produkto ----------
    if is_main or credits > 0:
        add_card = (f"<div class='card'><h2>Magdagdag ng produkto</h2>"
                    + (f"<p class='note'>Natitirang slot: <b>{credits}</b> (1 slot = 1 produkto)</p>" if not is_main else "")
                    + product_form(base + "/products", None, min_price) + "</div>")
    else:
        add_card = "<div class='card'><h2>Magdagdag ng produkto</h2><p class='note'>Wala ka nang slot. Bumili ng slot sa ibaba para makapagdagdag.</p></div>"
    slots_card = "" if is_main else f"""<div class="card"><h2>Bumili ng slot</h2>
<p class="muted">Bawat slot ay para sa 1 produktong ipa-publish. Ang minimum na presyo ng produkto ay ₱{MIN_PRICE}.</p>{slot_packages_form(base)}</div>"""

    def pcard(p):
        pid = e(p["id"])
        thumb = p.get("image_url") or ((p.get("images") or [""])[0])
        img = f"<img src='{e(thumb)}' alt=''>" if thumb else "<div class='ph'>🛍️</div>"
        rating = f"★ {p['rating_sum'] / p['rating_count']:.1f} ({p['rating_count']})" if p["rating_count"] else "Wala pang rating"
        out = " " + tag("soldout", "sold out") if p["stock"] <= 0 else ""
        return f"""<div class="pcard">{img}<div class="pinfo"><b>{e(p['name'])}</b>
<div class="muted">{peso(p['price_centavos'])} · {p['sold_count']} nabenta · {rating}</div>
<div style="margin-top:6px"><form class="inline" method="post" action="{base}/products/{pid}/stock">
<span class="muted">Stock</span><input name="stock" type="number" min="0" step="1" value="{p['stock']}" aria-label="Stock"><button class="sm">OK</button></form>{out}</div>
<div class="acts"><a class="btn sec sm" href="/p/{pid}" target="_blank">Tingnan</a>
<a class="btn sec sm" href="{base}/products/{pid}/edit">I-edit</a>
<form class="inline" method="post" action="{base}/products/{pid}/remove" onsubmit="return confirm('Alisin sa shop ang produktong ito?')"><button class="red sm">Alisin</button></form></div>
</div></div>"""

    plist = "".join(pcard(p) for p in prods) or "<p class='muted'>Wala pang produkto.</p>"
    t_produkto = f"{add_card}{slots_card}<div class='card'><h2>Mga produkto ({len(prods)})</h2>{plist}</div>"

    # ---------- Order ----------
    def ocard(o):
        act = ""
        if o["status"] in ("paid", "paid_conflict"):
            act = ("<span class='muted'>Na-deliver na</span>" if o.get("delivered") else
                   f"<form class='inline' method='post' action='{base}/orders/{e(o['id'])}/delivered'><button class='sec sm'>Markahan: Na-deliver</button></form>")
        return f"""<div class="ocard"><div class="top"><b>{e(o['product_name'])}</b><span>{peso(o['amount_centavos'])}</span></div>
<div class="muted">{e(o['created_at'][:16].replace('T', ' '))} UTC · {tag(o['status'])}</div>
<div class="muted">{e(o.get('buyer_name') or '—')} · ID: {e(o.get('buyer_id') or '—')} · {e(o.get('email') or '—')}</div>
{('<div class="note">' + e(o['note']) + '</div>') if o.get('note') else ''}<div style="margin-top:6px">{act}</div></div>"""
    olist = "".join(ocard(o) for o in ords) or "<p class='muted'>Wala pang order.</p>"
    t_order = f"<div class='card'><h2>Mga order ({len(ords)})</h2>{olist}</div>"

    # ---------- Kita ----------
    t_kita = ""
    if m:
        waiting = next((p for p in payouts if p["status"] == "pending"), None)
        if waiting:
            wbox = (f"<div class='note'><b>Please wait for approval of admin.</b><br>Hiniling mo: {peso(waiting['amount_centavos'])}</div>")
        elif m["available"] < MIN_PAYOUT_CENTAVOS:
            wbox = f"<p class='muted'>Wala pang puwedeng i-withdraw (minimum {peso(MIN_PAYOUT_CENTAVOS)}).</p>"
        else:
            wbox = f"""<form method="post" action="{base}/payout">
<div class="field"><label>Halaga (₱), hanggang {peso(m['available'])}</label>
<input name="amount" type="number" inputmode="decimal" step="0.01" min="{MIN_PAYOUT_CENTAVOS / 100}" max="{m['available'] / 100:.2f}" required></div>
<div class="field"><label>ID number mo</label><input name="id_number" maxlength="40" required></div>
<div class="field"><label>GCash account (number)</label><input name="gcash" maxlength="40" inputmode="tel" required></div>
<div class="field"><label>Email mo</label><input name="email" type="email" maxlength="120" required></div>
<button>OK</button></form>"""
        labels = {"pending": "Naghihintay ng approval", "approved": "Naipadala / approved", "rejected": "Na-reject (ibinalik sa balanse)"}
        hist = "".join(
            f"<tr><td>{e(p['created_at'][:16].replace('T', ' '))}</td><td>{peso(p['amount_centavos'])}</td><td>{tag(p['status'], labels.get(p['status'], p['status']))}</td></tr>"
            for p in payouts)
        hist_html = f"<h3>Mga withdraw mo</h3><table><tr><th>Petsa (UTC)</th><th>Halaga</th><th>Status</th></tr>{hist}</table>" if hist else ""
        est = "<p class='muted'>May mga order na hindi pa alam ang eksaktong PayMongo fee, kaya buong halaga ang ipinapakita para sa mga iyon.</p>" if m["est"] else ""
        t_kita = f"""<div class="card"><h2>Kita mo</h2>
<table class="sum">
<tr><td>Kabuuang benta ({m['count']})</td><td>{peso(m['gross'])}</td></tr>
<tr class="neg"><td>Fees ng PayMongo</td><td>-{peso(m['fees'])}</td></tr>
<tr class="neg"><td>Fee ng platform (₱1 bawat benta)</td><td>-{peso(m['platform'])}</td></tr>
<tr><td><b>Net na kita mo</b></td><td><b>{peso(m['net'])}</b></td></tr>
<tr><td>Naipadala na sa iyo</td><td>{peso(m['approved'])}</td></tr>
<tr><td>Naghihintay ng approval</td><td>{peso(m['pending'])}</td></tr>
<tr class="total"><td>Natitira (puwedeng i-withdraw)</td><td>{peso(m['available'])}</td></tr></table>{est}</div>
<div class="card"><h2>Mag-withdraw</h2>{wbox}{hist_html}</div>"""

    # ---------- Profile ----------
    cover_prev = (f"<div class='cover-prev' style=\"background-image:url('{e(shop['cover_url'])}')\"></div>" if shop.get("cover_url") else "")
    av_prev = (f"<p><img src='{e(shop['avatar_url'])}' width='72' height='72' alt='' style='border-radius:50%;object-fit:cover'></p>" if shop.get("avatar_url") else "")
    t_profile = f"""<div class="card"><h2>Profile ng shop</h2>
<form method="post" action="{base}/profile" enctype="multipart/form-data">
<div class="field"><span class="lbl">Background image (banner)</span>{cover_prev}
<input id="img_cover" name="cover" type="file" accept="image/*"><small id="note_cover" class="muted"></small>
{'<label class="chk"><input type="checkbox" name="remove_cover"> Alisin ang background</label>' if shop.get('cover_url') else ''}</div>
<div class="field"><span class="lbl">Logo / larawan ng shop</span>{av_prev}
<input id="img_avatar" name="avatar" type="file" accept="image/*"><small id="note_avatar" class="muted"></small>
{'<label class="chk"><input type="checkbox" name="remove_avatar"> Alisin ang logo</label>' if shop.get('avatar_url') else ''}</div>
<div class="field"><label>Pangalan ng shop</label><input name="name" required maxlength="60" value="{e(shop['name'])}"></div>
<div class="field"><label>Description (tungkol sa shop mo)</label><textarea name="description" maxlength="500" rows="4">{e(shop.get('description') or '')}</textarea></div>
<button>I-save ang profile</button></form></div>"""

    tabs = [("buod", "Buod"), ("produkto", "Produkto"), ("order", "Order")]
    if m:
        tabs.append(("kita", "Kita"))
    tabs.append(("profile", "Profile"))
    tabs_html = "".join(f"<button type='button' role='tab' data-t='{k}' aria-selected='false'>{v}</button>" for k, v in tabs)
    owner_link = "<a class='btn sec sm' href='/admin'>Platform admin</a>" if is_main else ""
    body = f"""<div class="app">
<div class="hdr"><div><h1>{e(shop['name'])}</h1><small>/s/{e(slug)}</small></div>
<div class="hact">{owner_link}<a class="btn sec sm" href="/s/{e(slug)}" target="_blank">Shop ko</a><a class="btn sec sm" href="/">Homepage</a>
<form class="inline" method="post" action="/logout"><button class="sec sm">Mag-logout</button></form></div></div>
<nav class="tabs" role="tablist">{tabs_html}</nav>
<section id="t_buod">{t_buod}</section>
<section id="t_produkto" hidden>{t_produkto}</section>
<section id="t_order" hidden>{t_order}</section>
<section id="t_kita" hidden>{t_kita}</section>
<section id="t_profile" hidden>{t_profile}</section></div>"""
    return shell("Admin", body)


def save_image(image):
    """I-upload ang larawan sa Supabase Storage at ibalik ang public URL ('' kung walang larawan)."""
    if image is None or not getattr(image, "filename", ""):
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


def delete_image(url):
    """Burahin ang file sa storage (best-effort)."""
    prefix = f"{SUPABASE_URL}/storage/v1/object/public/{BUCKET}/"
    if url and url.startswith(prefix):
        try:
            supabase.storage.from_(BUCKET).remove([url[len(prefix):]])
        except Exception as ex:
            print("DELETE IMAGE ERROR:", ex)


def clean_fields(name, price, stock, description, id_label, require_name, require_id, require_email, min_price):
    name = name.strip()[:100]
    centavos = int(round(price * 100))
    if not name or centavos < min_price * 100:
        raise HTTPException(400, f"Kailangan ng pangalan at presyong hindi bababa sa ₱{min_price}.")
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


def min_price_for(slug):
    return MAIN_MIN_PRICE if slug == MAIN_SLUG else MIN_PRICE


@app.post("/s/{slug}/admin/profile")
async def admin_profile(slug: str, request: Request, shop=Depends(shop_admin)):
    same_origin(request)
    form = await request.form()
    name = CTRL.sub("", str(form.get("name") or "")).strip()[:60] or shop["name"]
    description = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(form.get("description") or "")).strip()[:500]
    row = {"name": name, "description": description}
    for field, col, rm in (("avatar", "avatar_url", "remove_avatar"), ("cover", "cover_url", "remove_cover")):
        f = form.get(field)
        if f is not None and getattr(f, "filename", ""):
            row[col] = save_image(f)
        elif form.get(rm):
            row[col] = ""
    supabase.table("seller_shops").update(row).eq("id", shop["id"]).execute()
    for col in ("avatar_url", "cover_url"):
        if col in row and shop.get(col) and row[col] != shop[col]:
            delete_image(shop[col])
    return back(slug, "profile")


@app.post("/s/{slug}/admin/slots")
def admin_slots(slug: str, request: Request, package: str = Form("1"), shop=Depends(shop_admin)):
    same_origin(request)
    if slug == MAIN_SLUG:
        return back(slug, "produkto")
    if package not in SLOT_PACKAGES:
        raise HTTPException(400, "Piliin ang 1, 3, o 6 na slot.")
    try:
        url = start_fee(shop, package)
    except Exception as ex:
        print("SLOT FEE ERROR:", ex)
        raise HTTPException(502, "Hindi nagawa ang bayad. Subukan ulit.")
    return RedirectResponse(url, status_code=303)


@app.post("/s/{slug}/admin/products")
def admin_add_product(
    slug: str, request: Request,
    name: str = Form(...), price: float = Form(...), stock: int = Form(...),
    description: str = Form(""), id_label: str = Form("ID"),
    main_image: UploadFile = File(None),
    images: List[UploadFile] = File(default=[]),
    require_name: str = Form(None), require_id: str = Form(None), require_email: str = Form(None),
    shop=Depends(shop_admin),
):
    same_origin(request)
    row = clean_fields(name, price, stock, description, id_label, require_name, require_id, require_email, min_price_for(slug))
    row["seller_shop_id"] = shop["id"]

    # 1 slot bawat produkto. Ang shop mo (main) ay walang slot.
    consumed = False
    if slug != MAIN_SLUG:
        if not supabase.rpc("use_product_credit", {"p_shop": shop["id"]}).execute().data:
            raise HTTPException(402, "Wala ka nang slot. Bumili muna ng slot para sa produktong ito.")
        consumed = True
    try:
        row["images"] = save_images(images)  # carousel (product page)
        main_url = save_image(main_image)    # main image (homepage / listahan)
        row["image_url"] = main_url or (row["images"][0] if row["images"] else "")
        supabase.table("products").insert(row).execute()
    except Exception as ex:
        if consumed:  # ibalik ang slot kung hindi na-save ang produkto
            supabase.rpc("add_product_credits", {"p_shop": shop["id"], "p_n": 1}).execute()
        if isinstance(ex, HTTPException):
            raise
        print("ADD PRODUCT ERROR:", ex)
        raise HTTPException(502, "Hindi nai-save ang produkto. Subukan ulit.")
    return back(slug, "produkto")


@app.get("/s/{slug}/admin/products/{pid}/edit", response_class=HTMLResponse)
def admin_edit_page(slug: str, pid: str, shop=Depends(shop_admin)):
    check_uuid(pid)
    rows = (
        supabase.table("products").select("*")
        .eq("id", pid).eq("seller_shop_id", shop["id"]).limit(1).execute().data
    )
    if not rows:
        raise HTTPException(404, "Wala")
    action = f"/s/{e(slug)}/admin/products/{e(pid)}/edit"
    body = (f"<div class='app'><p><a href='/s/{e(slug)}/admin#produkto'>← Balik sa admin panel</a></p>"
            f"<div class='card'><h2>I-edit ang produkto</h2>{product_form(action, rows[0], min_price_for(slug))}</div></div>")
    return shell("I-edit", body)


@app.post("/s/{slug}/admin/products/{pid}/edit")
def admin_edit_product(
    slug: str, pid: str, request: Request,
    name: str = Form(...), price: float = Form(...), stock: int = Form(...),
    description: str = Form(""), id_label: str = Form("ID"),
    main_image: UploadFile = File(None),
    images: List[UploadFile] = File(default=[]),
    remove_img: List[str] = Form(default=[]), remove_main: str = Form(None),
    require_name: str = Form(None), require_id: str = Form(None), require_email: str = Form(None),
    shop=Depends(shop_admin),
):
    same_origin(request)
    check_uuid(pid)
    row = clean_fields(name, price, stock, description, id_label, require_name, require_id, require_email, min_price_for(slug))
    cur = (
        supabase.table("products").select("image_url,images")
        .eq("id", pid).eq("seller_shop_id", shop["id"]).limit(1).execute().data
    )
    if not cur:
        raise HTTPException(404, "Wala")
    old_main = cur[0].get("image_url") or ""
    old_imgs = cur[0].get("images") or []

    # Alisin lang ang mga piniling larawan; ang iba ay mananatili, at idadagdag ang mga bago.
    drop = set(remove_img) & set(old_imgs)
    keep = [u for u in old_imgs if u not in drop]
    incoming = [f for f in (images or []) if getattr(f, "filename", "")]
    if len(keep) + len(incoming) > MAX_IMAGES:
        raise HTTPException(400, f"Hanggang {MAX_IMAGES} larawan lang sa carousel. Lagyan ng check ang aalisin muna.")
    combined = keep + save_images(incoming)
    new_main = save_image(main_image)
    if new_main:
        main = new_main
    elif remove_main:
        main = ""
    else:
        main = old_main
    if not main and combined:
        main = combined[0]
    row["images"], row["image_url"] = combined, main
    supabase.table("products").update(row).eq("id", pid).eq("seller_shop_id", shop["id"]).execute()

    still = set(combined) | ({main} if main else set())
    for u in ({old_main} | set(old_imgs)) - {""} - still:
        delete_image(u)
    return back(slug, "produkto")


@app.post("/s/{slug}/admin/products/{pid}/stock")
def admin_set_stock(slug: str, pid: str, request: Request, stock: int = Form(...), shop=Depends(shop_admin)):
    same_origin(request)
    check_uuid(pid)
    if stock < 0 or stock > 100000:
        raise HTTPException(400, "Mali ang stock.")
    supabase.table("products").update({"stock": stock}).eq("id", pid).eq("seller_shop_id", shop["id"]).execute()
    return back(slug, "produkto")


@app.post("/s/{slug}/admin/products/{pid}/remove")
def admin_remove_product(slug: str, pid: str, request: Request, shop=Depends(shop_admin)):
    same_origin(request)
    check_uuid(pid)
    supabase.table("products").update({"status": "removed"}).eq("id", pid).eq("seller_shop_id", shop["id"]).execute()
    return back(slug, "produkto")


@app.post("/s/{slug}/admin/orders/{oid}/delivered")
def admin_delivered(slug: str, oid: str, request: Request, shop=Depends(shop_admin)):
    same_origin(request)
    supabase.table("orders").update({"delivered": True}).eq("id", oid).eq("seller_shop_id", shop["id"]).execute()
    return back(slug, "order")


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
    return back(slug, "kita")


# ====================== PLATFORM ADMIN (ikaw lang) ======================
@app.get("/admin", response_class=HTMLResponse)
def platform_page(_: bool = Depends(platform_admin)):
    shops = supabase.table("seller_shops").select("*").order("created_at", desc=True).execute().data
    by_id = {sh["id"]: sh for sh in shops}
    orders_paid = (
        supabase.table("orders").select("seller_shop_id,amount_centavos,fee_centavos,net_centavos,platform_fee_centavos")
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
