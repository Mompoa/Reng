import os, re, hmac, hashlib, json, secrets, html, uuid, time
from datetime import datetime, timezone, timedelta
import requests
from pydantic import BaseModel
from supabase import create_client
from fastapi import FastAPI, Request, HTTPException, Depends, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

app = FastAPI()

PAYMONGO_SECRET = os.getenv("PAYMONGO_SECRET", "")
WEBHOOK_SECRET = os.getenv("PAYMONGO_WEBHOOK_SECRET", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
ADMIN_KEY = os.getenv("ADMIN_KEY", "")

RESERVE_MINUTES = 30      # gaano katagal naka-reserve ang stock habang nagbabayad ang buyer
MIN_PRICE = 1             # minimum na presyo ng produkto (pesos)
FEE_CENTAVOS = 100        # ₱1 na bayad ng seller (paggawa ng shop, at pag-unlock ng products)
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
    return RedirectResponse(f"/s/{MAIN_SLUG}")


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
        .select("id,name,description,image_url,price_centavos,stock,require_name,require_id,require_email,id_label")
        .eq("seller_shop_id", shop["id"]).eq("status", "active")
        .order("created_at", desc=True).execute().data
    )
    return {"shop": {"name": shop["name"], "slug": slug}, "products": products}


class CheckoutIn(BaseModel):
    product_id: str
    buyer_name: str = ""
    buyer_id: str = ""
    email: str = ""


EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$")
CTRL = re.compile(r"[\x00-\x1f\x7f]")


@app.post("/api/checkout")
def api_checkout(body: CheckoutIn):
    check_uuid(body.product_id)
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
    return FileResponse("signup.html")


class SignupIn(BaseModel):
    name: str
    username: str
    password: str


def start_fee(shop, kind):
    fee_id = secrets.token_urlsafe(8)
    supabase.table("seller_fees").insert(
        {"id": fee_id, "seller_shop_id": shop["id"], "kind": kind}
    ).execute()
    label = "Bayad sa paggawa ng shop" if kind == "shop" else "Bayad para makapag-add ng produkto"
    done = f"{BASE_URL}/fee/done?fee={fee_id}"
    session_id, url = create_checkout(
        FEE_CENTAVOS, label, f"{label} ({shop['slug']})", done, done,
        {"fee_id": fee_id}, methods=("gcash", "paymaya", "qrph"),  # walang card: malulugi sa fixed fee
    )
    supabase.table("seller_fees").update({"session_id": session_id}).eq("id", fee_id).execute()
    return url


@app.post("/api/signup")
def api_signup(body: SignupIn):
    name = CTRL.sub("", body.name).strip()
    slug = body.username.strip().lower()
    pw = body.password
    if not (1 <= len(name) <= 60):
        raise HTTPException(400, "Ilagay ang pangalan ng shop (hanggang 60 letra).")
    if not SLUG_RE.match(slug) or slug in RESERVED:
        raise HTTPException(400, "Username: 3-30 letra/numero/gitling (a-z, 0-9, -), at hindi puwede ang mga nakareserba.")
    if not (8 <= len(pw) <= 72):
        raise HTTPException(400, "Ang password ay 8 hanggang 72 letra.")

    cutoff = iso(now_dt() - timedelta(minutes=PENDING_SHOP_MINUTES))
    supabase.table("seller_shops").delete().eq("status", "pending").lt("created_at", cutoff).execute()
    if get_shop(slug):
        raise HTTPException(409, "Ginagamit na ang username na ito.")

    salt, h = hash_pw(pw)
    try:
        shop = supabase.table("seller_shops").insert(
            {"slug": slug, "name": name, "pw_salt": salt, "pw_hash": h, "status": "pending"}
        ).execute().data[0]
    except Exception:
        raise HTTPException(409, "Ginagamit na ang username na ito.")
    try:
        return {"checkout_url": start_fee(shop, "shop")}
    except Exception as ex:
        print("SIGNUP ERROR:", ex)
        supabase.table("seller_shops").delete().eq("id", shop["id"]).execute()
        raise HTTPException(502, "Hindi nagawa ang bayad. Subukan ulit.")


@app.get("/api/fee/{fee_id}")
def fee_status(fee_id: str):
    rows = supabase.table("seller_fees").select("status,kind,seller_shop_id").eq("id", fee_id).limit(1).execute().data
    if not rows:
        raise HTTPException(404, "Not found")
    shop = get_shop_by_id(rows[0]["seller_shop_id"])
    return {"status": rows[0]["status"], "kind": rows[0]["kind"], "slug": shop["slug"] if shop else ""}


@app.get("/fee/done", response_class=HTMLResponse)
def fee_done(fee: str = ""):
    return f"""<!DOCTYPE html><html lang="fil"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Bayad</title></head>
<body style="font-family:sans-serif;text-align:center;padding:40px">
<h2 id="msg">Kinukumpirma ang bayad mo...</h2><p id="sub"></p>
<script>const API="/api/fee/", ID={json.dumps(fee)};
function done(d) {{
  document.getElementById("msg").textContent = d.kind === "shop" ? "Bayad na! Handa na ang shop mo." : "Bayad na! Puwede ka nang magdagdag ng produkto.";
  const a = document.createElement("a"); a.href = "/s/" + d.slug + "/admin"; a.textContent = "Pumunta sa admin panel";
  document.getElementById("sub").append(a);
}}
{POLL_JS}</script></body></html>"""


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
            if fee["kind"] == "shop":
                supabase.table("seller_shops").update({"status": "active"}) \
                    .eq("id", fee["seller_shop_id"]).eq("status", "pending").execute()
            else:
                supabase.table("seller_shops").update({"products_unlocked": True}) \
                    .eq("id", fee["seller_shop_id"]).execute()
            print("FEE PAID:", fee_id, fee["kind"])
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
    if upd.data and prev != "pending":
        # Nabalik na dati ang stock (expired/cancelled). Kunin ulit; kung wala na, i-flag para sa refund.
        if not reserve_stock(order["product_id"]):
            supabase.table("orders").update({
                "status": "paid_conflict",
                "note": "Sold out na ang produkto nang dumating ang bayad. I-refund ang customer na ito.",
            }).eq("id", order_id).execute()
    print("PAID:", order_id)
    return {"ok": True}


# ====================== AUTH ======================
def unauthorized(realm):
    return HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": f'Basic realm="{realm}"'})


def shop_admin(slug: str, creds: HTTPBasicCredentials = Depends(security)):
    shop = get_shop(slug)
    if not shop:
        raise HTTPException(404, "Walang ganitong shop.")
    realm = f"shop-{slug}"
    if creds is None:
        raise unauthorized(realm)
    if is_locked(slug):
        raise HTTPException(429, "Maraming maling subok. Subukan ulit pagkalipas ng 5 minuto.")
    if slug == MAIN_SLUG:
        ok = bool(ADMIN_KEY) and hmac.compare_digest(creds.password.encode(), ADMIN_KEY.encode())
    else:
        ok = (
            bool(shop["pw_hash"])
            and creds.username.strip().lower() == slug
            and verify_pw(creds.password, shop["pw_salt"], shop["pw_hash"])
        )
    if not ok:
        note_fail(slug)
        raise unauthorized(realm)
    FAILS.pop(slug, None)
    if shop["status"] == "pending":
        raise HTTPException(403, "Hindi pa bayad ang paggawa ng shop na ito.")
    if shop["status"] == "suspended":
        raise HTTPException(403, "Na-suspend ang shop na ito. Makipag-ugnayan sa admin.")
    return shop


def platform_admin(creds: HTTPBasicCredentials = Depends(security)):
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
const img = document.getElementById('img');
if (img) img.addEventListener('change', async ev => {
  const f = ev.target.files[0];
  if (!f || !f.type.startsWith('image/')) return;
  try {
    const bmp = await createImageBitmap(f);
    const k = Math.min(1, 900 / Math.max(bmp.width, bmp.height));
    const c = document.createElement('canvas');
    c.width = Math.round(bmp.width * k); c.height = Math.round(bmp.height * k);
    const x = c.getContext('2d');
    x.fillStyle = '#fff'; x.fillRect(0, 0, c.width, c.height);
    x.drawImage(bmp, 0, 0, c.width, c.height);
    const blob = await new Promise(r => c.toBlob(r, 'image/jpeg', 0.85));
    const dt = new DataTransfer();
    dt.items.add(new File([blob], 'photo.jpg', {type: 'image/jpeg'}));
    ev.target.files = dt.files;
    document.getElementById('imgnote').textContent = 'Na-resize: ' + Math.round(blob.size / 1024) + ' KB';
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
    hint = " — mag-upload ng bago para palitan" if p.get("image_url") else ""
    return f"""<form method="post" action="{action}" enctype="multipart/form-data">
<label>Pangalan ng produkto</label><input name="name" required maxlength="100" value="{e(p.get('name', ''))}">
<label>Presyo (₱, minimum {MIN_PRICE})</label><input name="price" type="number" step="0.01" min="{MIN_PRICE}" required value="{price}">
<label>Ilan ang available (stock)</label><input name="stock" type="number" min="0" step="1" required value="{p.get('stock', 1)}">
<label>Description (optional)</label><textarea name="description" maxlength="500" rows="2">{e(p.get('description', ''))}</textarea>
<label>Larawan (optional, JPG/PNG/WEBP){hint}</label>
<input id="img" name="image" type="file" accept="image/*"><small id="imgnote"></small>
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

    if shop["products_unlocked"]:
        add_card = f'<div class="card"><h2>Magdagdag ng produkto</h2>{product_form(base + "/products")}</div>'
    else:
        add_card = f"""<div class="card"><h2>Magdagdag ng produkto</h2>
<p>Para makapagdagdag ng produkto, magbayad muna ng <b>₱1</b> (isang beses lang).</p>
<form method="post" action="{base}/unlock"><button>Magbayad ng ₱1 para i-unlock</button></form></div>"""

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

    top = (f"<p><a href='/admin'>Platform admin</a> · " if is_main else "<p>") + \
          f"<a href='/s/{e(slug)}' target='_blank'>Tingnan ang shop ko</a></p>"
    body = f"""<h1>{e(shop['name'])} — Admin</h1>{top}{money_card}{add_card}
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


@app.post("/s/{slug}/admin/unlock")
def admin_unlock(slug: str, request: Request, shop=Depends(shop_admin)):
    same_origin(request)
    if shop["products_unlocked"]:
        return RedirectResponse(f"/s/{slug}/admin", status_code=303)
    try:
        url = start_fee(shop, "unlock")
    except Exception as ex:
        print("UNLOCK ERROR:", ex)
        raise HTTPException(502, "Hindi nagawa ang bayad. Subukan ulit.")
    return RedirectResponse(url, status_code=303)


@app.post("/s/{slug}/admin/products")
def admin_add_product(
    slug: str, request: Request,
    name: str = Form(...), price: float = Form(...), stock: int = Form(...),
    description: str = Form(""), id_label: str = Form("ID"),
    image: UploadFile = File(None),
    require_name: str = Form(None), require_id: str = Form(None), require_email: str = Form(None),
    shop=Depends(shop_admin),
):
    same_origin(request)
    if not shop["products_unlocked"]:
        raise HTTPException(402, "Magbayad muna ng ₱1 para makapagdagdag ng produkto.")
    row = clean_fields(name, price, stock, description, id_label, require_name, require_id, require_email)
    row["image_url"] = save_image(image)
    row["seller_shop_id"] = shop["id"]
    supabase.table("products").insert(row).execute()
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
    img = f"<p><img src='{e(p['image_url'])}' width='120' style='border-radius:8px'></p>" if p.get("image_url") else ""
    action = f"/s/{e(slug)}/admin/products/{e(pid)}/edit"
    return shell("I-edit", f"<p><a href='/s/{e(slug)}/admin'>← Balik</a></p><div class='card'><h2>I-edit ang produkto</h2>{img}{product_form(action, p)}</div>")


@app.post("/s/{slug}/admin/products/{pid}/edit")
def admin_edit_product(
    slug: str, pid: str, request: Request,
    name: str = Form(...), price: float = Form(...), stock: int = Form(...),
    description: str = Form(""), id_label: str = Form("ID"),
    image: UploadFile = File(None),
    require_name: str = Form(None), require_id: str = Form(None), require_email: str = Form(None),
    shop=Depends(shop_admin),
):
    same_origin(request)
    check_uuid(pid)
    row = clean_fields(name, price, stock, description, id_label, require_name, require_id, require_email)
    new_url = save_image(image)
    if new_url:
        row["image_url"] = new_url
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
            f"<td>{tag(sh['status'])}</td><td>{'Oo' if sh['products_unlocked'] else 'Hindi pa'}</td>"
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
<table><tr><th>Shop</th><th>Status</th><th>Product unlock</th><th>Pera</th><th></th></tr>{shop_rows}</table></div>{done_html}"""
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
