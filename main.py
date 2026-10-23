import os, re, hmac, hashlib, json, secrets, html, uuid
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

RESERVE_MINUTES = 30   # gaano katagal naka-reserve ang skin habang nagbabayad ang buyer
MIN_PRICE = 1          # minimum na presyo (pesos)

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
supabase = create_client(SUPABASE_URL, os.environ["SUPABASE_KEY"])
BUCKET = "product-images"
MAX_IMAGE = 8 * 1024 * 1024
security = HTTPBasic()
e = html.escape


def now_dt():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="seconds")


def release_expired():
    """Ibalik sa 'available' ang mga skin na na-reserve pero hindi binayaran."""
    cutoff = iso(now_dt() - timedelta(minutes=RESERVE_MINUTES))
    supabase.table("products").update(
        {"status": "available", "reserved_by": None, "reserved_at": None}
    ).eq("status", "reserved").lt("reserved_at", cutoff).execute()


def release_product(product_id, order_id):
    supabase.table("products").update(
        {"status": "available", "reserved_by": None, "reserved_at": None}
    ).eq("id", product_id).eq("reserved_by", order_id).eq("status", "reserved").execute()


# ====================== PUBLIC ======================
@app.get("/")
def home():
    return FileResponse("index.html")


@app.get("/api/products")
def api_products():
    release_expired()
    rows = (
        supabase.table("products")
        .select("id,name,description,image_url,price_centavos,require_name,require_roblox_id,require_email")
        .eq("status", "available")
        .order("created_at", desc=True)
        .execute()
        .data
    )
    return rows


class CheckoutIn(BaseModel):
    product_id: str
    roblox_name: str = ""
    roblox_id: str = ""
    email: str = ""


ROBLOX_NAME = re.compile(r"^[A-Za-z0-9_]{3,20}$")
ROBLOX_ID = re.compile(r"^\d{1,12}$")
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$")


@app.post("/api/checkout")
def api_checkout(body: CheckoutIn):
    try:
        uuid.UUID(body.product_id)
    except ValueError:
        raise HTTPException(400, "Mali ang produkto.")

    release_expired()
    info = (
        supabase.table("products")
        .select("require_name,require_roblox_id,require_email")
        .eq("id", body.product_id).eq("status", "available")
        .limit(1).execute().data
    )
    if not info:
        raise HTTPException(409, "Pasensya, hindi na available ang skin na ito.")
    need = info[0]

    name = body.roblox_name.strip()
    rid = body.roblox_id.strip()
    email = body.email.strip()
    if need["require_name"] and not ROBLOX_NAME.match(name):
        raise HTTPException(400, "Mali ang Roblox username (3-20 letra, numero, o _).")
    if need["require_roblox_id"] and not ROBLOX_ID.match(rid):
        raise HTTPException(400, "Mali ang Roblox ID (numero lang).")
    if need["require_email"] and not EMAIL.match(email):
        raise HTTPException(400, "Mali ang email.")
    # Itatabi lang ang mga hinihingi ng admin para sa produktong ito
    name = name if need["require_name"] else None
    rid = rid if need["require_roblox_id"] else None
    email = email if need["require_email"] else None

    order_id = secrets.token_urlsafe(8)

    # Atomic na pag-reserve: isang buyer lang ang makakakuha
    claim = (
        supabase.table("products")
        .update({"status": "reserved", "reserved_by": order_id, "reserved_at": iso(now_dt())})
        .eq("id", body.product_id)
        .eq("status", "available")
        .execute()
    )
    if not claim.data:
        raise HTTPException(409, "Pasensya, hindi na available ang skin na ito.")
    product = claim.data[0]

    try:
        supabase.table("orders").insert({
            "id": order_id,
            "product_id": product["id"],
            "product_name": product["name"],
            "amount_centavos": product["price_centavos"],
            "roblox_id": rid,
            "roblox_name": name,
            "email": email,
        }).execute()

        payload = {"data": {"attributes": {
            "line_items": [{
                "currency": "PHP",
                "amount": product["price_centavos"],
                "name": product["name"],
                "quantity": 1,
            }],
            "payment_method_types": ["gcash", "paymaya", "qrph", "card"],
            "success_url": f"{BASE_URL}/success?order={order_id}",
            "cancel_url": f"{BASE_URL}/cancel?order={order_id}",
            "description": f"Roblox skin: {product['name']} (order {order_id})",
            "metadata": {"order_id": order_id},
        }}}
        r = requests.post(
            "https://api.paymongo.com/v1/checkout_sessions",
            json=payload,
            auth=(PAYMONGO_SECRET, ""),
            timeout=30,
        )
    except Exception as ex:
        print("CHECKOUT ERROR:", ex)
        release_product(product["id"], order_id)
        raise HTTPException(502, "Hindi nagawa ang checkout. Subukan ulit.")

    if r.status_code != 200:
        print("PAYMONGO ERROR:", r.status_code, r.text)
        release_product(product["id"], order_id)
        supabase.table("orders").update({"status": "failed"}).eq("id", order_id).execute()
        raise HTTPException(502, "Hindi nagawa ang checkout. Subukan ulit.")

    data = r.json()["data"]
    supabase.table("orders").update({"session_id": data["id"]}).eq("id", order_id).execute()
    return {"checkout_url": data["attributes"]["checkout_url"]}


@app.get("/api/order/{order_id}")
def order_status(order_id: str):
    res = supabase.table("orders").select("status").eq("id", order_id).limit(1).execute()
    if not res.data:
        raise HTTPException(404, "Not found")
    return {"status": res.data[0]["status"]}


@app.get("/success", response_class=HTMLResponse)
def success(order: str = ""):
    safe = e(order)
    return f"""<!DOCTYPE html><html lang="fil"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Bayad</title></head>
<body style="font-family:sans-serif;text-align:center;padding:40px">
<h2 id="msg">Pinoproseso ang bayad mo...</h2>
<p>Order: {safe}</p>
<p id="sub">Ipapadala ang skin sa Roblox account mo pagkatapos ma-verify ng admin.</p>
<a href="/">Balik sa shop</a>
<script>
let tries = 0;
async function check() {{
  try {{
    const r = await fetch("/api/order/" + encodeURIComponent({json.dumps(order)}));
    const d = await r.json();
    if (d.status === "paid") {{ document.getElementById("msg").textContent = "Bayad na! Salamat."; return; }}
    if (d.status === "paid_conflict") {{ document.getElementById("msg").textContent = "Bayad na, pero may problema sa stock. Kokontakin ka ng admin para sa refund."; return; }}
  }} catch (e) {{}}
  if (++tries < 40) setTimeout(check, 3000);
  else document.getElementById("msg").textContent = "Matagal ang proseso. I-refresh o kontakin ang admin.";
}}
check();
</script></body></html>"""


@app.get("/cancel", response_class=HTMLResponse)
def cancel(order: str = ""):
    res = (
        supabase.table("orders")
        .update({"status": "cancelled"})
        .eq("id", order).eq("status", "pending")
        .execute()
    )
    if res.data:
        release_product(res.data[0]["product_id"], order)
    return "<h2>Na-cancel ang bayad.</h2><a href='/'>Balik sa shop</a>"


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
    if event["data"]["attributes"]["type"] == "checkout_session.payment.paid":
        session = event["data"]["attributes"]["data"]
        order_id = (session["attributes"].get("metadata") or {}).get("order_id")
        if not order_id:
            return {"ok": True}

        upd = (
            supabase.table("orders")
            .update({"status": "paid", "paid_at": iso(now_dt()), "session_id": session["id"]})
            .eq("id", order_id)
            .in_("status", ["pending", "cancelled", "failed"])  # idempotent
            .execute()
        )
        if upd.data:
            order = upd.data[0]
            sold = (
                supabase.table("products")
                .update({"status": "sold", "sold_to": order_id, "reserved_by": None})
                .eq("id", order["product_id"])
                .neq("status", "sold")
                .execute()
            )
            if not sold.data:
                supabase.table("orders").update({
                    "status": "paid_conflict",
                    "note": "Naibenta na ang skin sa ibang buyer. I-refund ang customer na ito.",
                }).eq("id", order_id).execute()
            print("PAID:", order_id)

    return {"ok": True}


# ====================== ADMIN ======================
def admin_auth(creds: HTTPBasicCredentials = Depends(security)):
    ok = ADMIN_KEY and hmac.compare_digest(creds.password.encode(), ADMIN_KEY.encode())
    if not ok:
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return creds.username


def same_origin(request: Request):
    src = request.headers.get("origin") or request.headers.get("referer") or ""
    if not src.startswith(BASE_URL):
        raise HTTPException(403, "Bad origin")


CSS = """
body{font-family:system-ui,sans-serif;margin:0;padding:16px;background:#f3f6f9;color:#14202b}
h1,h2{margin:.4em 0}.card{background:#fff;border:1px solid #d6e0e8;border-radius:12px;padding:14px;margin-bottom:16px;overflow-x:auto}
input,textarea,button{font:inherit;padding:8px;border:1px solid #b9c8d4;border-radius:8px;width:100%;margin:4px 0 10px}
button{background:#0b6bcb;color:#fff;border:0;cursor:pointer;width:auto;padding:8px 14px}
button.red{background:#c0392b}button.gray{background:#5b6f80}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border-bottom:1px solid #e3ebf1;padding:6px;text-align:left;vertical-align:top}
input[type=checkbox]{width:auto;margin:0 8px 0 0}label.chk{display:flex;align-items:center;margin:4px 0;font-size:1rem}
.tag{padding:2px 8px;border-radius:99px;background:#e3ebf1;font-size:.8rem}
.paid{background:#cdf3e1}.paid_conflict{background:#ffd6d2}.reserved{background:#fff0c2}.sold{background:#d9d9ff}
form.inline{display:inline}form.inline button{margin:0;padding:4px 10px}
"""


ADMIN_JS = """
document.getElementById('img').addEventListener('change', async ev => {
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
    dt.items.add(new File([blob], 'skin.jpg', {type: 'image/jpeg'}));
    ev.target.files = dt.files;
    document.getElementById('imgnote').textContent = 'Na-resize: ' + Math.round(blob.size / 1024) + ' KB';
  } catch (err) {}
});
"""


def tag(status):
    return f"<span class='tag {e(status)}'>{e(status)}</span>"


@app.get("/admin", response_class=HTMLResponse)
def admin_page(_: str = Depends(admin_auth)):
    release_expired()
    prods = (
        supabase.table("products").select("*").neq("status", "removed")
        .order("created_at", desc=True).execute().data
    )
    ords = (
        supabase.table("orders").select("*").neq("status", "failed")
        .order("created_at", desc=True).limit(200).execute().data
    )

    def needs(p):
        parts = []
        if p.get("require_name"): parts.append("Username")
        if p.get("require_roblox_id"): parts.append("ID")
        if p.get("require_email"): parts.append("Email")
        return ", ".join(parts) or "Wala"

    prod_rows = "".join(
        "<tr><td>"
        + (f"<img src='{e(p['image_url'])}' width='48' height='48' style='object-fit:cover;border-radius:8px;vertical-align:middle;margin-right:8px'>"
           if p.get("image_url") else "")
        + f"<b>{e(p['name'])}</b><br><small>{e(p.get('description') or '')}</small></td>"
        f"<td>₱{p['price_centavos'] / 100:.2f}</td><td>{needs(p)}</td><td>{tag(p['status'])}</td><td>"
        + (
            f"<form class='inline' method='post' action='/admin/products/{e(p['id'])}/remove'>"
            f"<button class='red'>Alisin</button></form>"
            if p["status"] != "sold" else ""
        )
        + "</td></tr>"
        for p in prods
    ) or "<tr><td colspan=5>Wala pang produkto.</td></tr>"

    def order_row(o):
        rid = e(o.get("roblox_id") or "")
        rlink = (
            f"ID: <a href='https://www.roblox.com/users/{rid}/profile' target='_blank' rel='noopener'>{rid}</a>"
            if rid else "ID: —"
        )
        action = ""
        if o["status"] in ("paid", "paid_conflict"):
            action = (
                "Na-deliver na" if o.get("delivered") else
                f"<form class='inline' method='post' action='/admin/orders/{e(o['id'])}/delivered'>"
                f"<button class='gray'>Markahan: Na-deliver</button></form>"
            )
        return (
            f"<tr><td>{e(o['created_at'][:16].replace('T', ' '))}</td>"
            f"<td>{e(o['product_name'])}<br>₱{o['amount_centavos'] / 100:.2f}</td>"
            f"<td>{e(o.get('roblox_name') or '—')}<br>{rlink}</td>"
            f"<td>{e(o.get('email') or '—')}</td>"
            f"<td>{tag(o['status'])}<br>{e(o.get('note') or '')}</td><td>{action}</td></tr>"
        )

    order_rows = "".join(order_row(o) for o in ords) or "<tr><td colspan=6>Wala pang order.</td></tr>"

    body = f"""<!DOCTYPE html><html lang="fil"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin</title><style>{CSS}</style></head><body>
<h1>Admin Panel</h1>
<div class="card"><h2>Magdagdag ng skin</h2>
<form method="post" action="/admin/products" enctype="multipart/form-data">
<label>Pangalan ng produkto</label><input name="name" required maxlength="100">
<label>Presyo (₱, minimum {MIN_PRICE})</label><input name="price" type="number" step="0.01" min="{MIN_PRICE}" required>
<label>Description (optional)</label><textarea name="description" maxlength="500" rows="2"></textarea>
<label>Larawan (optional, JPG/PNG/WEBP)</label><input id="img" name="image" type="file" accept="image/*">
<small id="imgnote"></small>
<p><b>Ano ang hihingin sa buyer?</b></p>
<label class="chk"><input type="checkbox" name="require_name" checked> Roblox username</label>
<label class="chk"><input type="checkbox" name="require_roblox_id" checked> Roblox ID</label>
<label class="chk"><input type="checkbox" name="require_email" checked> Email</label>
<button>Idagdag</button></form></div>
<div class="card"><h2>Mga produkto</h2><table><tr><th>Produkto</th><th>Presyo</th><th>Hinihingi</th><th>Status</th><th></th></tr>{prod_rows}</table></div>
<div class="card"><h2>Mga order</h2><table><tr><th>Petsa (UTC)</th><th>Produkto</th><th>Roblox</th><th>Email</th><th>Status</th><th></th></tr>{order_rows}</table></div>
<script>{ADMIN_JS}</script></body></html>"""
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})


def detect_image(data: bytes):
    if data[:3] == b"\xff\xd8\xff":
        return "jpg", "image/jpeg"
    if data[:4] == b"\x89PNG":
        return "png", "image/png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp", "image/webp"
    return None


@app.post("/admin/products")
def admin_add_product(
    request: Request,
    name: str = Form(...),
    price: float = Form(...),
    description: str = Form(""),
    image: UploadFile = File(None),
    require_name: str = Form(None),
    require_roblox_id: str = Form(None),
    require_email: str = Form(None),
    _: str = Depends(admin_auth),
):
    same_origin(request)
    name = name.strip()[:100]
    centavos = int(round(price * 100))
    if not name or centavos < MIN_PRICE * 100:
        raise HTTPException(400, f"Kailangan ng pangalan at presyong hindi bababa sa ₱{MIN_PRICE}.")

    image_url = ""
    if image is not None and image.filename:
        data = image.file.read(MAX_IMAGE + 1)
        if len(data) > MAX_IMAGE:
            raise HTTPException(400, "Masyadong malaki ang larawan (max 8 MB).")
        kind = detect_image(data)
        if not kind:
            raise HTTPException(400, "JPG, PNG, o WEBP lang ang tinatanggap.")
        ext, ctype = kind
        path = f"{uuid.uuid4().hex}.{ext}"
        try:
            supabase.storage.from_(BUCKET).upload(path, data, {"content-type": ctype})
        except Exception as ex:
            print("UPLOAD ERROR:", ex)
            raise HTTPException(502, "Hindi na-upload ang larawan. Subukan ulit.")
        image_url = f"{SUPABASE_URL}/storage/v1/object/public/{BUCKET}/{path}"

    supabase.table("products").insert({
        "name": name,
        "description": description.strip()[:500],
        "image_url": image_url,
        "price_centavos": centavos,
        "require_name": bool(require_name),
        "require_roblox_id": bool(require_roblox_id),
        "require_email": bool(require_email),
    }).execute()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/products/{pid}/remove")
def admin_remove_product(pid: str, request: Request, _: str = Depends(admin_auth)):
    same_origin(request)
    uuid.UUID(pid)
    supabase.table("products").update({"status": "removed"}).eq("id", pid).neq("status", "sold").execute()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/orders/{oid}/delivered")
def admin_delivered(oid: str, request: Request, _: str = Depends(admin_auth)):
    same_origin(request)
    supabase.table("orders").update({"delivered": True}).eq("id", oid).execute()
    return RedirectResponse("/admin", status_code=303)
