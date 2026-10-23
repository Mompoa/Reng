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

RESERVE_MINUTES = 30   # gaano katagal naka-reserve ang stock habang nagbabayad ang buyer
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


def check_uuid(value):
    try:
        uuid.UUID(value)
    except ValueError:
        raise HTTPException(400, "Mali ang ID.")


# ---------- Stock helpers (atomic, sa pamamagitan ng SQL functions) ----------
def reserve_stock(product_id) -> bool:
    res = supabase.rpc("reserve_stock", {"p_id": product_id}).execute()
    return bool(res.data)


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


# ====================== PUBLIC ======================
@app.get("/")
def home():
    return FileResponse("index.html")


@app.get("/api/products")
def api_products():
    release_expired()
    return (
        supabase.table("products")
        .select("id,name,description,image_url,price_centavos,stock,require_name,require_id,require_email,id_label")
        .eq("status", "active")
        .order("created_at", desc=True)
        .execute()
        .data
    )


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

    name = CTRL.sub("", body.buyer_name).strip()
    bid = CTRL.sub("", body.buyer_id).strip()
    email = body.email.strip()
    if product["require_name"] and not (1 <= len(name) <= 60):
        raise HTTPException(400, "Ilagay ang pangalan (hanggang 60 letra).")
    if product["require_id"] and not (1 <= len(bid) <= 60):
        raise HTTPException(400, f"Ilagay ang {product['id_label']} (hanggang 60 letra).")
    if product["require_email"] and not EMAIL.match(email):
        raise HTTPException(400, "Mali ang email.")
    # Itatabi lang ang mga hinihingi ng admin para sa produktong ito
    name = name if product["require_name"] else None
    bid = bid if product["require_id"] else None
    email = email if product["require_email"] else None

    # Atomic na pag-reserve ng 1 piraso
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
            "product_id": product["id"],
            "product_name": product["name"],
            "amount_centavos": product["price_centavos"],
            "buyer_name": name,
            "buyer_id": bid,
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
            "description": f"{product['name']} (order {order_id})",
            "metadata": {"order_id": order_id},
        }}}
        r = requests.post(
            "https://api.paymongo.com/v1/checkout_sessions",
            json=payload, auth=(PAYMONGO_SECRET, ""), timeout=30,
        )
    except Exception as ex:
        print("CHECKOUT ERROR:", ex)
        fail()

    if r.status_code != 200:
        print("PAYMONGO ERROR:", r.status_code, r.text)
        fail()

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
    return f"""<!DOCTYPE html><html lang="fil"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Bayad</title></head>
<body style="font-family:sans-serif;text-align:center;padding:40px">
<h2 id="msg">Pinoproseso ang bayad mo...</h2>
<p>Order: {e(order)}</p>
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
        supabase.table("orders").update({"status": "cancelled"})
        .eq("id", order).eq("status", "pending").execute()
    )
    if res.data:
        release_stock(res.data[0]["product_id"])
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

        found = supabase.table("orders").select("*").eq("id", order_id).limit(1).execute().data
        if not found or found[0]["status"] in ("paid", "paid_conflict"):
            return {"ok": True}  # idempotent
        order = found[0]
        prev = order["status"]

        upd = (
            supabase.table("orders")
            .update({"status": "paid", "paid_at": iso(now_dt()), "session_id": session["id"]})
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
input[type=checkbox]{width:auto;margin:0 8px 0 0}label.chk{display:flex;align-items:center;margin:4px 0}
button,a.btn{background:#0b6bcb;color:#fff;border:0;cursor:pointer;width:auto;padding:8px 14px;border-radius:8px;text-decoration:none;display:inline-block;font-size:1rem}
button.red{background:#c0392b}button.gray{background:#5b6f80}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{border-bottom:1px solid #e3ebf1;padding:6px;text-align:left;vertical-align:top}
.tag{padding:2px 8px;border-radius:99px;background:#e3ebf1;font-size:.8rem}
.paid{background:#cdf3e1}.paid_conflict{background:#ffd6d2}.pending{background:#fff0c2}.soldout{background:#ffd6d2}
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


def tag(status):
    return f"<span class='tag {e(status)}'>{e(status)}</span>"


def product_form(action, p=None):
    p = p or {}
    chk = lambda k: "checked" if p.get(k, True) else ""
    return f"""<form method="post" action="{action}" enctype="multipart/form-data">
<label>Pangalan ng produkto</label><input name="name" required maxlength="100" value="{e(p.get('name', ''))}">
<label>Presyo (₱, minimum {MIN_PRICE})</label><input name="price" type="number" step="0.01" min="{MIN_PRICE}" required value="{p['price_centavos'] / 100 if p else ''}">
<label>Ilan ang available (stock)</label><input name="stock" type="number" min="0" step="1" required value="{p.get('stock', 1)}">
<label>Description (optional)</label><textarea name="description" maxlength="500" rows="2">{e(p.get('description', ''))}</textarea>
<label>Larawan (optional, JPG/PNG/WEBP){' — mag-upload ng bago para palitan' if p.get('image_url') else ''}</label>
<input id="img" name="image" type="file" accept="image/*"><small id="imgnote"></small>
<p><b>Ano ang hihingin sa buyer?</b></p>
<label class="chk"><input type="checkbox" name="require_name" {chk('require_name')}> Pangalan</label>
<label class="chk"><input type="checkbox" name="require_id" {chk('require_id')}> ID / Username</label>
<label>Tawag sa ID field (hal. Game ID, Username, Account No.)</label>
<input name="id_label" maxlength="30" value="{e(p.get('id_label', 'ID'))}">
<label class="chk"><input type="checkbox" name="require_email" {chk('require_email')}> Email</label>
<button>I-save</button></form>"""


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
        f"<td><form class='inline' method='post' action='/admin/products/{e(p['id'])}/stock'>"
        f"<input name='stock' type='number' min='0' step='1' value='{p['stock']}' aria-label='Stock'>"
        f"<button>OK</button></form>"
        + (" <span class='tag soldout'>sold out</span>" if p["stock"] <= 0 else "")
        + f"</td><td>{needs(p)}</td><td>"
        f"<a class='btn gray' href='/admin/products/{e(p['id'])}/edit'>I-edit</a> "
        f"<form class='inline' method='post' action='/admin/products/{e(p['id'])}/remove' "
        f"onsubmit=\"return confirm('Alisin sa shop ang produktong ito?')\"><button class='red'>Alisin</button></form>"
        "</td></tr>"
        for p in prods
    ) or "<tr><td colspan=5>Wala pang produkto.</td></tr>"

    def order_row(o):
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
            f"<td>{e(o.get('buyer_name') or '—')}<br>ID: {e(o.get('buyer_id') or '—')}<br>{e(o.get('email') or '—')}</td>"
            f"<td>{tag(o['status'])}<br>{e(o.get('note') or '')}</td><td>{action}</td></tr>"
        )

    order_rows = "".join(order_row(o) for o in ords) or "<tr><td colspan=5>Wala pang order.</td></tr>"

    body = f"""<h1>Admin Panel</h1>
<div class="card"><h2>Magdagdag ng produkto</h2>{product_form("/admin/products")}</div>
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


@app.post("/admin/products")
def admin_add_product(
    request: Request,
    name: str = Form(...), price: float = Form(...), stock: int = Form(...),
    description: str = Form(""), id_label: str = Form("ID"),
    image: UploadFile = File(None),
    require_name: str = Form(None), require_id: str = Form(None), require_email: str = Form(None),
    _: str = Depends(admin_auth),
):
    same_origin(request)
    row = clean_fields(name, price, stock, description, id_label, require_name, require_id, require_email)
    row["image_url"] = save_image(image)
    supabase.table("products").insert(row).execute()
    return RedirectResponse("/admin", status_code=303)


@app.get("/admin/products/{pid}/edit", response_class=HTMLResponse)
def admin_edit_page(pid: str, _: str = Depends(admin_auth)):
    check_uuid(pid)
    rows = supabase.table("products").select("*").eq("id", pid).limit(1).execute().data
    if not rows:
        raise HTTPException(404, "Wala")
    p = rows[0]
    img = f"<p><img src='{e(p['image_url'])}' width='120' style='border-radius:8px'></p>" if p.get("image_url") else ""
    return shell("I-edit", f"<p><a href='/admin'>← Balik</a></p><div class='card'><h2>I-edit ang produkto</h2>{img}{product_form(f'/admin/products/{e(pid)}/edit', p)}</div>")


@app.post("/admin/products/{pid}/edit")
def admin_edit_product(
    pid: str, request: Request,
    name: str = Form(...), price: float = Form(...), stock: int = Form(...),
    description: str = Form(""), id_label: str = Form("ID"),
    image: UploadFile = File(None),
    require_name: str = Form(None), require_id: str = Form(None), require_email: str = Form(None),
    _: str = Depends(admin_auth),
):
    same_origin(request)
    check_uuid(pid)
    row = clean_fields(name, price, stock, description, id_label, require_name, require_id, require_email)
    new_url = save_image(image)
    if new_url:
        row["image_url"] = new_url
    supabase.table("products").update(row).eq("id", pid).execute()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/products/{pid}/stock")
def admin_set_stock(pid: str, request: Request, stock: int = Form(...), _: str = Depends(admin_auth)):
    same_origin(request)
    check_uuid(pid)
    if stock < 0 or stock > 100000:
        raise HTTPException(400, "Mali ang stock.")
    supabase.table("products").update({"stock": stock}).eq("id", pid).execute()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/products/{pid}/remove")
def admin_remove_product(pid: str, request: Request, _: str = Depends(admin_auth)):
    same_origin(request)
    check_uuid(pid)
    supabase.table("products").update({"status": "removed"}).eq("id", pid).execute()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/orders/{oid}/delivered")
def admin_delivered(oid: str, request: Request, _: str = Depends(admin_auth)):
    same_origin(request)
    supabase.table("orders").update({"delivered": True}).eq("id", oid).execute()
    return RedirectResponse("/admin", status_code=303)
