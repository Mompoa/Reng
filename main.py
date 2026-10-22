import os, hmac, hashlib, json, secrets
from datetime import datetime, timezone
import requests
from supabase import create_client
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse

app = FastAPI()

PAYMONGO_SECRET = os.getenv("PAYMONGO_SECRET", "")
WEBHOOK_SECRET = os.getenv("PAYMONGO_WEBHOOK_SECRET", "")
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
ADMIN_KEY = os.getenv("ADMIN_KEY", "")

# Server-side lang ang key na ito (service_role / secret key). Huwag ilagay sa HTML.
supabase = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_KEY"])

# Dapat tugma sa PRODUCTS sa index.html
PRODUCTS = {
    "1": {"name": "Reviewer Pack", "price": 200.00},
    "2": {"name": "Android App Template", "price": 200.00},
    "3": {"name": "Logo Design", "price": 200.00},
}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_order(order_id: str):
    res = supabase.table("orders").select("*").eq("id", order_id).limit(1).execute()
    return res.data[0] if res.data else None


# ---------- Pages ----------
@app.get("/")
def home():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    items = "".join(
        f"<p><b>{p['name']}</b> - ₱{p['price']:.2f} "
        f"<a href='/checkout/{pid}'><button>Bayaran</button></a></p>"
        for pid, p in PRODUCTS.items()
    )
    return HTMLResponse(f"<h2>Shop</h2>{items}")


@app.get("/checkout/{pid}")
def checkout(pid: str):
    product = PRODUCTS.get(pid)
    if not product:
        raise HTTPException(404, "Product not found")

    amount = int(round(product["price"] * 100))  # centavos
    order_id = secrets.token_urlsafe(8)

    supabase.table("orders").insert({
        "id": order_id,
        "product_id": pid,
        "product_name": product["name"],
        "amount_centavos": amount,
    }).execute()

    payload = {
        "data": {
            "attributes": {
                "line_items": [{
                    "currency": "PHP",
                    "amount": amount,
                    "name": product["name"],
                    "quantity": 1,
                }],
                "payment_method_types": ["gcash", "paymaya", "qrph", "card"],
                "success_url": f"{BASE_URL}/success?order={order_id}",
                "cancel_url": f"{BASE_URL}/cancel?order={order_id}",
                "description": f"Order {order_id}: {product['name']}",
                "metadata": {"order_id": order_id, "product_id": pid},
            }
        }
    }
    r = requests.post(
        "https://api.paymongo.com/v1/checkout_sessions",
        json=payload,
        auth=(PAYMONGO_SECRET, ""),
        timeout=30,
    )
    if r.status_code != 200:
        supabase.table("orders").update({"status": "failed"}).eq("id", order_id).execute()
        raise HTTPException(502, r.text)

    data = r.json()["data"]
    supabase.table("orders").update({"session_id": data["id"]}).eq("id", order_id).execute()
    return RedirectResponse(data["attributes"]["checkout_url"])


@app.get("/api/order/{order_id}")
def order_status(order_id: str):
    row = get_order(order_id)
    if not row:
        raise HTTPException(404, "Not found")
    return {"status": row["status"]}


@app.get("/success", response_class=HTMLResponse)
def success(order: str = ""):
    return f"""<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:sans-serif;text-align:center;padding:40px">
<h2 id="msg">Pinoproseso ang bayad mo...</h2>
<p>Order: {order}</p><a href="/">Balik</a>
<script>
let tries = 0;
async function check() {{
  try {{
    const r = await fetch("/api/order/{order}");
    const d = await r.json();
    if (d.status === "paid") {{
      document.getElementById("msg").textContent = "Bayad na! Salamat.";
      return;
    }}
  }} catch (e) {{}}
  if (++tries < 40) setTimeout(check, 3000);
  else document.getElementById("msg").textContent = "Matagal ang proseso. I-refresh o kontakin kami.";
}}
check();
</script></body></html>"""


@app.get("/cancel", response_class=HTMLResponse)
def cancel(order: str = ""):
    supabase.table("orders").update({"status": "cancelled"}) \
        .eq("id", order).eq("status", "pending").execute()
    return "<h2>Na-cancel ang bayad.</h2><a href='/'>Balik</a>"


# ---------- Webhook ----------
@app.post("/webhook")
async def webhook(request: Request):
    raw = await request.body()
    sig_header = request.headers.get("Paymongo-Signature", "")
    parts = dict(p.split("=", 1) for p in sig_header.split(",") if "=" in p)

    timestamp = parts.get("t", "")
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        f"{timestamp}.{raw.decode()}".encode(),
        hashlib.sha256,
    ).hexdigest()
    received = parts.get("li") or parts.get("te") or ""
    if not hmac.compare_digest(expected, received):
        raise HTTPException(400, "Invalid signature")

    event = json.loads(raw)
    event_type = event["data"]["attributes"]["type"]

    if event_type == "checkout_session.payment.paid":
        session = event["data"]["attributes"]["data"]
        session_id = session["id"]
        order_id = (session["attributes"].get("metadata") or {}).get("order_id")

        q = supabase.table("orders").update(
            {"status": "paid", "paid_at": now(), "session_id": session_id}
        ).neq("status", "paid")  # idempotent: ligtas kahit ulit-ulitin ang event
        q = q.eq("id", order_id) if order_id else q.eq("session_id", session_id)
        res = q.execute()

        if res.data:
            print("PAID:", order_id, session_id)
            # TODO: dito mo ipadala ang product / email / i-unlock ang download

    return {"ok": True}


# ---------- Admin ----------
@app.get("/orders", response_class=HTMLResponse)
def orders(key: str = ""):
    if not ADMIN_KEY or not hmac.compare_digest(key, ADMIN_KEY):
        raise HTTPException(403, "Forbidden")
    rows = supabase.table("orders").select("*").order("created_at", desc=True).execute().data
    body = "".join(
        f"<tr><td>{r['id']}</td><td>{r['product_name']}</td>"
        f"<td>₱{r['amount_centavos'] / 100:.2f}</td><td>{r['status']}</td>"
        f"<td>{r['created_at']}</td><td>{r['paid_at'] or ''}</td></tr>"
        for r in rows
    )
    return (
        "<h2>Orders</h2><table border=1 cellpadding=6>"
        "<tr><th>ID</th><th>Product</th><th>Amount</th><th>Status</th><th>Created</th><th>Paid</th></tr>"
        f"{body}</table>"
    )
