from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import sqlite3
from datetime import datetime, timedelta
import uvicorn

app = FastAPI(title="CourtVision Premium License Server")

ADMIN_SECRET = "MySuperSecretPassword2026CourtVision12345!"   # ← Must match your Railway variable

class ValidateRequest(BaseModel):
    key: str
    mac: str

class ResetRequest(BaseModel):
    key: str
    mac: str

class CreateKeyRequest(BaseModel):
    key: str
    days: int = 365
    is_lifetime: bool = False

def init_db():
    conn = sqlite3.connect("licenses.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY,
        expiration TEXT,
        locked_mac TEXT,
        hwid_resets INTEGER DEFAULT 0,
        is_lifetime INTEGER DEFAULT 0
    )''')
    conn.commit()
    conn.close()

init_db()

@app.post("/validate")
async def validate(request: ValidateRequest):
    conn = sqlite3.connect("licenses.db")
    c = conn.cursor()
    c.execute("SELECT * FROM keys WHERE key = ?", (request.key,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Invalid key")

    key, expiration, locked_mac, resets, is_lifetime = row

    try:
        exp_date = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
        if exp_date < datetime.now():
            return {"valid": False, "message": "Key expired"}
    except:
        pass

    if not locked_mac or locked_mac == request.mac:
        return {"valid": True, "expiration": expiration}
    else:
        return {"valid": False, "message": "HWID mismatch"}

@app.post("/reset_hwid")
async def reset_hwid(request: ResetRequest):
    conn = sqlite3.connect("licenses.db")
    c = conn.cursor()
    c.execute("SELECT * FROM keys WHERE key = ?", (request.key,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Invalid key")

    key, expiration, locked_mac, resets, is_lifetime = row
    resets = int(resets) + 1

    try:
        current_exp = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
        new_exp = current_exp - timedelta(days=1)
        if is_lifetime and resets >= 3:
            new_exp = datetime.now() + timedelta(days=30)
            is_lifetime = 0
    except:
        new_exp = datetime.now() + timedelta(days=364)

    new_exp_str = new_exp.isoformat()

    c.execute("UPDATE keys SET locked_mac = ?, hwid_resets = ?, expiration = ? WHERE key = ?",
              (request.mac, resets, new_exp_str, request.key))
    conn.commit()
    conn.close()
    return {"success": True, "new_expiration": new_exp_str}

# ================== NEW ENDPOINTS ==================
@app.post("/delete_key")
async def delete_key(req: CreateKeyRequest, x_admin_secret: str = Header(None)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")
    conn = sqlite3.connect("licenses.db")
    c = conn.cursor()
    c.execute("DELETE FROM keys WHERE key = ?", (req.key,))
    conn.commit()
    conn.close()
    return {"status": "Key deleted successfully"}

@app.post("/update_expiration")
async def update_expiration(req: CreateKeyRequest, x_admin_secret: str = Header(None)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")
    conn = sqlite3.connect("licenses.db")
    c = conn.cursor()
    exp = datetime.now() + timedelta(days=req.days if not req.is_lifetime else 365)
    c.execute("UPDATE keys SET expiration = ? WHERE key = ?", (exp.isoformat(), req.key))
    conn.commit()
    conn.close()
    return {"status": "Expiration updated", "new_expiration": exp.isoformat()}
# ==================================================

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
