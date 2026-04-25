from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import uvicorn
from datetime import datetime, timedelta
import sqlite3
import hashlib
import uuid

app = FastAPI()

# ←←← CHANGE THIS TO A STRONG SECRET AND SET THE SAME IN RAILWAY VARIABLES ←←←
ADMIN_SECRET = "MySuperSecretPassword2026CourtVision12345!"

# SQLite database
conn = sqlite3.connect("licenses.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS keys (
    key TEXT PRIMARY KEY,
    expiration TEXT,
    locked_mac TEXT,
    hwid_resets INTEGER DEFAULT 0,
    is_lifetime INTEGER DEFAULT 0
)''')
conn.commit()

class ValidateRequest(BaseModel):
    key: str
    mac: str

class CreateKeyRequest(BaseModel):
    key_name: str
    days: int

class ResetHwidRequest(BaseModel):
    key: str
    mac: str

@app.post("/validate")
async def validate(req: ValidateRequest):
    cursor.execute("SELECT expiration, locked_mac, is_lifetime FROM keys WHERE key = ?", (req.key,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Invalid or expired key")
    
    expiration_str, locked_mac, is_lifetime = row
    if locked_mac and locked_mac != req.mac:
        raise HTTPException(status_code=403, detail="Key locked to another device")
    
    try:
        exp = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
        if exp < datetime.now():
            raise HTTPException(status_code=400, detail="Key expired")
    except:
        pass

    return {"valid": True, "expiration": expiration_str, "is_lifetime": bool(is_lifetime)}

@app.post("/create_key")
async def create_key(req: CreateKeyRequest, x_admin_secret: str = Header(None)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    key = req.key_name.strip()
    days = req.days

    if days == 0:  # lifetime
        expiration = (datetime.now() + timedelta(days=36525)).isoformat()
        is_lifetime = 1
    else:
        expiration = (datetime.now() + timedelta(days=days)).isoformat()
        is_lifetime = 0

    cursor.execute("INSERT OR REPLACE INTO keys (key, expiration, locked_mac, hwid_resets, is_lifetime) VALUES (?, ?, '', 0, ?)", 
                   (key, expiration, is_lifetime))
    conn.commit()

    return {"status": "Key created", "key": key, "expiration": expiration}

@app.post("/reset_hwid")
async def reset_hwid(req: ResetHwidRequest):
    cursor.execute("SELECT expiration, hwid_resets, is_lifetime FROM keys WHERE key = ?", (req.key,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Key not found")
    
    expiration_str, resets, is_lifetime = row
    new_resets = resets + 1

    if is_lifetime and new_resets >= 3:
        expiration = (datetime.now() + timedelta(days=30)).isoformat()
    else:
        expiration = (datetime.now() + timedelta(days=364)).isoformat()

    cursor.execute("UPDATE keys SET locked_mac = ?, hwid_resets = ? WHERE key = ?", (req.mac, new_resets, req.key))
    conn.commit()

    return {"status": "HWID reset successful", "new_expiration": expiration}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
