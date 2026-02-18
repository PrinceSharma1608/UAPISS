from fastapi import FastAPI, Request
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel, Field, field_validator, ValidationError
import httpx
import time
import re
from collections import defaultdict
from logger import log_request

 
# CONFIG
 

TARGET_API = "http://127.0.0.1:8000"

MAX_BODY_SIZE = 2048
RATE_LIMIT = 50
TIME_WINDOW = 60

ip_requests = defaultdict(list)

app = FastAPI()

 
# STRICT LOGIN SCHEMA
 

class LoginSchema(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    password: str = Field(min_length=3, max_length=50)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Invalid username format")
        return v


 
# SECURE LOGIN ROUTE
 

@app.post("/login")
async def secure_login(request: Request):

    body = await request.body()
    client_ip = request.client.host
    current_time = time.time()

    # 1️⃣ Payload size limit
    
    if len(body) > MAX_BODY_SIZE:
        return JSONResponse(status_code=413, content={"detail": "Payload Too Large"})

  
    # 2️⃣ Rate limiting
   
    request_times = ip_requests[client_ip]
    ip_requests[client_ip] = [
        t for t in request_times if current_time - t < TIME_WINDOW
    ]
    ip_requests[client_ip].append(current_time)

    if len(ip_requests[client_ip]) > RATE_LIMIT:
        return JSONResponse(status_code=429, content={"detail": "Too Many Requests"})

  
    # 3️⃣ Schema validation
  
    try:
        json_data = await request.json()
        LoginSchema(**json_data)
    except ValidationError:
        return JSONResponse(status_code=422, content={"detail": "Invalid Input Format"})
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Malformed Request"})

    
    # 4️⃣ Logging (FIXED)
   
    log_request({
    "ip": client_ip,
    "path": "/login",
    "method": request.method,
    "body": body.decode(errors="ignore"),
    "timestamp": current_time,
    "risk_score": 0
})

  
    # 5️⃣ Forward to backend

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{TARGET_API}/login",
                content=body,
                headers={"Content-Type": "application/json"}
            )

        return Response(
            content=response.content,
            status_code=response.status_code
        )

    except Exception as e:
        print("Forwarding Error:", e)
        return JSONResponse(status_code=500, content={"detail": "Internal Proxy Error"})


@app.get("/")
def home():
    return {"status": "Professional Security Proxy Running"}
