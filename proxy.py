from fastapi import FastAPI, Request
from fastapi.responses import Response, JSONResponse
import httpx
from anomaly import calculate_risk_score
from logger import log_request

TARGET_API = "http://127.0.0.1:9000"

app = FastAPI()


@app.middleware("http")
async def security_middleware(request: Request, call_next):

    body = await request.body()

    request_data = {
        "ip": request.client.host,
        "path": str(request.url.path),
        "method": request.method,
        "body": body.decode()
    }

    # Calculate risk
    risk_score = calculate_risk_score(request_data)
    request_data["risk_score"] = risk_score

    log_request(request_data)

    print(f"Request Risk Score: {risk_score}")

    # 🚨 Block malicious request properly
    if risk_score >= 70:
        print("⚠ BLOCKED: Malicious Request")
        return JSONResponse(
            status_code=403,
            content={"detail": "Blocked: Suspicious Activity"}
        )

    # Forward safe request to actual API
    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=request.method,
                url=f"{TARGET_API}{request.url.path}",
                headers=request.headers,
                content=body
            )

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers)
        )

    except Exception as e:
        print("Forwarding Error:", e)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal proxy forwarding error"}
        )


@app.get("/")
def home():
    return {"status": "Security Proxy Running"}
