from fastapi import FastAPI

app = FastAPI()

@app.post("/login")
def login(data: dict):
    return {"message": "Login endpoint reached", "data": data}

@app.get("/data")
def get_data():
    return {"data": "Sensitive information"}
