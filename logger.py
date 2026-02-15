from datetime import datetime

def log_request(data):
    with open("logs.txt", "a") as f:
        f.write(f"""
Time: {datetime.now()}
IP: {data['ip']}
Path: {data['path']}
Method: {data['method']}
Risk Score: {data['risk_score']}
Body: {data['body']}
-----------------------------------------
""")
