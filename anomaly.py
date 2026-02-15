def calculate_risk_score(request_data):
    score = 0

    body = request_data["body"].lower()

    # SQL injection keywords
    suspicious_keywords = ["drop", "delete", "union", "select *", "--", "' or 1=1"]

    for word in suspicious_keywords:
        if word in body:
            score += 40

    # Large payload
    if len(body) > 2000:
        score += 20

    return score
