def calculate_risk(status, failure_count, anomaly=False):

    risk_score = 0

    if status == "Failed":
        risk_score += 20

    if failure_count >= 5:
        risk_score += 30

    if anomaly:
        risk_score += 25

    return risk_score