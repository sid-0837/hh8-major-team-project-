def calculate_risk(status, failure_count, anomaly):

    score = 0

    if status == "Failed":
        score += 30

    score += failure_count * 10

    if anomaly:
        score += 40

    return min(score, 100)
