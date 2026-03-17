def map_priority_from_cvss(score):
    if score >= 9.0:
        return 4
    elif score >= 7.0:
        return 3
    elif score >= 4.0:
        return 2
    elif score > 0:
        return 1
    return 0


def calculate_priority(cvss_score):
    return map_priority_from_cvss(cvss_score)
