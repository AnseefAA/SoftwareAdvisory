

from math import ceil


def parse_cvss_vector(vector: str) -> dict:
    if validate_str(vector):
        return {} 
    
    if vector.startswith("CVSS:3.1/"):
        vector = vector[10:]

    # components = dict(item.split(":") for item in vector.split("/"))
    
    components = {} 

    items = vector.split("/") 

    for item in items:
        key, value = item.split(":")  
        components[key] = value 

    components.get("AV", "N")
    return {
        "attack_vector": components.get("V") or components.get("AV") or components.get("N") or components.get("L") or components.get("P") or "N",
        "attack_complexity": components.get("AC")  or components.get("H") or "L",
        "privileges_required": components.get("PR") or components.get("L") or components.get("H") or "N",
        "user_interaction": components.get("UI") or components.get("R") or "N",
        "scope": components.get("S") or components.get("S") or "U",
        "confidentiality": components.get("C") or components.get("L") or components.get("H") or "N",
        "integrity": components.get("I") or components.get("L") or components.get("H") or "N",
        "availability": components.get("A") or components.get("L") or components.get("H") or "N",
    }
    
def calculate_cvss_score(
    attack_vector: str,         # "N", "A", "L", or "P"
    attack_complexity: str,     # "L" or "H"
    privileges_required: str,   # "N", "L", or "H"
    user_interaction: str,      # "N" or "R"
    scope: str,                 # "U" or "C"
    confidentiality: str,       # "N", "L", or "H"
    integrity: str,             # "N", "L", or "H"
    availability: str           # "N", "L", or "H"
) -> float:
    """
    Calculate the Base CVSS v3.1 Score.
    """

    # Metric values for Exploitability
    attack_vector_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    attack_complexity_values = {"L": 0.77, "H": 0.44}
    privileges_required_values = {
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.5}
    }
    user_interaction_values = {"N": 0.85, "R": 0.62}

    # Metric values for Impact
    impact_values = {"N": 0.0, "L": 0.22, "H": 0.56}

    # Get values from inputs
    av = attack_vector_values[attack_vector]
    ac = attack_complexity_values[attack_complexity]
    pr = privileges_required_values[privileges_required][scope]
    ui = user_interaction_values[user_interaction]
    c = impact_values[confidentiality]
    i = impact_values[integrity]
    a = impact_values[availability]

    # Exploitability Subscore
    exploitability = 8.22 * av * ac * pr * ui

    # Impact Subscore
    impact = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope == "U":
        impact_score = 6.42 * impact
    else:  # scope == "C"
        impact_score = 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15

    # Base Score
    if impact_score <= 0:
        base_score = 0
    else:
        if scope == "U":
            base_score = round_up(min((impact_score + exploitability), 10))
        else:
            base_score = round_up(min(1.08 * (impact_score + exploitability), 10))

    return base_score

def round_up(score: float) -> float:
    """Round up the score to one decimal place."""
    return ceil(score * 10) / 10

def calculate_severity_from_range(cvss_score : int | float) -> str:
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"
    
def validate_str(value : str) -> bool:
    return value == ""