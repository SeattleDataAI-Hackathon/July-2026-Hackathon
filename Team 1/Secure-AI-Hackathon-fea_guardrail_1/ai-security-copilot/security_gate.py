import json
import sys


FINDINGS_FILE = "output/security_findings.json"

MINIMUM_SECURITY_SCORE = 60


def calculate_security_score(findings):

    score = 100

    severity_penalty = {
        "Critical": 30,
        "High": 20,
        "Medium": 10,
        "Low": 0
    }

    analyzed_assets = set()
    total_penalty = 0

    for finding in findings:

        asset = finding.get("asset")

        if asset in analyzed_assets:
            continue

        analyzed_assets.add(asset)

        risk = finding.get(
            "risk",
            "Low"
        )

        total_penalty += severity_penalty.get(
            risk,
            0
        )

    # Normalize: scale penalty relative to worst case (all Critical)
    num_assets = len(analyzed_assets) if analyzed_assets else 1
    max_possible_penalty = num_assets * 30
    if max_possible_penalty > 0:
        normalized_penalty = (total_penalty / max_possible_penalty) * 80
    else:
        normalized_penalty = 0

    score = round(score - normalized_penalty)

    return max(score, 0)



def main():

    with open(FINDINGS_FILE) as f:
        findings = json.load(f)


    score = calculate_security_score(findings)


    print("=" * 50)
    print(f"Security Score: {score}%")
    print(f"Required Score: {MINIMUM_SECURITY_SCORE}%")
    print("=" * 50)



    if score < MINIMUM_SECURITY_SCORE:

        print(
            "❌ SECURITY GATE FAILED"
        )

        print(
            "Merge blocked due to low security score."
        )

        sys.exit(1)



    else:

        print(
            "✅ SECURITY GATE PASSED"
        )

        sys.exit(0)



if __name__ == "__main__":
    main()
