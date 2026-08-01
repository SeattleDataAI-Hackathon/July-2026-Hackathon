import json


FINDINGS_FILE = "output/security_findings.json"
OUTPUT_FILE = "output/remediation_plan.json"



def load_json(file_path):

    with open(file_path, "r") as file:
        return json.load(file)



def generate_steps(finding):

    algorithm = finding["asset"]


    remediation_steps = {


        "RSA-OAEP": [

            "Inventory all RSA encryption usage identified in CBOM evidence",

            "Identify applications using RSA key exchange or encryption",

            "Implement hybrid cryptography using RSA-OAEP + ML-KEM-768",

            "Validate interoperability with existing systems",

            "Plan migration to pure ML-KEM when supported"

        ],



        "MD5": [

            "Locate all MD5 hashing implementations",

            "Replace MD5 with SHA-256 or SHA3-256",

            "Update stored hashes if backward compatibility allows",

            "Perform regression testing"

        ],



        "SHA-1": [

            "Identify SHA-1 hashing and signature usage",

            "Replace SHA-1 with SHA-256 or SHA-3",

            "Validate certificates and signing workflows",

            "Perform security regression testing"

        ],



        "AES-128": [

            "Identify AES-128 encryption implementations",

            "Validate key storage and rotation process",

            "Upgrade encryption keys to AES-256",

            "Perform compatibility testing"

        ]

    }


    return remediation_steps.get(
        algorithm,
        [
            "Review cryptographic implementation",
            "Apply recommended migration algorithm",
            "Perform security validation"
        ]
    )



def calculate_priority_score(finding):


    score = {


        "Critical":100,

        "High":80,

        "Medium":50,

        "Low":10

    }


    return score.get(
        finding["risk"],
        0
    )



def build_remediation_plan(findings):


    plan = []


    for finding in findings:


        item = {


            "finding_id":
                finding["finding_id"],


            "asset":
                finding["asset"],


            "risk":
                finding["risk"],


            "priority_score":
                calculate_priority_score(
                    finding
                ),


            "migration_wave":
                finding["migration_wave"],


            "owner":
                finding["owner"],


            "estimated_effort":
                finding["estimated_effort"],


            "estimated_hours":
                finding["estimated_hours"],


            "current_algorithm":
                finding["asset"],


            "target_algorithm":
                finding["recommended_algorithm"],


            "transition_strategy":
                finding["transition_strategy"],


            "implementation_steps":
                generate_steps(
                    finding
                ),


            "evidence_count":
                len(
                    finding.get(
                        "evidence",
                        []
                    )
                ),


            "nist_reference":
                finding["nist_reference"]

        }


        plan.append(item)



    # highest risk first

    plan.sort(
        key=lambda x:x["priority_score"],
        reverse=True
    )


    return plan




if __name__ == "__main__":


    findings = load_json(
        FINDINGS_FILE
    )


    remediation = build_remediation_plan(
        findings
    )


    with open(
        OUTPUT_FILE,
        "w"
    ) as file:

        json.dump(
            remediation,
            file,
            indent=4
        )



    print(
        "\n===== REMEDIATION PLAN =====\n"
    )


    print(
        "Total remediation items:",
        len(remediation)
    )


    for item in remediation:


        print(
            "\n----------------------------"
        )

        print(
            "Asset:",
            item["asset"]
        )

        print(
            "Risk:",
            item["risk"]
        )

        print(
            "Wave:",
            item["migration_wave"]
        )

        print(
            "Target:",
            item["target_algorithm"]
        )

        print(
            "Steps:",
            len(
                item["implementation_steps"]
            )
        )


    print(
        "\nSaved:",
        OUTPUT_FILE
    )