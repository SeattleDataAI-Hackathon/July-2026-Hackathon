import json


CBOM_FILE = "app-cbom-final.json"
RULE_FILE = "pqc_rules.json"


def load_json(file_path):

    with open(file_path, "r") as file:
        return json.load(file)



def normalize_algorithm(name):

    if not name:
        return ""

    name = name.upper()

    replacements = {
        "-": "",
        "_": "",
        " ": ""
    }

    for old, new in replacements.items():
        name = name.replace(old, new)

    return name



def extract_algorithm(asset):
    """
    Extract algorithm from CycloneDX CBOM asset name.
    """

    name = asset.get("name", "")

    if not name:
        return None


    normalized = normalize_algorithm(name)


    # IMPORTANT:
    # Longer patterns first
    # Otherwise AES128 matches AES128GCM first

    algorithm_map = [

        ("RSAOAEP", "RSA-OAEP"),

        ("RSA2048", "RSA"),

        ("AES256CBCPKCS5", "AES-256"),

        ("AES256GCM", "AES-256"),

        ("AES256", "AES-256"),

        ("AES128GCM", "AES-128"),

        ("AES128CBCPKCS5", "AES-128"),

        ("AES128", "AES-128"),

        ("SHA256", "SHA-256"),

        ("SHA1", "SHA-1"),

        ("HMACSHA1", "SHA-1"),

        ("MD5", "MD5"),

        ("3DES", "3DES"),

        ("DES", "DES"),

        ("MLKEM", "ML-KEM"),

        ("MLDSA", "ML-DSA")
    ]


    for pattern, algorithm in algorithm_map:

        if pattern in normalized:
            return algorithm


    return None



def extract_evidence(asset):

    evidence = asset.get(
        "evidence",
        {}
    )

    occurrences = evidence.get(
        "occurrences",
        []
    )


    results = []


    for item in occurrences:

        results.append({

            "location": item.get(
                "location"
            ),

            "line": item.get(
                "line"
            ),

            "context": item.get(
                "additionalContext"
            )

        })


    return results



def build_rule_lookup(rules):

    lookup = {}


    for algorithm, rule in rules.items():

        normalized = normalize_algorithm(
            algorithm
        )


        lookup[normalized] = rule


    # aliases without modifying JSON

    if "SHA1" in lookup:

        lookup["SHA-1"] = lookup["SHA1"]


    if "SHA-1" in lookup:

        lookup["SHA1"] = lookup["SHA-1"]


    if "RSA2048" in lookup:

        lookup["RSA"] = lookup["RSA2048"]


    return lookup



def analyze_cbom():

    cbom = load_json(
        CBOM_FILE
    )

    rules = load_json(
        RULE_FILE
    )


    rules_lookup = build_rule_lookup(
        rules
    )


    findings = {}



    for asset in cbom.get(
        "components",
        []
    ):


        if asset.get(
            "type"
        ) != "cryptographic-asset":

            continue



        algorithm = extract_algorithm(
            asset
        )


        if not algorithm:
            continue



        normalized = normalize_algorithm(
            algorithm
        )


        # Debug if needed
        # print(asset.get("name"), "=>", algorithm, normalized)



        if normalized not in rules_lookup:

            continue



        rule = rules_lookup[
            normalized
        ]



        if normalized not in findings:


            findings[normalized] = {


                "finding_id":
                    f"PQC-{normalized}-001",


                "asset":
                    algorithm,


                "normalized_algorithm":
                    normalized,


                "risk":
                    rule.get(
                        "risk"
                    ),


                "category":
                    rule.get(
                        "category"
                    ),


                "priority":
                    rule.get(
                        "priority"
                    ),


                "reason":
                    rule.get(
                        "reason"
                    ),


                "migration":
                    rule.get(
                        "migration"
                    ),


                "recommended_algorithm":
                    rule.get(
                        "recommended_algorithm",
                        []
                    ),


                "transition_strategy":
                    rule.get(
                        "transition_strategy",
                        "Unknown"
                    ),


                "migration_wave":
                    rule.get(
                        "migration_wave",
                        "Unknown"
                    ),


                "estimated_effort":
                    rule.get(
                        "estimated_effort",
                        "Unknown"
                    ),


                "estimated_hours":
                    rule.get(
                        "estimated_hours",
                        "Unknown"
                    ),


                "owner":
                    rule.get(
                        "owner",
                        "Security Team"
                    ),


                "nist_reference":
                    rule.get(
                        "nist_reference",
                        []
                    ),


                "confidence":
                    rule.get(
                        "confidence",
                        "Medium"
                    ),


                "auto_fix":
                    rule.get(
                        "auto_fix",
                        False
                    ),


                "evidence": []

            }



        findings[normalized]["evidence"].extend(
            extract_evidence(asset)
        )



    return list(
        findings.values()
    )



if __name__ == "__main__":

    import os


    findings = analyze_cbom()


    print(
        "\n===== PQC SECURITY FINDINGS =====\n"
    )


    print(
        "Total findings:",
        len(findings)
    )


    for finding in findings:

        print("\n--------------------------------")

        print(
            "Algorithm:",
            finding["asset"]
        )

        print(
            "Risk:",
            finding["risk"]
        )

        print(
            "Priority:",
            finding["priority"]
        )

        print(
            "Evidence Count:",
            len(finding["evidence"])
        )

        print(
            "Migration:",
            finding["migration"]
        )


    # Save output for next pipeline stage
    os.makedirs(
        "output",
        exist_ok=True
    )


    output_file = "output/security_findings.json"


    with open(
        output_file,
        "w"
    ) as f:

        json.dump(
            findings,
            f,
            indent=4
        )


    print(
        "\nSaved:",
        output_file
    )