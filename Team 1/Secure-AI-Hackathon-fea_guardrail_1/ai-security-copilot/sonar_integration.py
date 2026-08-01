import json
import os


CBOM_FILE = "output/security_findings.json"
SONAR_FILE = "output/sonar_findings.json"

OUTPUT_FILE = "output/combined_security_context.json"


def load_json(path):

    with open(path,"r") as f:
        return json.load(f)



def build_context():

    cbom_findings = load_json(
        CBOM_FILE
    )

    sonar_findings = load_json(
        SONAR_FILE
    )


    context = {

        "pqc_findings": cbom_findings,

        "sonarqube_findings": sonar_findings,

        "summary": {

            "total_crypto_findings":
                len(cbom_findings),

            "total_code_findings":
                len(sonar_findings)

        }

    }


    return context



if __name__ == "__main__":


    context = build_context()


    os.makedirs(
        "output",
        exist_ok=True
    )


    with open(
        OUTPUT_FILE,
        "w"
    ) as f:

        json.dump(
            context,
            f,
            indent=4
        )


    print(
        "Created:",
        OUTPUT_FILE
    )