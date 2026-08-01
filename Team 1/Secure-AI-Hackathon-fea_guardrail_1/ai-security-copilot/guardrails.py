"""
AI Security Copilot - Guardrails Module

Three guardrails for trustworthy AI-generated security reports:
1. Hallucination Guardrail - verifies claims against CBOM/Sonar/RAG evidence
2. Prompt Injection Guardrail - protects RAG and Sonar inputs from malicious instructions
3. Output Validation Guardrail - ensures report completeness and no fabricated references
"""

import json
import re
from typing import Any


# =============================================================================
# 1. HALLUCINATION GUARDRAIL
# =============================================================================

class HallucinationGuardrail:
    """
    Verifies that LLM-generated report claims are grounded in actual evidence
    from CBOM findings, SonarQube results, and RAG-retrieved NIST documents.

    Catches:
    - Algorithms mentioned in report but not in CBOM/findings
    - File paths or line numbers not present in SonarQube data
    - NIST references not found in rules or RAG evidence
    - Risk levels that don't match source findings
    """

    # Valid NIST references from our rules
    VALID_NIST_REFS = {
        "FIPS 197", "FIPS 180-4", "FIPS 203", "FIPS 204",
        "SP 1800-38B", "SP 800-131A", "SP 800-57",
    }

    # Known algorithms from our PQC rules and recommendations
    KNOWN_ALGORITHMS = {
        "RSA", "RSA-OAEP", "MD5", "SHA-1", "SHA-2", "SHA-256", "SHA-384",
        "SHA-3", "SHA3-256", "SHA3-384", "SHA3-512", "AES-128", "AES-256",
        "ML-KEM-768", "ML-KEM-1024", "ML-DSA", "ML-DSA-44", "ML-DSA-65",
        "ML-DSA-87", "ECDSA", "ECDH", "DH", "DSA", "ED25519", "ED448",
    }

    def __init__(self, pqc_findings: list, sonar_findings: list, rag_evidence: list):
        self.pqc_findings = pqc_findings
        self.sonar_findings = sonar_findings
        self.rag_evidence = rag_evidence

        # Build sets of valid data from source evidence
        self.valid_assets = {f.get("asset", "").upper() for f in pqc_findings}
        self.valid_finding_ids = {f.get("finding_id", "") for f in pqc_findings}
        self.valid_sonar_files = {
            f.get("component", "") for f in sonar_findings
        }
        self.valid_sonar_lines = {
            (f.get("component", ""), f.get("line"))
            for f in sonar_findings
            if f.get("line")
        }
        self.rag_sources = {
            e.get("source", "") for e in rag_evidence if e.get("source")
        }

    def validate_report(self, report_text: str) -> dict:
        """
        Validate a generated report against source evidence.
        Returns a dict with pass/fail status and list of violations.
        """
        violations = []

        violations.extend(self._check_algorithm_hallucinations(report_text))
        violations.extend(self._check_nist_hallucinations(report_text))
        violations.extend(self._check_file_hallucinations(report_text))
        violations.extend(self._check_risk_consistency(report_text))

        return {
            "passed": len(violations) == 0,
            "guardrail": "hallucination",
            "violations": violations,
            "violation_count": len(violations),
            "severity": self._max_severity(violations),
        }

    def _check_algorithm_hallucinations(self, report: str) -> list:
        """Check for algorithms mentioned in report but not in evidence."""
        violations = []

        # Common crypto algorithm patterns - match real algorithm names only
        # Exclude finding IDs (e.g., PQC-RSA-001) and partial matches
        algo_pattern = r'(?<![A-Za-z-])\b(RSA-(?:OAEP|\d{3,})|AES-\d{3}|SHA-\d+|SHA3-\d{3}|MD\d|DES|3DES|Blowfish|RC4|ECDSA-\d+|EdDSA|ChaCha20)\b'
        mentioned = set(re.findall(algo_pattern, report, re.IGNORECASE))

        # Filter out finding IDs (patterns like RSA-001, PQC-RSA-001)
        finding_id_pattern = re.compile(r'^[A-Z]+-\d{3}$', re.IGNORECASE)

        for algo in mentioned:
            algo_upper = algo.upper()

            # Skip if it looks like a finding ID (e.g., RSA-001)
            if finding_id_pattern.match(algo_upper):
                continue

            # Check if it's in our findings or known algorithm set
            if (algo_upper not in self.valid_assets and
                    algo_upper not in self.KNOWN_ALGORITHMS):
                violations.append({
                    "type": "hallucinated_algorithm",
                    "severity": "high",
                    "detail": f"Algorithm '{algo}' mentioned in report but not found in CBOM or PQC findings.",
                })

        return violations

    def _check_nist_hallucinations(self, report: str) -> list:
        """Check for NIST references not backed by evidence."""
        violations = []

        # Match NIST reference patterns
        nist_pattern = r'\b(FIPS\s*\d+[-\w]*|SP\s*\d+[-\w]*|NIST\s*IR\s*\d+)\b'
        mentioned_refs = set(re.findall(nist_pattern, report, re.IGNORECASE))

        for ref in mentioned_refs:
            # Normalize spacing
            normalized = re.sub(r'\s+', ' ', ref.upper().strip())
            # Check against valid refs and RAG sources
            if not self._is_valid_nist_ref(normalized):
                violations.append({
                    "type": "hallucinated_nist_reference",
                    "severity": "high",
                    "detail": f"NIST reference '{ref}' not found in rules or RAG evidence.",
                })

        return violations

    def _check_file_hallucinations(self, report: str) -> list:
        """Check for source file references not in SonarQube data."""
        violations = []

        # Match Java/Python file paths with line numbers
        file_line_pattern = r'([A-Za-z][\w/\\.-]+\.(?:java|py|js|ts|go|c|cpp|cs))\s*(?::|line\s*)(\d+)'
        matches = re.findall(file_line_pattern, report)

        for filepath, line in matches:
            # Check if SonarQube has any findings (skip if no sonar data)
            if self.valid_sonar_files and filepath not in self.valid_sonar_files:
                # Check partial match (filename only)
                filename = filepath.split("/")[-1].split("\\")[-1]
                partial_match = any(
                    filename in sf for sf in self.valid_sonar_files
                )
                if not partial_match:
                    violations.append({
                        "type": "hallucinated_file_reference",
                        "severity": "medium",
                        "detail": f"File '{filepath}' at line {line} not found in SonarQube evidence.",
                    })

        return violations

    def _check_risk_consistency(self, report: str) -> list:
        """Check that risk levels in report match source findings."""
        violations = []

        # Build risk map from findings
        risk_map = {}
        for f in self.pqc_findings:
            asset = f.get("asset", "")
            risk_map[asset.upper()] = f.get("risk", "")

        # Look for risk assignments in report
        risk_pattern = r'(?:Risk|Severity)\s*:\s*(Critical|High|Medium|Low)'
        asset_risk_pattern = r'(?:Asset|Algorithm)\s*:\s*([^\n]+)\n.*?(?:Risk|Severity)\s*:\s*(Critical|High|Medium|Low)'
        matches = re.findall(asset_risk_pattern, report, re.IGNORECASE | re.DOTALL)

        for asset, stated_risk in matches:
            asset_clean = asset.strip().upper()
            if asset_clean in risk_map:
                actual_risk = risk_map[asset_clean]
                if stated_risk.capitalize() != actual_risk:
                    violations.append({
                        "type": "inconsistent_risk_level",
                        "severity": "high",
                        "detail": (
                            f"Report states '{asset.strip()}' has risk '{stated_risk}' "
                            f"but evidence shows '{actual_risk}'."
                        ),
                    })

        return violations

    def _is_valid_nist_ref(self, ref: str) -> bool:
        """Check if a NIST reference is valid based on rules or RAG evidence."""
        # Check against known valid refs
        for valid in self.VALID_NIST_REFS:
            if valid.upper() in ref or ref in valid.upper():
                return True
        # Check against RAG source filenames
        for source in self.rag_sources:
            if source and any(
                part in source.upper()
                for part in ref.replace(" ", "").split("-")
                if len(part) > 2
            ):
                return True
        return False

    def _max_severity(self, violations: list) -> str:
        if not violations:
            return "none"
        severity_order = {"high": 3, "medium": 2, "low": 1}
        max_sev = max(
            violations,
            key=lambda v: severity_order.get(v.get("severity", "low"), 0)
        )
        return max_sev.get("severity", "low")


# =============================================================================
# 2. PROMPT INJECTION GUARDRAIL
# =============================================================================

class PromptInjectionGuardrail:
    """
    Sanitizes inputs (RAG documents, SonarQube data, CBOM data) before they
    are included in the LLM prompt. Detects and neutralizes injection attempts.

    Protects against:
    - Instruction override attempts in RAG-retrieved documents
    - Malicious payloads in SonarQube report fields
    - Jailbreak patterns embedded in CBOM metadata
    """

    # Patterns that indicate prompt injection attempts
    INJECTION_PATTERNS = [
        # Direct instruction overrides
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"ignore\s+(all\s+)?above\s+instructions",
        r"disregard\s+(all\s+)?prior",
        r"forget\s+(everything|all)\s+(above|before)",
        r"you\s+are\s+now\s+a",
        r"new\s+instructions?\s*:",
        r"system\s*:\s*you",
        r"<\s*system\s*>",

        # Role manipulation
        r"pretend\s+you\s+are",
        r"act\s+as\s+(if\s+)?you",
        r"switch\s+to\s+.+\s+mode",
        r"enter\s+.+\s+mode",
        r"jailbreak",
        r"DAN\s+mode",

        # Output manipulation
        r"output\s+the\s+(system|hidden|secret)",
        r"reveal\s+(your|the)\s+(system|prompt|instructions)",
        r"print\s+(your|the)\s+system\s+prompt",
        r"what\s+is\s+your\s+system\s+prompt",

        # Data exfiltration
        r"send\s+(this|data|the)\s+to",
        r"fetch\s+from\s+https?://",
        r"curl\s+",
        r"wget\s+",

        # Delimiter attacks
        r"```\s*system",
        r"\[INST\]",
        r"\[/INST\]",
        r"<\|im_start\|>",
        r"<<SYS>>",
    ]

    def __init__(self):
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS
        ]

    def validate_inputs(self, rag_evidence: list, sonar_findings: list,
                        cbom_data: dict = None) -> dict:
        """
        Scan all input data for injection attempts before prompt construction.
        Returns validation result with any detected threats.
        """
        threats = []

        # Scan RAG evidence
        for i, doc in enumerate(rag_evidence):
            content = doc.get("content", "")
            source = doc.get("source", f"document_{i}")
            doc_threats = self._scan_text(content, f"RAG:{source}")
            threats.extend(doc_threats)

        # Scan SonarQube findings
        for i, finding in enumerate(sonar_findings):
            for field in ["message", "component", "rule"]:
                value = finding.get(field, "")
                if value:
                    field_threats = self._scan_text(
                        str(value),
                        f"SonarQube:finding_{i}:{field}"
                    )
                    threats.extend(field_threats)

        # Scan CBOM data
        if cbom_data:
            cbom_str = json.dumps(cbom_data)
            cbom_threats = self._scan_text(cbom_str, "CBOM:metadata")
            threats.extend(cbom_threats)

        return {
            "passed": len(threats) == 0,
            "guardrail": "prompt_injection",
            "threats": threats,
            "threat_count": len(threats),
            "action": "block" if threats else "allow",
        }

    def sanitize_text(self, text: str) -> str:
        """
        Remove or neutralize detected injection patterns from text.
        Use this to clean inputs before including in prompts.
        """
        sanitized = text
        for pattern in self._compiled_patterns:
            sanitized = pattern.sub("[REDACTED-INJECTION]", sanitized)

        # Also neutralize markdown/code-fence tricks
        sanitized = re.sub(
            r'```\s*(system|assistant|user)',
            '``` [BLOCKED]',
            sanitized,
            flags=re.IGNORECASE
        )

        return sanitized

    def sanitize_evidence(self, rag_evidence: list) -> list:
        """Sanitize all RAG evidence documents."""
        sanitized = []
        for doc in rag_evidence:
            sanitized.append({
                "content": self.sanitize_text(doc.get("content", "")),
                "source": doc.get("source", ""),
            })
        return sanitized

    def _scan_text(self, text: str, source: str) -> list:
        """Scan a text block for injection patterns."""
        threats = []
        for pattern in self._compiled_patterns:
            matches = pattern.findall(text)
            if matches:
                threats.append({
                    "source": source,
                    "pattern": pattern.pattern,
                    "match_count": len(matches),
                    "severity": "critical",
                    "detail": f"Prompt injection pattern detected in {source}",
                })
        return threats


# =============================================================================
# 3. OUTPUT VALIDATION GUARDRAIL
# =============================================================================

class OutputValidationGuardrail:
    """
    Validates the structure and integrity of the generated security report.

    Ensures:
    - All required sections are present
    - No fabricated NIST references
    - Finding IDs match source data
    - Report doesn't contain obvious LLM refusal patterns
    - Recommendations reference real algorithms
    """

    REQUIRED_SECTIONS = [
        "Quantum Readiness Score",
        "Executive Summary",
        "Findings",
        "NIST Guidance",
        "Migration Roadmap",
        "Limitations",
    ]

    # Patterns that indicate LLM refusal or confusion
    REFUSAL_PATTERNS = [
        r"I cannot",
        r"I'm unable to",
        r"as an AI",
        r"as a language model",
        r"I don't have access",
        r"I apologize",
    ]

    def __init__(self, pqc_findings: list, valid_nist_refs: set = None):
        self.pqc_findings = pqc_findings
        self.valid_nist_refs = valid_nist_refs or HallucinationGuardrail.VALID_NIST_REFS
        self.valid_finding_ids = {f.get("finding_id", "") for f in pqc_findings}
        self.valid_assets = {f.get("asset", "") for f in pqc_findings}

    def validate_report(self, report_text: str) -> dict:
        """
        Validate the generated report for completeness and integrity.
        """
        violations = []

        violations.extend(self._check_required_sections(report_text))
        violations.extend(self._check_fabricated_references(report_text))
        violations.extend(self._check_refusal_patterns(report_text))
        violations.extend(self._check_finding_coverage(report_text))
        violations.extend(self._check_score_format(report_text))

        return {
            "passed": len(violations) == 0,
            "guardrail": "output_validation",
            "violations": violations,
            "violation_count": len(violations),
            "completeness_score": self._calculate_completeness(report_text),
        }

    def _check_required_sections(self, report: str) -> list:
        """Ensure all required report sections are present."""
        violations = []

        # Flexible matching: check for key terms in any markdown heading
        section_keywords = {
            "Quantum Readiness Score": ["readiness", "score"],
            "Executive Summary": ["executive", "summary"],
            "Findings": ["finding"],
            "NIST Guidance": ["nist", "guidance"],
            "Migration Roadmap": ["migration", "roadmap"],
            "Limitations": ["limitation"],
        }

        for section, keywords in section_keywords.items():
            # Look for a markdown heading containing any of the keywords
            found = False
            for keyword in keywords:
                # Match heading lines (# or ##) containing the keyword
                pattern = rf'^#+\s+.*{re.escape(keyword)}'
                if re.search(pattern, report, re.IGNORECASE | re.MULTILINE):
                    found = True
                    break
            if not found:
                violations.append({
                    "type": "missing_section",
                    "severity": "high",
                    "detail": f"Required section '{section}' is missing from report.",
                })
        return violations

    def _check_fabricated_references(self, report: str) -> list:
        """Detect NIST references that look fabricated (fake document numbers)."""
        violations = []

        # Find all NIST-style references
        nist_pattern = r'\b(FIPS\s*\d+[-\w]*|SP\s*\d+[-\w]*)\b'
        mentioned = set(re.findall(nist_pattern, report, re.IGNORECASE))

        for ref in mentioned:
            normalized = re.sub(r'\s+', ' ', ref.upper().strip())
            if not self._is_known_reference(normalized):
                violations.append({
                    "type": "fabricated_reference",
                    "severity": "high",
                    "detail": f"Potentially fabricated NIST reference: '{ref}'",
                })

        return violations

    def _check_refusal_patterns(self, report: str) -> list:
        """Detect if the LLM refused or broke character."""
        violations = []
        for pattern in self.REFUSAL_PATTERNS:
            if re.search(pattern, report, re.IGNORECASE):
                violations.append({
                    "type": "llm_refusal_detected",
                    "severity": "medium",
                    "detail": f"LLM refusal/meta-commentary pattern detected: '{pattern}'",
                })
        return violations

    def _check_finding_coverage(self, report: str) -> list:
        """Ensure non-Low findings are covered in the report."""
        violations = []
        non_low_assets = {
            f.get("asset", "") for f in self.pqc_findings
            if f.get("risk", "") != "Low"
        }

        for asset in non_low_assets:
            if asset and asset not in report:
                violations.append({
                    "type": "missing_finding_coverage",
                    "severity": "medium",
                    "detail": f"Finding for '{asset}' not addressed in report.",
                })

        return violations

    def _check_score_format(self, report: str) -> list:
        """Validate that the readiness score is present and reasonable."""
        violations = []

        # Match various score formats: "Score: 40%", "**40%**", "40/100", etc.
        score_match = re.search(r'(?:Score|Readiness)\s*[:\-]\s*\**(\d+)\**\s*%', report, re.IGNORECASE)
        if not score_match:
            # Try alternate format: just a percentage near "readiness"
            score_match = re.search(r'(\d+)\s*%', report)

        if not score_match:
            violations.append({
                "type": "missing_score",
                "severity": "medium",
                "detail": "Quantum Readiness Score not found in expected format.",
            })
        else:
            score = int(score_match.group(1))
            if score < 0 or score > 100:
                violations.append({
                    "type": "invalid_score",
                    "severity": "high",
                    "detail": f"Readiness score {score}% is outside valid range (0-100).",
                })

        return violations

    def _is_known_reference(self, ref: str) -> bool:
        """Check if a NIST reference is one we recognize."""
        for valid in self.valid_nist_refs:
            if valid.upper().replace(" ", "") in ref.replace(" ", ""):
                return True
            if ref.replace(" ", "") in valid.upper().replace(" ", ""):
                return True
        return False

    def _calculate_completeness(self, report: str) -> float:
        """Calculate what percentage of required sections are present."""
        section_keywords = {
            "Quantum Readiness Score": ["readiness", "score"],
            "Executive Summary": ["executive", "summary"],
            "Findings": ["finding"],
            "NIST Guidance": ["nist", "guidance"],
            "Migration Roadmap": ["migration", "roadmap"],
            "Limitations": ["limitation"],
        }
        found = 0
        for section, keywords in section_keywords.items():
            for keyword in keywords:
                pattern = rf'^#+\s+.*{re.escape(keyword)}'
                if re.search(pattern, report, re.IGNORECASE | re.MULTILINE):
                    found += 1
                    break
        return round((found / len(section_keywords)) * 100, 1)


# =============================================================================
# GUARDRAIL RUNNER - Orchestrates all three guardrails
# =============================================================================

class GuardrailRunner:
    """
    Orchestrates all guardrails in the correct order:
    1. Pre-generation: Prompt Injection (on inputs)
    2. Post-generation: Hallucination + Output Validation (on outputs)
    """

    def __init__(self, pqc_findings: list, sonar_findings: list,
                 rag_evidence: list, cbom_data: dict = None):
        self.pqc_findings = pqc_findings
        self.sonar_findings = sonar_findings
        self.rag_evidence = rag_evidence
        self.cbom_data = cbom_data

        # Initialize guardrails
        self.injection_guard = PromptInjectionGuardrail()
        self.hallucination_guard = HallucinationGuardrail(
            pqc_findings, sonar_findings, rag_evidence
        )
        self.output_guard = OutputValidationGuardrail(pqc_findings)

    def run_pre_generation(self) -> dict:
        """
        Run input guardrails BEFORE sending to LLM.
        Call this before constructing the prompt.
        """
        result = self.injection_guard.validate_inputs(
            self.rag_evidence, self.sonar_findings, self.cbom_data
        )

        if not result["passed"]:
            # Sanitize and return cleaned evidence
            result["sanitized_evidence"] = self.injection_guard.sanitize_evidence(
                self.rag_evidence
            )
            result["recommendation"] = (
                "Injection patterns detected. Using sanitized evidence. "
                "Review threats for potential data integrity issues."
            )

        return result

    def run_post_generation(self, report_text: str) -> dict:
        """
        Run output guardrails AFTER LLM generates report.
        Call this before presenting the report to the user.
        """
        hallucination_result = self.hallucination_guard.validate_report(report_text)
        output_result = self.output_guard.validate_report(report_text)

        all_passed = hallucination_result["passed"] and output_result["passed"]
        total_violations = (
            hallucination_result["violation_count"] +
            output_result["violation_count"]
        )

        return {
            "passed": all_passed,
            "hallucination_check": hallucination_result,
            "output_validation": output_result,
            "total_violations": total_violations,
            "recommendation": self._get_recommendation(
                hallucination_result, output_result
            ),
        }

    def run_all(self, report_text: str) -> dict:
        """Run all guardrails and return combined results."""
        pre = self.run_pre_generation()
        post = self.run_post_generation(report_text)

        return {
            "overall_passed": pre["passed"] and post["passed"],
            "pre_generation": pre,
            "post_generation": post,
        }

    def _get_recommendation(self, hallucination_result: dict,
                            output_result: dict) -> str:
        """Generate actionable recommendation based on results."""
        if hallucination_result["passed"] and output_result["passed"]:
            return "Report passed all validation checks."

        issues = []
        if not hallucination_result["passed"]:
            issues.append(
                f"{hallucination_result['violation_count']} hallucination issue(s)"
            )
        if not output_result["passed"]:
            issues.append(
                f"{output_result['violation_count']} output format issue(s)"
            )

        return (
            f"Report has {', '.join(issues)}. "
            "Consider regenerating with stricter prompt constraints or "
            "manually reviewing flagged sections."
        )
