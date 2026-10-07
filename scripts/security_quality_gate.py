#!/usr/bin/env python3

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def fail(message):
    print(f"[ERROR] {message}")
    return True


def load_json(path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def check_semgrep(path):
    print("\n=== SEMGREP ===")

    if not path.is_file():
        return fail(f"Reporte Semgrep no encontrado: {path}")

    try:
        data = load_json(path)
    except Exception as exc:
        return fail(f"No se pudo leer Semgrep JSON: {exc}")

    results = data.get("results", [])

    errors = []
    warnings = []

    for result in results:
        extra = result.get("extra", {})
        severity = str(extra.get("severity", "")).upper()

        if severity == "ERROR":
            errors.append(result)
        elif severity == "WARNING":
            warnings.append(result)

    print(f"Hallazgos totales : {len(results)}")
    print(f"ERROR             : {len(errors)}")
    print(f"WARNING           : {len(warnings)}")

    for result in errors:
        rule = result.get("check_id", "unknown")
        file = result.get("path", "unknown")
        line = result.get("start", {}).get("line", "?")
        print(f"  [ERROR] {rule} -> {file}:{line}")

    if errors:
        print("[FAIL] Semgrep contiene hallazgos ERROR.")
        return True

    print("[PASS] Semgrep sin hallazgos ERROR.")
    return False


def vulnerability_score(vulnerability):
    scores = []

    for field in ("cvssv4", "cvssv3", "cvssv2"):
        cvss = vulnerability.get(field)

        if isinstance(cvss, dict):
            score = cvss.get("baseScore")

            try:
                if score is not None:
                    scores.append(float(score))
            except (TypeError, ValueError):
                pass

    return max(scores) if scores else None


def check_dependency_check(path, threshold):
    print("\n=== OWASP DEPENDENCY-CHECK ===")

    if not path.is_file():
        return fail(f"Reporte Dependency-Check no encontrado: {path}")

    try:
        data = load_json(path)
    except Exception as exc:
        return fail(f"No se pudo leer Dependency-Check JSON: {exc}")

    dependencies = data.get("dependencies")

    if not isinstance(dependencies, list):
        return fail("El JSON de Dependency-Check no contiene 'dependencies' válido.")

    vulnerabilities = []

    for dependency in dependencies:
        dependency_name = dependency.get("fileName", "unknown")

        for vulnerability in dependency.get("vulnerabilities") or []:
            score = vulnerability_score(vulnerability)

            vulnerabilities.append(
                {
                    "dependency": dependency_name,
                    "name": vulnerability.get("name", "unknown"),
                    "severity": str(
                        vulnerability.get("severity", "UNKNOWN")
                    ).upper(),
                    "score": score,
                }
            )

    blocking = [
        vulnerability
        for vulnerability in vulnerabilities
        if (
            vulnerability["severity"] == "CRITICAL"
            or (
                vulnerability["score"] is not None
                and vulnerability["score"] >= threshold
            )
        )
    ]

    critical = [
        vulnerability
        for vulnerability in vulnerabilities
        if vulnerability["severity"] == "CRITICAL"
    ]

    print(f"Dependencias analizadas       : {len(dependencies)}")
    print(f"Vulnerabilidades encontradas  : {len(vulnerabilities)}")
    print(f"CRITICAL                      : {len(critical)}")
    print(f"CVSS >= {threshold:g} / bloqueantes : {len(blocking)}")

    for vulnerability in blocking:
        score = (
            f"{vulnerability['score']:.1f}"
            if vulnerability["score"] is not None
            else "N/A"
        )

        print(
            f"  [BLOCK] {vulnerability['dependency']} | "
            f"{vulnerability['name']} | "
            f"{vulnerability['severity']} | CVSS={score}"
        )

    if blocking:
        print(
            f"[FAIL] Dependency-Check contiene {len(blocking)} "
            "vulnerabilidades bloqueantes."
        )
        return True

    print("[PASS] Dependency-Check sin vulnerabilidades bloqueantes.")
    return False


def check_spotbugs(path, blocking_priority):
    print("\n=== SPOTBUGS ===")

    if not path.is_file():
        return fail(f"Reporte SpotBugs no encontrado: {path}")

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as exc:
        return fail(f"No se pudo leer SpotBugs XML: {exc}")

    bugs = root.findall(".//BugInstance")
    blocking = []

    for bug in bugs:
        try:
            priority = int(bug.attrib.get("priority", "999"))
        except ValueError:
            priority = 999

        if priority <= blocking_priority:
            blocking.append(bug)

    print(f"Hallazgos totales            : {len(bugs)}")
    print(
        f"Prioridad <= {blocking_priority} / bloqueantes : "
        f"{len(blocking)}"
    )

    for bug in blocking:
        print(
            f"  [BLOCK] {bug.attrib.get('type', 'unknown')} | "
            f"priority={bug.attrib.get('priority', '?')} | "
            f"rank={bug.attrib.get('rank', '?')} | "
            f"category={bug.attrib.get('category', 'unknown')}"
        )

    if blocking:
        print(
            f"[FAIL] SpotBugs contiene {len(blocking)} "
            "hallazgos bloqueantes."
        )
        return True

    print("[PASS] SpotBugs sin hallazgos bloqueantes.")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Quality Gate de seguridad del Laboratorio 3"
    )

    parser.add_argument(
        "--semgrep",
        default="reports/semgrep.json",
    )

    parser.add_argument(
        "--dependency-check",
        default="reports/dependency-check-report.json",
    )

    parser.add_argument(
        "--spotbugs",
        default="reports/spotbugsXml.xml",
    )

    parser.add_argument(
        "--cvss-threshold",
        type=float,
        default=7.0,
    )

    parser.add_argument(
        "--spotbugs-priority",
        type=int,
        default=2,
    )

    args = parser.parse_args()

    print("=" * 64)
    print("        SECURITY QUALITY GATE - DEVSECOPS LAB 3")
    print("=" * 64)

    failed = False

    failed |= check_semgrep(Path(args.semgrep))

    failed |= check_dependency_check(
        Path(args.dependency_check),
        args.cvss_threshold,
    )

    failed |= check_spotbugs(
        Path(args.spotbugs),
        args.spotbugs_priority,
    )

    print("\n" + "=" * 64)

    if failed:
        print("SECURITY QUALITY GATE: FAILED")
        print("=" * 64)
        return 1

    print("SECURITY QUALITY GATE: PASSED")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())