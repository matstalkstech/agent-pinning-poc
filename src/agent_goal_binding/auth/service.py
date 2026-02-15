from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

DEBUG_LOG_PATH = Path("/Users/mats/Documents/ai-sec-safety/agent-goal-binding-poc/.cursor/debug.log")

def _debug_log(message: str, data: dict, hypothesis_id: str) -> None:
    try:
        DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(DEBUG_LOG_PATH, "a") as f:
            f.write(json.dumps({
                "timestamp": int(time.time() * 1000),
                "location": "service.py",
                "message": message,
                "data": data,
                "hypothesisId": hypothesis_id,
            }) + "\n")
    except Exception as e:
        print(f"[debug] log failed path={DEBUG_LOG_PATH} err={e!r}", file=sys.stderr)

from agent_goal_binding.auth.merkletree import MerkleLog
from agent_goal_binding.auth.verification import (
    load_and_verify_certificate,
    verify_action_permitted,
    verify_goals_integrity,
    verify_permissions_integrity,
)


def create_app(cert_path: str | Path) -> Flask:
    _debug_log("create_app called", {"cert_path": str(cert_path)}, "H1_H2")
    app = Flask(__name__)

    try:
        certificate = load_and_verify_certificate(cert_path)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    app.config["CERTIFICATE"] = certificate

    log_path = Path(cert_path).parent / "agent_decision_log.json"
    app.config["MERKLE_LOG"] = MerkleLog(log_path)

    @app.route("/", methods=["GET"])
    def index():
        _debug_log("index route hit", {"path": request.path, "method": request.method}, "H4_H5")
        cert = app.config["CERTIFICATE"]
        return jsonify({
            "service": "Agent Authorization Service",
            "agent_id": cert["manifest"]["agent_id"],
            "endpoints": {
                "health": "/health",
                "verify_action": "POST /verify_action",
                "logs": "/logs",
                "verify_logs": "/verify_logs",
                "dashboard": "/dashboard",
            },
        }), 200

    @app.route("/verify_action", methods=["POST"])
    def verify_action():
        data = request.json
        cert = app.config["CERTIFICATE"]

        agent_id = data.get("agent_id")
        current_goals = data.get("current_goals")
        current_permissions = data.get("current_permissions")
        requested_action = data.get("action")

        if agent_id != cert["manifest"]["agent_id"]:
            return jsonify({
                "authorized": False,
                "reason": "Agent ID mismatch",
                "expected": cert["manifest"]["agent_id"],
                "received": agent_id,
            }), 403

        ok, reason = verify_goals_integrity(current_goals, cert)
        if not ok:
            return jsonify({
                "authorized": False,
                "reason": reason,
                "alert": "SECURITY_VIOLATION",
                "severity": "CRITICAL",
            }), 403

        ok, reason = verify_permissions_integrity(current_permissions, cert)
        if not ok:
            return jsonify({
                "authorized": False,
                "reason": reason,
                "alert": "SECURITY_VIOLATION",
                "severity": "CRITICAL",
            }), 403

        ok, reason = verify_action_permitted(requested_action, cert)
        if not ok:
            return jsonify({
                "authorized": False,
                "reason": reason,
                "permitted_actions": cert["manifest"]["permissions"],
                "prohibited_actions": cert["manifest"]["prohibited_actions"],
                "requested_action": requested_action,
            }), 403

        merkle_log = app.config["MERKLE_LOG"]
        block = merkle_log.append(
            agent_id=agent_id,
            action=requested_action,
            parameters=data.get("parameters", {})
        )

        return jsonify({
            "authorized": True,
            "agent_id": agent_id,
            "action": requested_action,
            "timestamp": data.get("timestamp"),
            "verification_method": "Ed25519 + SHA256",
            "log_block": {
                "index": block.index,
                "hash": block.hash,
                "previous_hash": block.previous_hash
            }
        }), 200

    @app.route("/logs", methods=["GET"])
    def get_logs():
        merkle_log = app.config["MERKLE_LOG"]
        return jsonify({
            "chain": merkle_log.get_serializable_chain(),
            "length": len(merkle_log.chain),
            "head_hash": merkle_log.chain[-1].hash
        }), 200

    @app.route("/verify_logs", methods=["GET"])
    def verify_logs():
        merkle_log = app.config["MERKLE_LOG"]
        ok, reason = merkle_log.verify_integrity()
        return jsonify({
            "verified": ok,
            "reason": reason,
            "head_hash": merkle_log.chain[-1].hash
        }), 200 if ok else 400

    @app.route("/health", methods=["GET"])
    def health():
        cert = app.config["CERTIFICATE"]
        return jsonify({
            "status": "healthy",
            "certificate_loaded": True,
            "agent_id": cert["manifest"]["agent_id"],
            "signature_algorithm": cert.get("signature_algorithm", "unknown"),
        }), 200

    project_root = Path(cert_path).resolve().parent.parent
    app.config["PROJECT_ROOT"] = project_root
    app.config["REQUEST_LOG"] = []
    dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"

    @app.after_request
    def log_request_for_dashboard(response):
        log = app.config.get("REQUEST_LOG")
        if log is not None:
            log.append({
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
            })
        return response

    @app.route("/dashboard")
    @app.route("/dashboard/")
    def dashboard():
        return send_from_directory(dashboard_dir, "index.html")

    @app.route("/api/tests", methods=["GET"])
    def list_tests():
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            lines = (result.stdout or "") + (result.stderr or "")
            current_module = ""
            current_class = ""
            test_ids = []
            for line in lines.splitlines():
                m = re.match(r"<Module ([^>]+)>", line.strip())
                if m:
                    current_module = m.group(1).strip()
                    current_class = ""
                    continue
                c = re.match(r"<Class ([^>]+)>", line.strip())
                if c:
                    current_class = c.group(1).strip()
                    continue
                f = re.match(r"<Function ([^>]+)>", line.strip())
                if f and current_module:
                    name = f.group(1).strip()
                    mod = f"tests/{current_module}" if not current_module.startswith("tests/") else current_module
                    node_id = f"{mod}::{current_class}::{name}" if current_class else f"{mod}::{name}"
                    test_ids.append(node_id)
            if not test_ids:
                test_ids = ["tests/test_verification.py", "tests/test_attacks.py"]
            attack_tests = []
            for node_id in test_ids:
                if "test_attacks.py" not in node_id:
                    continue
                parts = node_id.split("::")
                method_name = parts[-1] if len(parts) >= 3 else ""
                if method_name.startswith("test_"):
                    label = method_name[5:].replace("_", " ").title()
                else:
                    label = method_name.replace("_", " ").title() or node_id
                attack_tests.append({"id": node_id, "label": label})
            return jsonify({"tests": test_ids, "attack_tests": attack_tests}), 200
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Collect timeout"}), 500
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/tests/run", methods=["POST"])
    def run_tests():
        payload = request.get_json(silent=True) or {}
        test_ids = payload.get("test_ids") or []
        app.config["REQUEST_LOG"] = []
        steps_file = project_root / ".cursor" / "test_steps.ndjson"
        steps_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            steps_file.write_text("")
        except Exception:
            pass
        try:
            cmd = [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"]
            if test_ids:
                cmd.extend(test_ids)
            env = {
                **os.environ,
                "AGENT_AUTH_SERVER_EXTERNAL": "1",
                "TEST_STEPS_FILE": str(steps_file),
            }
            result = subprocess.run(
                cmd,
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=120,
                env=env,
            )
            steps_by_test = {}
            if steps_file.exists():
                for line in steps_file.read_text().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        tid = entry.pop("test_id", None)
                        if tid:
                            steps_by_test.setdefault(tid, []).append(entry)
                    except json.JSONDecodeError:
                        pass
            request_log = app.config.get("REQUEST_LOG") or []
            return jsonify({
                "exit_code": result.returncode,
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
                "passed": result.returncode == 0,
                "steps": steps_by_test,
                "request_log": request_log,
            }), 200
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Run timeout", "stdout": "", "stderr": "", "steps": {}, "request_log": []}), 500
        except Exception as e:
            return jsonify({"error": str(e), "stdout": "", "stderr": "", "steps": {}, "request_log": []}), 500

    reports_dir = Path(cert_path).parent / "reports"
    app.config["REPORTS_DIR"] = reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    @app.route("/api/security/status", methods=["GET"])
    def security_status():
        cert = app.config["CERTIFICATE"]
        merkle_log = app.config["MERKLE_LOG"]

        security_reports = []
        if reports_dir.exists():
            report_files = sorted(reports_dir.glob("*.json"))[-10:]
            for report_file in report_files:
                try:
                    with open(report_file, "r") as f:
                        security_reports.append({
                            "filename": report_file.name,
                            "timestamp": report_file.stat().st_mtime,
                            "summary": json.load(f).get("summary", {})
                        })
                except Exception:
                    pass

        return jsonify({
            "status": "monitoring",
            "agent_id": cert["manifest"]["agent_id"],
            "certificate_loaded": True,
            "merkle_chain_length": len(merkle_log.chain),
            "merkle_chain_verified": merkle_log.verify_integrity()[0],
            "recent_reports": security_reports,
            "endpoints": {
                "garak_scan": "POST /api/security/garak/scan",
                "purplellama_eval": "POST /api/security/purplellama/eval",
                "reports": "GET /api/security/reports",
            }
        }), 200

    @app.route("/api/security/garak/scan", methods=["POST"])
    def run_garak_scan():
        try:
            tools_dir = project_root / "tools"
            spec = importlib.util.spec_from_file_location(
                "run_garak_scan",
                tools_dir / "run_garak_scan.py",
            )
            garak_tool = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(garak_tool)

            payload = request.get_json(silent=True) or {}
            categories = payload.get("categories")
            output_path = payload.get("output")

            scanner = garak_tool.GarakScanner(
                str(cert_path),
                output_dir=reports_dir
            )

            if categories:
                for category in categories:
                    result = scanner.run_category(category)
                    scanner.results["probe_results"].append(result)
            else:
                scanner.run_all()

            report_path = scanner.save_report(output_path)

            return jsonify({
                "scan_type": "garak",
                "status": "completed",
                "report_path": str(report_path.relative_to(reports_dir)),
                "summary": scanner.results["summary"],
                "results": scanner.results["probe_results"]
            }), 200

        except ImportError as e:
            return jsonify({
                "error": "Garak scan tool not found",
                "message": f"Failed to import garak scanner: {e}"
            }), 503
        except Exception as e:
            return jsonify({
                "error": "Scan failed",
                "message": str(e)
            }), 500

    @app.route("/api/security/purplellama/eval", methods=["POST"])
    def run_purplellama_eval():
        try:
            tools_dir = project_root / "tools"
            spec = importlib.util.spec_from_file_location(
                "run_purplellama_eval",
                tools_dir / "run_purplellama_eval.py",
            )
            purplellama_tool = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(purplellama_tool)

            payload = request.get_json(silent=True) or {}
            categories = payload.get("categories")
            output_path = payload.get("output")
            baseline_path = payload.get("baseline")

            evaluator = purplellama_tool.PurpleLlamaEvaluator(
                str(cert_path),
                output_dir=reports_dir
            )

            if categories:
                for category in categories:
                    result = evaluator.run_category(category)
                    evaluator.results["categories"][category] = result
            else:
                evaluator.run_all()

            if baseline_path:
                evaluator.compare_with_baseline(baseline_path)

            report_path = evaluator.save_report(output_path)

            return jsonify({
                "eval_type": "purplellama",
                "status": "completed",
                "report_path": str(report_path.relative_to(reports_dir)),
                "summary": evaluator.results.get("summary", {}),
                "results": evaluator.results.get("categories", {}),
                "baseline_comparison": evaluator.results.get("baseline_comparison", {})
            }), 200

        except ImportError as e:
            return jsonify({
                "error": "PurpleLlama evaluator tool not found",
                "message": f"Failed to import purplellama evaluator: {e}"
            }), 503
        except Exception as e:
            return jsonify({
                "error": "Evaluation failed",
                "message": str(e)
            }), 500

    @app.route("/api/security/reports", methods=["GET"])
    def list_security_reports():
        reports = []

        if reports_dir.exists():
            report_files = sorted(
                reports_dir.glob("*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )

            for report_file in report_files:
                try:
                    with open(report_file, "r") as f:
                        report_data = json.load(f)

                    report_type = "unknown"
                    if "scan_info" in report_data:
                        report_type = "garak"
                    elif "eval_info" in report_data:
                        report_type = "purplellama"
                    elif "probe_type" in report_data:
                        report_type = "custom"

                    summary = report_data.get("summary", {})

                    reports.append({
                        "filename": report_file.name,
                        "type": report_type,
                        "timestamp": report_file.stat().st_mtime,
                        "modified": datetime.fromtimestamp(
                            report_file.stat().st_mtime,
                            timezone.utc
                        ).isoformat(),
                        "size_bytes": report_file.stat().st_size,
                        "summary": summary
                    })
                except Exception:
                    pass

        return jsonify({
            "reports": reports,
            "count": len(reports),
            "reports_dir": str(reports_dir)
        }), 200

    @app.route("/api/security/reports/<path:filename>", methods=["GET"])
    def get_security_report(filename: str):
        report_path = reports_dir / filename

        if not report_path.exists():
            return jsonify({
                "error": "Report not found",
                "filename": filename
            }), 404

        if not report_path.resolve().parent == reports_dir.resolve():
            return jsonify({
                "error": "Invalid report path"
            }), 403

        with open(report_path, "r") as f:
            return jsonify(json.load(f)), 200

    @app.route("/api/security/tests", methods=["GET"])
    def list_security_tests():
        security_tests = [
            {"id": "garak:jailbreak", "label": "Garak Jailbreak Probes", "description": "Test resistance to jailbreak attacks"},
            {"id": "garak:dan", "label": "Garak DAN Attacks", "description": "Test resistance to Do Anything Now attacks"},
            {"id": "garak:goal_tampering", "label": "Garak Goal Tampering", "description": "Test resistance to goal injection"},
            {"id": "garak:permission_escalation", "label": "Garak Permission Escalation", "description": "Test resistance to permission elevation"},
            {"id": "garak:leakage", "label": "Garak Information Leakage", "description": "Test for sensitive information leaks"},
            {"id": "purplellama:prompt_injection", "label": "PurpleLlama Prompt Injection", "description": "Test for prompt injection vulnerabilities"},
            {"id": "purplellama:code_interpreter", "label": "PurpleLlama Code Interpreter", "description": "Test code execution security"},
        ]
        return jsonify({"security_tests": security_tests}), 200

    @app.route("/api/security/tests/run", methods=["POST"])
    def run_security_tests():
        payload = request.get_json(silent=True) or {}
        test_ids = payload.get("test_ids") or []

        test_mapping = {
            "garak:jailbreak": "tests/security/test_garak_probes.py::TestGarakJailbreakProbes",
            "garak:dan": "tests/security/test_garak_probes.py::TestGarakDanProbes",
            "garak:goal_tampering": "tests/security/test_garak_probes.py::TestGarakLeakageProbes",
            "garak:permission_escalation": "tests/security/test_garak_probes.py::TestGarakMemorizationProbes",
            "garak:leakage": "tests/security/test_garak_probes.py::TestGarakContinuationProbes",
            "purplellama:prompt_injection": "tests/security/test_purplellama.py::TestPurpleLlamaPromptInjection",
            "purplellama:code_interpreter": "tests/security/test_purplellama.py::TestPurpleLlamaCodeInterpreter",
        }

        pytest_ids = []
        if test_ids:
            pytest_ids = [test_mapping.get(t) for t in test_ids if t in test_mapping]
        else:
            pytest_ids = list(test_mapping.values())

        app.config["REQUEST_LOG"] = []

        try:
            cmd = [sys.executable, "-m", "pytest", "-v", "--tb=short"]
            if pytest_ids:
                cmd.extend(pytest_ids)
            else:
                cmd.append("tests/security/")

            env = {
                **os.environ,
                "AGENT_AUTH_SERVER_EXTERNAL": "1",
            }
            result = subprocess.run(
                cmd,
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=300,
                env=env,
            )

            request_log = app.config.get("REQUEST_LOG") or []
            return jsonify({
                "exit_code": result.returncode,
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
                "passed": result.returncode == 0,
                "test_ids": pytest_ids,
                "request_log": request_log,
            }), 200
        except subprocess.TimeoutExpired:
            return jsonify({"error": "Run timeout", "stdout": "", "stderr": "", "passed": False}), 500
        except Exception as e:
            return jsonify({"error": str(e), "stdout": "", "stderr": "", "passed": False}), 500

    _debug_log(
        "create_app routes registered",
        {"rules": [f"{r.rule} {list(r.methods - {'HEAD', 'OPTIONS'})}" for r in app.url_map.iter_rules()]},
        "H1_H2_H3",
    )

    @app.errorhandler(404)
    def handle_404(e):
        _debug_log("404 returned", {"path": request.path, "method": request.method}, "H4_H5")
        return jsonify({"error": "Not found"}), 404

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent authorization service")
    parser.add_argument(
        "--cert",
        default="config/agent_certificate.asc",
        help="Path to the signed agent certificate (default: config/agent_certificate.asc)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5001,
        help="Port to listen on (default: 5001)",
    )
    args = parser.parse_args()

    app = create_app(args.cert)

    print("\n" + "=" * 60)
    print("Authorization Service Started")
    print("=" * 60)
    cert = app.config["CERTIFICATE"]
    print(f"Protecting agent: {cert['manifest']['agent_id']}")
    print(f"Signature: Ed25519")
    print(f"Listening on http://localhost:{args.port}")
    print("=" * 60 + "\n")

    app.run(port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
