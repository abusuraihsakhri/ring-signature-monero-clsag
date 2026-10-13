"""
Command Line Interface for Ring Signature Monero Clsag.
"""
import argparse
import csv
import json
import sys
from pathlib import Path
from agents.models import SystemTaskPayload
from agents.supervisor import SystemSupervisor
from agents.base import AuditLogger

supervisor = SystemSupervisor(model_provider="mock")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="ring-signature-monero-clsag", description="Ring Signature Monero Clsag")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Audit
    p_audit = subparsers.add_parser("audit", help="Run single task evaluation")
    p_audit.add_argument("--task-id", default="TASK-2026-001")
    p_audit.add_argument("--target", default="KEY-TARGET-01")
    p_audit.add_argument("--primary", type=float, default=28.5)
    p_audit.add_argument("--secondary", type=float, default=14.2)
    p_audit.add_argument("--critical", action="store_true")
    p_audit.add_argument("--status", default="DISCORDANT")

    # Chat
    p_chat = subparsers.add_parser("chat", help="System configuration query")
    p_chat.add_argument("query", nargs="+")

    # Batch
    p_batch = subparsers.add_parser("batch", help="Batch process CSV records")
    p_batch.add_argument("-i", "--input", required=True)
    p_batch.add_argument("-o", "--output", default="results.csv")

    # Verify Audit
    subparsers.add_parser("verify-audit", help="Verify HMAC audit trail integrity")

    # Serve
    p_serve = subparsers.add_parser("serve", help="Launch FastAPI REST server")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args(argv)

    if args.command == "audit":
        payload = SystemTaskPayload(
            task_id=args.task_id,
            target_identifier=args.target,
            primary_metric=args.primary,
            secondary_metric=args.secondary,
            status_descriptor=args.status,
            is_critical_flag=args.critical,
        )
        dossier = supervisor.process_task(payload)
        print("=" * 80)
        print(f"  RING SIGNATURE MONERO CLSAG")
        print(f"  Domain: Post-Quantum Cryptography & Hardware Security | Standard: NIST FIPS 203/204/205 / ISO/IEC 17825 Standards")
        print(f"  Dossier ID: {dossier.dossier_id} | Urgency: [{dossier.overall_urgency.value}]")
        print("=" * 80)
        for a in dossier.alerts:
            print(f"\n  [{a.urgency.value}] from {a.origin_worker}:")
            print(f"  Summary: {a.summary}")
            print(f"  Details: {a.technical_details}")
            print(f"  Action:  {a.actionable_remediation}")
        print(f"\n  HMAC-SHA256 Audit Hash: {dossier.audit_hash}")
        print("=" * 80)
        return 0

    if args.command == "chat":
        ans = supervisor.query_supervisory_chat(" ".join(args.query))
        print(f"\n[Ring Signature Monero Clsag Supervisor]:\n{ans}\n")
        return 0

    if args.command == "verify-audit":
        trail = AuditLogger.get_trail()
        valid = AuditLogger.verify_integrity()
        print(f"Audit Trail Blocks: {len(trail)} | Cryptographic Integrity Verified: {valid}")
        return 0

    if args.command == "batch":
        if Path(args.input).resolve() == Path(args.output).resolve():
            print("Error: Input and output CSV paths must be different.")
            return 1
        try:
            with open(args.input, mode="r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                fieldnames = list(reader.fieldnames or [])
                rows = list(reader)
        except FileNotFoundError:
            print(f"Error: Input file '{args.input}' not found.")
            return 1
        except Exception as e:
            print(f"Error reading input file: {e}")
            return 1

        out_fields = list(dict.fromkeys(fieldnames + ["overall_urgency", "integrity_status", "total_alerts", "audit_hash"]))
        out_rows = []
        errors = 0
        for idx, r in enumerate(rows):
            try:
                payload = SystemTaskPayload(
                    task_id=r.get("task_id", "TASK-01"),
                    target_identifier=r.get("target_identifier", "TARGET-01"),
                    primary_metric=float(r.get("primary_metric", 15.0)),
                    secondary_metric=float(r.get("secondary_metric", 5.0)),
                    status_descriptor=r.get("status_descriptor", "NOMINAL"),
                    is_critical_flag=str(r.get("is_critical_flag", "")).lower() in ("true", "1", "yes"),
                )
                dossier = supervisor.process_task(payload)
                row_dict = dict(r)
                row_dict["overall_urgency"] = dossier.overall_urgency.value
                row_dict["integrity_status"] = dossier.integrity_status.value
                row_dict["total_alerts"] = dossier.total_alerts
                row_dict["audit_hash"] = dossier.audit_hash
                out_rows.append(row_dict)
            except (ValueError, TypeError) as e:
                print(f"Warning: Skipping row {idx + 1}: {e}")
                errors += 1

        with open(args.output, mode="w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=out_fields)
            writer.writeheader()
            writer.writerows(out_rows)
        print(f"Processed {len(out_rows)} records -> {args.output} ({errors} skipped due to errors)")
        return 0

    if args.command == "serve":
        import uvicorn
        from agents.api import app
        print(f"Starting Ring Signature Monero Clsag API server on http://{args.host}:{args.port}")
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
