"""memwarden-verify: auditor CLI (design §10).

Replays a tenant chain, checks every prev_hash, and validates the latest anchor.
Runnable with read-only credentials. Works against the local sidecar (library
mode) or the DynamoDB/S3 deployment (--table/--bucket).
"""

from __future__ import annotations

import argparse
import json
import sys

from .audit import AuditChain, merkle_root


def verify_tenant(sidecar, tenant_id: str, anchors: list[dict] | None = None) -> dict:
    entries = sidecar.audit_entries(tenant_id)
    ok, bad_seq = AuditChain.verify(entries)
    out = {"tenant": tenant_id, "entries": len(entries), "chain_ok": ok,
           "first_bad_seq": bad_seq}
    if ok and anchors:
        latest = anchors[-1]
        head_at_anchor = latest["chain_heads"].get(tenant_id)
        # The anchored head must appear on the chain (entries after the anchor
        # extend it; tampering before it breaks replay above).
        on_chain = any(e.entry_hash == head_at_anchor for e in entries)
        root_ok = merkle_root(list(latest["chain_heads"].values())) == latest["merkle_root"]
        out["anchor_ok"] = bool(on_chain and root_ok)
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="memwarden-verify")
    p.add_argument("--tenant", required=True)
    p.add_argument("--table-prefix", default="memwarden",
                   help="DynamoDB table prefix (live mode)")
    p.add_argument("--bucket", help="S3 anchor bucket (live mode)")
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default="us-east-1")
    args = p.parse_args(argv)

    from .sidecar.dynamo import DynamoSidecar
    import boto3
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sidecar = DynamoSidecar(session=session, table_prefix=args.table_prefix)
    anchors = None
    if args.bucket:
        s3 = session.client("s3")
        keys = sorted(o["Key"] for page in s3.get_paginator("list_objects_v2")
                      .paginate(Bucket=args.bucket, Prefix="anchors/")
                      for o in page.get("Contents", []))
        if keys:
            body = s3.get_object(Bucket=args.bucket, Key=keys[-1])["Body"].read()
            anchors = [json.loads(body)]
    result = verify_tenant(sidecar, args.tenant, anchors)
    print(json.dumps(result, indent=2))
    return 0 if result["chain_ok"] and result.get("anchor_ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
