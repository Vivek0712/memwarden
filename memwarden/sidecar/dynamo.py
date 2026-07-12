"""DynamoDB sidecar index (design §4): four tables, blast-radius separated.

- {prefix}-envelopes    PK TENANT#{t}#REC#{rid} / SK ENV; GSI1 actor walk, GSI2 sweep
- {prefix}-quarantine   PK TENANT#{t}#REC#{rid} / SK Q
- {prefix}-audit        PK TENANT#{t}#CHAIN / SK SEQ#{seq:012d}, conditional append
- {prefix}-certificates PK TENANT#{t} / SK CERT#{iso}#{cert_id}
"""

from __future__ import annotations

import datetime as _dt
import time
from decimal import Decimal
from typing import Iterable, Optional

from botocore.exceptions import ClientError

import json

from ..audit import GENESIS, AuditEntry, _entry_hash, _h, canonical_body
from ..envelope import GovernanceEnvelope
from ..errors import SidecarUnavailable
from .base import Verdict


def _to_ddb(x):
    if isinstance(x, float):
        return Decimal(str(x))
    if isinstance(x, dict):
        return {k: _to_ddb(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_to_ddb(v) for v in x]
    return x


def _from_ddb(x):
    if isinstance(x, Decimal):
        f = float(x)
        return int(f) if f.is_integer() and "." not in str(x) else f
    if isinstance(x, dict):
        return {k: _from_ddb(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_from_ddb(v) for v in x]
    return x


def _day_bucket(epoch: float) -> str:
    return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime("%Y%m%d")


class DynamoSidecar:
    def __init__(self, session=None, region: str = "us-east-1",
                 table_prefix: str = "memwarden"):
        import boto3
        session = session or boto3.Session(region_name=region)
        ddb = session.resource("dynamodb")
        self.envelopes = ddb.Table(f"{table_prefix}-envelopes")
        self.quarantine = ddb.Table(f"{table_prefix}-quarantine")
        self.audit = ddb.Table(f"{table_prefix}-audit")
        self.certs = ddb.Table(f"{table_prefix}-certificates")
        self._head_cache: dict[str, tuple[int, str]] = {}   # tenant -> (seq, hash)

    @staticmethod
    def _rec_pk(tenant_id: str, record_id: str) -> str:
        return f"TENANT#{tenant_id}#REC#{record_id}"

    def _call(self, fn, **kwargs):
        try:
            return fn(**kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("ProvisionedThroughputExceededException", "ThrottlingException",
                        "InternalServerError", "ServiceUnavailable"):
                raise SidecarUnavailable(code) from e
            raise

    # -- envelopes -------------------------------------------------------------
    def put_envelope_for(self, record_id: str, env: GovernanceEnvelope) -> None:
        item = {
            "pk": self._rec_pk(env.tenant_id, record_id), "sk": "ENV",
            "record_id": record_id, **_to_ddb(env.to_item()),
            "gsi1pk": f"TENANT#{env.tenant_id}#ACTOR#{env.actor_id}",
            "gsi1sk": Decimal(str(env.created_at)),
        }
        if env.expires_at_epoch is not None:   # sparse GSI2: only rows with a TTL
            item["gsi2pk"] = f"TENANT#{env.tenant_id}#EXP#{_day_bucket(env.expires_at_epoch)}"
            item["gsi2sk"] = Decimal(str(env.expires_at_epoch))
        self._call(self.envelopes.put_item, Item=item)

    def get_envelope(self, tenant_id: str, record_id: str) -> Optional[GovernanceEnvelope]:
        r = self._call(self.envelopes.get_item,
                       Key={"pk": self._rec_pk(tenant_id, record_id), "sk": "ENV"})
        item = r.get("Item")
        return self._env_from_item(item) if item else None

    def delete_envelope(self, tenant_id: str, record_id: str) -> None:
        self._call(self.envelopes.delete_item,
                   Key={"pk": self._rec_pk(tenant_id, record_id), "sk": "ENV"})

    def envelopes_by_actor(self, tenant_id: str, actor_id: str) -> Iterable[tuple[str, GovernanceEnvelope]]:
        kwargs = {
            "IndexName": "gsi1",
            "KeyConditionExpression": "gsi1pk = :p",
            "ExpressionAttributeValues": {":p": f"TENANT#{tenant_id}#ACTOR#{actor_id}"},
        }
        while True:
            r = self._call(self.envelopes.query, **kwargs)
            for item in r["Items"]:
                yield item["record_id"], self._env_from_item(item)
            if "LastEvaluatedKey" not in r:
                return
            kwargs["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def expired_envelopes(self, tenant_id: str, now: float,
                          lookback_days: int = 5) -> Iterable[tuple[str, GovernanceEnvelope]]:
        """Sweep walk over GSI2 day partitions (design §4.1). Validation walks a
        bounded lookback window; production walks all outstanding partitions."""
        for d in range(lookback_days, -1, -1):
            bucket = _day_bucket(now - d * 86400)
            kwargs = {
                "IndexName": "gsi2",
                "KeyConditionExpression": "gsi2pk = :p AND gsi2sk <= :now",
                "ExpressionAttributeValues": {
                    ":p": f"TENANT#{tenant_id}#EXP#{bucket}",
                    ":now": Decimal(str(now))},
            }
            while True:
                r = self._call(self.envelopes.query, **kwargs)
                for item in r["Items"]:
                    yield item["record_id"], self._env_from_item(item)
                if "LastEvaluatedKey" not in r:
                    break
                kwargs["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def set_legal_hold(self, tenant_id: str, record_id: str, hold: bool) -> None:
        self._call(self.envelopes.update_item,
                   Key={"pk": self._rec_pk(tenant_id, record_id), "sk": "ENV"},
                   UpdateExpression="SET legal_hold = :h",
                   ExpressionAttributeValues={":h": hold})

    @staticmethod
    def _env_from_item(item: dict) -> GovernanceEnvelope:
        fields = {k: _from_ddb(v) for k, v in item.items()
                  if k not in ("pk", "sk", "record_id", "gsi1pk", "gsi1sk",
                               "gsi2pk", "gsi2sk")}
        return GovernanceEnvelope.from_item(fields)

    # -- quarantine verdicts ------------------------------------------------------
    def put_verdict(self, tenant_id: str, record_id: str, verdict: Verdict) -> None:
        self._call(self.quarantine.put_item, Item={
            "pk": self._rec_pk(tenant_id, record_id), "sk": "Q",
            "verdict": verdict.verdict, "verdict_digest": verdict.verdict_digest,
            "l1_score": Decimal(str(verdict.l1_score)),
            "l2_detail": _to_ddb(verdict.l2_detail),
            "updated_at": Decimal(str(time.time()))})

    def get_verdict(self, tenant_id: str, record_id: str) -> Optional[Verdict]:
        r = self._call(self.quarantine.get_item,
                       Key={"pk": self._rec_pk(tenant_id, record_id), "sk": "Q"})
        item = r.get("Item")
        if not item:
            return None
        return Verdict(item["verdict"], item["verdict_digest"],
                       float(item.get("l1_score", 0)), _from_ddb(item.get("l2_detail", {})))

    def delete_verdict(self, tenant_id: str, record_id: str) -> None:
        self._call(self.quarantine.delete_item,
                   Key={"pk": self._rec_pk(tenant_id, record_id), "sk": "Q"})

    # -- audit chain (conditional-append protocol, design §4.3) ---------------------
    def _read_head(self, tenant_id: str) -> tuple[int, str]:
        r = self._call(self.audit.query,
                       KeyConditionExpression="pk = :p",
                       ExpressionAttributeValues={":p": f"TENANT#{tenant_id}#CHAIN"},
                       ScanIndexForward=False, Limit=1)
        items = r["Items"]
        if not items:
            return -1, GENESIS
        return int(items[0]["seq"]), items[0]["entry_hash"]

    def audit_append(self, tenant_id: str, op: str, record_id: str = "",
                     actor_id: str = "", detail: Optional[dict] = None) -> AuditEntry:
        if tenant_id not in self._head_cache:
            self._head_cache[tenant_id] = self._read_head(tenant_id)
        for _ in range(8):
            seq, prev = self._head_cache[tenant_id]
            body = {"seq": seq + 1, "op": op,
                    "record_id_hash": _h(record_id) if record_id else "",
                    "actor_hash": _h(actor_id) if actor_id else "",
                    "detail": detail or {}, "ts": time.time()}
            body_str = canonical_body(body)
            entry = AuditEntry(prev_hash=prev, entry_hash=_entry_hash(prev, body_str),
                               **body)
            try:
                # The canonical JSON is the hashed artifact and is stored
                # verbatim; op/seq are duplicated as plain attributes for
                # queryability only.
                self._call(self.audit.put_item,
                           Item={"pk": f"TENANT#{tenant_id}#CHAIN",
                                 "sk": f"SEQ#{entry.seq:012d}",
                                 "seq": entry.seq, "op": op,
                                 "body_json": body_str,
                                 "prev_hash": entry.prev_hash,
                                 "entry_hash": entry.entry_hash},
                           ConditionExpression="attribute_not_exists(sk)")
                self._head_cache[tenant_id] = (entry.seq, entry.entry_hash)
                return entry
            except ClientError as e:
                if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
                from ..metrics import registry
                registry.incr("memwarden.audit.append_retries")   # design §15
                self._head_cache[tenant_id] = self._read_head(tenant_id)  # retry
        raise SidecarUnavailable("audit append contention budget exhausted")

    def audit_entries(self, tenant_id: str) -> list[AuditEntry]:
        entries, kwargs = [], {
            "KeyConditionExpression": "pk = :p",
            "ExpressionAttributeValues": {":p": f"TENANT#{tenant_id}#CHAIN"}}
        while True:
            r = self._call(self.audit.query, **kwargs)
            for item in r["Items"]:
                body = json.loads(item["body_json"])
                entries.append(AuditEntry(
                    prev_hash=item["prev_hash"], entry_hash=item["entry_hash"], **body))
            if "LastEvaluatedKey" not in r:
                return entries
            kwargs["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def chain_head(self, tenant_id: str) -> str:
        return self._read_head(tenant_id)[1]

    # -- certificates -----------------------------------------------------------------
    def put_certificate(self, tenant_id: str, cert: dict) -> None:
        iso = _dt.datetime.fromtimestamp(cert["ts"], _dt.timezone.utc).isoformat()
        self._call(self.certs.put_item, Item={
            "pk": f"TENANT#{tenant_id}", "sk": f"CERT#{iso}#{cert['cert_id']}",
            **_to_ddb(cert)})

    def certificates(self, tenant_id: str) -> list[dict]:
        r = self._call(self.certs.query,
                       KeyConditionExpression="pk = :p",
                       ExpressionAttributeValues={":p": f"TENANT#{tenant_id}"})
        return [{k: _from_ddb(v) for k, v in item.items() if k not in ("pk", "sk")}
                for item in r["Items"]]
