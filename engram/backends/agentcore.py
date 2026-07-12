"""AgentCore Memory adapter (design §12): protocol ops mapped one-to-one onto
the bedrock-agentcore data plane. Transport only — no policy, detection, audit,
or erasure logic lives here.

Service behavior notes (validated live, see EXPERIMENTS.md):
- Namespaces are conventions: BatchCreateMemoryRecords accepts free-form
  namespaces not tied to any strategy, and semantic retrieval works on them.
- Reads (list/retrieve) are eventually consistent w.r.t. creates and deletes,
  with observed lag in the single-digit seconds.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from typing import Iterator, Optional

from botocore.config import Config
from botocore.exceptions import ClientError

from ..errors import BackendUnavailable
from .base import Page, Record

_RETRY_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 8})


def _canon(ns: str) -> str:
    """The service canonicalizes namespaces to '/a/b/c/'; queries with the bare
    form match nothing, so the adapter always sends the canonical form."""
    return "/" + ns.strip("/") + "/"


def _wrap_throttle(exc: ClientError):
    code = exc.response.get("Error", {}).get("Code", "")
    if code in ("ThrottlingException", "TooManyRequestsException",
                "ServiceUnavailableException"):
        raise BackendUnavailable(f"agentcore throttled: {code}") from exc
    raise exc


class AgentCoreBackend:
    def __init__(self, memory_id: str, session=None, region: str = "us-east-1",
                 client=None):
        if client is None:
            import boto3
            session = session or boto3.Session(region_name=region)
            client = session.client("bedrock-agentcore", config=_RETRY_CONFIG)
        self.client = client
        self.memory_id = memory_id

    # -- seven-operation protocol -------------------------------------------
    def put(self, ns: str, content: str, meta: dict) -> str:
        record: dict = {
            "requestIdentifier": uuid.uuid4().hex,
            "namespaces": [_canon(ns)],
            "content": {"text": content},
            "timestamp": _dt.datetime.now(_dt.timezone.utc),
        }
        if meta.get("actor_id"):
            record["metadata"] = {"actor_id": {"stringValue": meta["actor_id"]}}
        try:
            resp = self.client.batch_create_memory_records(
                memoryId=self.memory_id, records=[record])
        except ClientError as e:
            _wrap_throttle(e)
        if resp["failedRecords"]:
            raise BackendUnavailable(f"create failed: {resp['failedRecords']}")
        return resp["successfulRecords"][0]["memoryRecordId"]

    def get(self, ns: str, record_id: str) -> Optional[Record]:
        try:
            r = self.client.get_memory_record(
                memoryId=self.memory_id, memoryRecordId=record_id)["memoryRecord"]
        except self.client.exceptions.ResourceNotFoundException:
            return None
        except ClientError as e:
            _wrap_throttle(e)
        if ns and _canon(ns) not in [_canon(x) for x in r.get("namespaces", [])]:
            return None
        return self._to_record(r)

    def retrieve(self, ns: str, query: str, k: int = 8) -> list[Record]:
        try:
            resp = self.client.retrieve_memory_records(
                memoryId=self.memory_id, namespace=_canon(ns),
                searchCriteria={"searchQuery": query, "topK": k}, maxResults=k)
        except ClientError as e:
            _wrap_throttle(e)
        return [self._to_record(r) for r in resp["memoryRecordSummaries"]]

    def list(self, ns: str, cursor: Optional[str] = None) -> Page:
        kwargs = {"memoryId": self.memory_id, "namespace": _canon(ns), "maxResults": 100}
        if cursor:
            kwargs["nextToken"] = cursor
        try:
            resp = self.client.list_memory_records(**kwargs)
        except ClientError as e:
            _wrap_throttle(e)
        return Page(records=[self._to_record(r) for r in resp["memoryRecordSummaries"]],
                    cursor=resp.get("nextToken"))

    def delete(self, ns: str, record_id: str) -> bool:
        try:
            self.client.delete_memory_record(
                memoryId=self.memory_id, memoryRecordId=record_id)
            return True
        except self.client.exceptions.ResourceNotFoundException:
            return False
        except ClientError as e:
            _wrap_throttle(e)

    def batch_delete(self, ns: str, record_ids: list[str]) -> int:
        deleted = 0
        for i in range(0, len(record_ids), 100):     # service limit: 100 per call
            chunk = record_ids[i:i + 100]
            try:
                resp = self.client.batch_delete_memory_records(
                    memoryId=self.memory_id,
                    records=[{"memoryRecordId": rid} for rid in chunk])
            except ClientError as e:
                _wrap_throttle(e)
            deleted += len(resp.get("successfulRecords", []))
        return deleted

    def list_by_actor(self, actor_id: str,
                      namespace_path: str = "tenants") -> Iterator[Record]:
        token = None
        while True:
            kwargs = {
                "memoryId": self.memory_id, "namespacePath": _canon(namespace_path),
                "maxResults": 100,
                "metadataFilters": [{
                    "left": {"metadataKey": "actor_id"},
                    "operator": "EQUALS_TO",
                    "right": {"metadataValue": {"stringValue": actor_id}},
                }],
            }
            if token:
                kwargs["nextToken"] = token
            try:
                resp = self.client.list_memory_records(**kwargs)
            except ClientError as e:
                _wrap_throttle(e)
            for r in resp["memoryRecordSummaries"]:
                yield self._to_record(r)
            token = resp.get("nextToken")
            if not token:
                return

    # -- short-term event tier (erasure walks it: design §9) ------------------
    def create_event(self, actor_id: str, session_id: str, payload: str) -> str:
        resp = self.client.create_event(
            memoryId=self.memory_id, actorId=actor_id, sessionId=session_id,
            eventTimestamp=_dt.datetime.now(_dt.timezone.utc),
            payload=[{"conversational": {"content": {"text": payload}, "role": "USER"}}])
        return resp["event"]["eventId"]

    def delete_actor_events(self, actor_id: str) -> int:
        deleted = 0
        token = None
        sessions = []
        while True:
            kwargs = {"memoryId": self.memory_id, "actorId": actor_id, "maxResults": 100}
            if token:
                kwargs["nextToken"] = token
            try:
                resp = self.client.list_sessions(**kwargs)
            except self.client.exceptions.ResourceNotFoundException:
                return deleted        # actor has no event-tier presence
            sessions += [s["sessionId"] for s in resp["sessionSummaries"]]
            token = resp.get("nextToken")
            if not token:
                break
        for sid in sessions:
            token = None
            while True:
                kwargs = {"memoryId": self.memory_id, "actorId": actor_id,
                          "sessionId": sid, "includePayloads": False, "maxResults": 100}
                if token:
                    kwargs["nextToken"] = token
                resp = self.client.list_events(**kwargs)
                for ev in resp["events"]:
                    self.client.delete_event(memoryId=self.memory_id, actorId=actor_id,
                                             sessionId=sid, eventId=ev["eventId"])
                    deleted += 1
                token = resp.get("nextToken")
                if not token:
                    break
        return deleted

    # ------------------------------------------------------------------------
    @staticmethod
    def _to_record(r: dict) -> Record:
        meta = {}
        for key, val in (r.get("metadata") or {}).items():
            meta[key] = val.get("stringValue", val)
        nss = r.get("namespaces", [])
        return Record(record_id=r["memoryRecordId"], namespace=nss[0] if nss else "",
                      content=r.get("content", {}).get("text", ""), meta=meta)
