"""Live L2 classifier: Bedrock Guardrails ApplyGuardrail (design §8.2)."""

from __future__ import annotations


class BedrockGuardrail:
    def __init__(self, guardrail_id: str, guardrail_version: str = "DRAFT",
                 session=None, region: str = "us-east-1", client=None):
        if client is None:
            import boto3
            session = session or boto3.Session(region_name=region)
            client = session.client("bedrock-runtime")
        self.client = client
        self.guardrail_id = guardrail_id
        self.guardrail_version = guardrail_version

    def assess(self, content: str) -> tuple[bool, dict]:
        resp = self.client.apply_guardrail(
            guardrailIdentifier=self.guardrail_id,
            guardrailVersion=self.guardrail_version,
            source="INPUT",
            content=[{"text": {"text": content}}])
        attack = resp["action"] == "GUARDRAIL_INTERVENED"
        detail = {"action": resp["action"]}
        assessments = resp.get("assessments", [])
        if assessments:
            filters = assessments[0].get("contentPolicy", {}).get("filters", [])
            detail["filters"] = [
                {"type": f.get("type"), "confidence": f.get("confidence"),
                 "detected": f.get("detected")} for f in filters]
        return attack, detail
