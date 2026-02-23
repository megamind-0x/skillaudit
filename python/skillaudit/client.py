"""SkillAudit Python SDK — zero-dependency client for the SkillAudit API."""

from __future__ import annotations

import json
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Optional


BASE_URL = "https://skillaudit.vercel.app"


# ── Result dataclasses ─────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security finding."""
    rule_id: str
    severity: str
    category: str
    name: str
    description: str
    line: int
    line_content: str = ""
    match: str = ""
    context: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            rule_id=d.get("ruleId", d.get("rule_id", "")),
            severity=d.get("severity", ""),
            category=d.get("category", ""),
            name=d.get("name", ""),
            description=d.get("description", ""),
            line=d.get("line", 0),
            line_content=d.get("lineContent", d.get("line_content", "")),
            match=d.get("match", ""),
            context=d.get("context", ""),
        )


@dataclass
class GateResult:
    """Result from the /gate endpoint."""
    allow: bool
    decision: str
    risk: str
    score: int
    findings: int
    critical: int = 0
    high: int = 0
    verdict: str = ""
    scan_id: str = ""
    report_url: str = ""
    domain: str = ""
    domain_reputation: str = ""
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "GateResult":
        return cls(
            allow=d.get("allow", False),
            decision=d.get("decision", "error"),
            risk=d.get("risk", "unknown"),
            score=d.get("score", 0),
            findings=d.get("findings", 0),
            critical=d.get("critical", 0),
            high=d.get("high", 0),
            verdict=d.get("verdict", ""),
            scan_id=d.get("scanId", d.get("scan_id", "")),
            report_url=d.get("reportUrl", d.get("report_url", "")),
            domain=d.get("domain", ""),
            domain_reputation=d.get("domainReputation", d.get("domain_reputation", "")),
            raw=d,
        )


@dataclass
class ScanResult:
    """Result from a full scan."""
    source: str
    risk_level: str
    risk_score: int
    verdict: str
    findings: list[Finding]
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    suppressed: int = 0
    content_hash: str = ""
    scan_id: str = ""
    report_url: str = ""
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        summary = d.get("summary", {})
        findings = [Finding.from_dict(f) for f in d.get("findings", [])]
        return cls(
            source=d.get("source", d.get("url", "")),
            risk_level=d.get("riskLevel", d.get("risk_level", "")),
            risk_score=d.get("riskScore", d.get("risk_score", 0)),
            verdict=d.get("verdict", ""),
            findings=findings,
            total=summary.get("total", len(findings)),
            critical=summary.get("critical", 0),
            high=summary.get("high", 0),
            medium=summary.get("medium", 0),
            low=summary.get("low", 0),
            suppressed=summary.get("suppressed", 0),
            content_hash=d.get("contentHash", d.get("content_hash", "")),
            scan_id=d.get("id", d.get("scanId", "")),
            report_url=d.get("reportUrl", d.get("report_url", "")),
            raw=d,
        )

    @property
    def is_clean(self) -> bool:
        return self.risk_score == 0

    @property
    def is_safe(self) -> bool:
        return self.risk_level in ("clean", "low")


@dataclass
class BulkGateResult:
    """Result from the /gate/bulk endpoint."""
    allow: bool
    decision: str
    total: int
    blocked: list[str] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "BulkGateResult":
        return cls(
            allow=d.get("allow", False),
            decision=d.get("decision", "error"),
            total=d.get("total", 0),
            blocked=d.get("blocked", []),
            results=d.get("results", []),
            raw=d,
        )


# ── HTTP helpers ───────────────────────────────────────────────────────────

def _get(url: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": f"skillaudit-python/{__import__('skillaudit').__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        try:
            return json.loads(body)
        except Exception:
            raise RuntimeError(f"SkillAudit API error {e.code}: {body[:500]}") from e


def _post(url: str, data: dict, timeout: int = 30) -> dict:
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"skillaudit-python/{__import__('skillaudit').__version__}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body_str = e.read().decode() if e.fp else ""
        try:
            return json.loads(body_str)
        except Exception:
            raise RuntimeError(f"SkillAudit API error {e.code}: {body_str[:500]}") from e


# ── Public API ─────────────────────────────────────────────────────────────

def gate(
    url: str,
    threshold: str = "moderate",
    api_key: Optional[str] = None,
    policy: Optional[str] = None,
    base_url: str = BASE_URL,
    timeout: int = 30,
) -> GateResult:
    """Check if a skill is safe to install. Returns allow/warn/deny decision.

    Args:
        url: URL of the skill to check.
        threshold: Risk level that triggers deny (low/moderate/high/critical).
        api_key: Optional API key for allowlist/denylist/policy features.
        policy: Optional policy ID to evaluate against.
        base_url: API base URL (default: https://skillaudit.vercel.app).
        timeout: Request timeout in seconds.

    Returns:
        GateResult with .allow, .decision, .risk, .score, .verdict
    """
    params = {"url": url, "threshold": threshold}
    if api_key:
        params["key"] = api_key
    if policy:
        params["policy"] = policy
    qs = urllib.parse.urlencode(params)
    data = _get(f"{base_url}/gate?{qs}", timeout=timeout)
    return GateResult.from_dict(data)


def scan(
    url: str,
    base_url: str = BASE_URL,
    timeout: int = 30,
) -> ScanResult:
    """Full security scan of a skill URL.

    Args:
        url: URL of the skill to scan.
        base_url: API base URL.
        timeout: Request timeout in seconds.

    Returns:
        ScanResult with .risk_level, .findings, .verdict, etc.
    """
    qs = urllib.parse.urlencode({"url": url})
    data = _get(f"{base_url}/scan/quick?{qs}", timeout=timeout)
    return ScanResult.from_dict(data)


def scan_content(
    content: str,
    base_url: str = BASE_URL,
    timeout: int = 30,
) -> ScanResult:
    """Scan raw text content for security threats.

    Args:
        content: Raw skill content to scan.
        base_url: API base URL.
        timeout: Request timeout in seconds.

    Returns:
        ScanResult with .risk_level, .findings, .verdict, etc.
    """
    data = _post(f"{base_url}/scan/content", {"content": content}, timeout=timeout)
    return ScanResult.from_dict(data)


def bulk_gate(
    urls: list[str],
    threshold: str = "moderate",
    api_key: Optional[str] = None,
    base_url: str = BASE_URL,
    timeout: int = 60,
) -> BulkGateResult:
    """Check multiple skills at once. Deny if ANY fails.

    Args:
        urls: List of skill URLs to check (max 20).
        threshold: Risk level that triggers deny.
        api_key: Optional API key.
        base_url: API base URL.
        timeout: Request timeout in seconds.

    Returns:
        BulkGateResult with .allow, .blocked, .results
    """
    ep = f"{base_url}/gate/bulk"
    if api_key:
        ep += f"?key={urllib.parse.quote(api_key)}"
    data = _post(ep, {"urls": urls, "threshold": threshold}, timeout=timeout)
    return BulkGateResult.from_dict(data)


# ── Class-based client ─────────────────────────────────────────────────────

class SkillAudit:
    """Stateful client with API key and configuration.

    Usage:
        client = SkillAudit(api_key="sk-...")
        result = client.gate("https://example.com/SKILL.md", policy="my-policy")
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = BASE_URL,
        threshold: str = "moderate",
        timeout: int = 30,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.threshold = threshold
        self.timeout = timeout

    def gate(self, url: str, threshold: Optional[str] = None, policy: Optional[str] = None) -> GateResult:
        """Gate check with instance defaults."""
        return gate(
            url, threshold=threshold or self.threshold,
            api_key=self.api_key, policy=policy,
            base_url=self.base_url, timeout=self.timeout,
        )

    def scan(self, url: str) -> ScanResult:
        """Full scan with instance defaults."""
        return scan(url, base_url=self.base_url, timeout=self.timeout)

    def scan_content(self, content: str) -> ScanResult:
        """Scan raw content."""
        return scan_content(content, base_url=self.base_url, timeout=self.timeout)

    def bulk_gate(self, urls: list[str], threshold: Optional[str] = None) -> BulkGateResult:
        """Bulk gate check."""
        return bulk_gate(
            urls, threshold=threshold or self.threshold,
            api_key=self.api_key, base_url=self.base_url, timeout=self.timeout,
        )

    def is_safe(self, url: str) -> bool:
        """Simple boolean: is this skill safe to install?"""
        return self.gate(url).allow
