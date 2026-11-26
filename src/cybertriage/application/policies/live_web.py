"""Resolve public identifiers to fixed vendor routes; never submit incident text."""

import re
from urllib.parse import urlsplit, urlunsplit

from cybertriage.domain.live_web import LiveWebSettings, WebPolicyError, WebTarget
from cybertriage.domain.retrieval import RetrievalContext
from cybertriage.domain.triage import RetrievedReference

MICROSOFT_CURRENT = "/en-us/windows/security/threat-protection/auditing/"
MICROSOFT_PREVIOUS = "/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/"
MICROSOFT_CATALOGUE = "/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration"


def approved_url(url: str) -> str:
    if not isinstance(url, str) or len(url) > 2048 or not url.isascii() or any(char.isspace() for char in url) or any(char in url for char in ("%", "\\")):
        raise WebPolicyError("Invalid public documentation URL.")
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise WebPolicyError("Malformed public documentation URL.") from None
    if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise WebPolicyError("Only fixed HTTPS documentation routes are permitted.")
    try:
        if port not in {None, 443}:
            raise WebPolicyError("Nonstandard documentation ports are not permitted.")
    except ValueError:
        raise WebPolicyError("Invalid documentation port.") from None
    path = parsed.path
    if host == "attack.mitre.org":
        if not re.fullmatch(r"/techniques/T\d{4}/(?:\d{3}/)?", path):
            raise WebPolicyError("Unsupported ATT&CK route.")
    elif host == "learn.microsoft.com":
        allowed = path == MICROSOFT_CATALOGUE
        for prefix in (MICROSOFT_CURRENT, MICROSOFT_PREVIOUS):
            if path.startswith(prefix):
                slug = path[len(prefix):]
                allowed = allowed or bool(re.fullmatch(r"event-\d{1,5}|audit-security-group-management", slug))
        if not allowed:
            raise WebPolicyError("Unsupported Microsoft documentation route.")
    else:
        raise WebPolicyError("Documentation host is not approved.")
    return urlunsplit(("https", host, path, "", ""))


def validate_target_url(target: WebTarget, url: str) -> str:
    canonical = approved_url(url)
    expected = "learn.microsoft.com" if target.source == "microsoft" else "attack.mitre.org"
    if urlsplit(canonical).hostname != expected:
        raise WebPolicyError("A documentation response changed source vendor.")
    return canonical


def plan_web_targets(query: str, context: RetrievalContext, local: tuple[RetrievedReference, ...],
                     settings: LiveWebSettings) -> tuple[WebTarget, ...]:
    if not settings.enabled:
        return ()
    targets = []
    event = context.event
    if ("microsoft" in settings.sources and event is not None and event.provider == "Microsoft-Windows-Security-Auditing"
            and event.channel == "Security"):
        suffix = f"event-{event.event_id}"
        targets.append(WebTarget("microsoft", str(event.event_id), (
            f"https://learn.microsoft.com{MICROSOFT_PREVIOUS}{suffix}",
            f"https://learn.microsoft.com{MICROSOFT_CURRENT}{suffix}",
            f"https://learn.microsoft.com{MICROSOFT_CATALOGUE}",
        )))
    if "mitre" in settings.sources:
        identifiers = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", query.upper())
        for reference in local:
            identifiers.extend(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", reference.title.upper()))
        for identifier in dict.fromkeys(identifiers):
            route = identifier.replace(".", "/")
            targets.append(WebTarget("mitre", identifier, (f"https://attack.mitre.org/techniques/{route}/",)))
    return tuple(targets[:settings.max_targets])
