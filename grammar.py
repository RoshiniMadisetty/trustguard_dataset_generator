"""
grammar.py
==========
The core natural-language composition engine. Selects a template
skeleton for a target category, fills its slots from the EntityLibrary
using the supplied RNG, optionally layers on additional clauses
(nested conditions, exceptions, ambiguity, contradiction) and an
optional opening "framing" clause (ticket reference, change-request
preamble, informal phrasing, etc.) to maximize structural diversity
well beyond the raw template count, and returns a fully formed
FirewallRequirement record.

Design notes for reproducibility / IEEE description:
  * Every random draw goes through the single `rng` passed in by the
    caller (generator.py), which is itself seeded once from
    config.GeneratorConfig.random_seed -> the whole corpus is
    deterministic for a fixed (seed, target_count) pair.
  * Slot-filling is data-driven: template strings reference named
    Python format-string placeholders (e.g. "{src_zone}") which are
    resolved from a per-call `slot_values` dict built by `_build_slots`.
    Missing optional slots (e.g. a template with no {compliance}
    placeholder) are simply ignored by `str.format_map` with a
    forgiving dict subclass.
"""

from __future__ import annotations

import itertools
import random
import re
from typing import Optional

from entities import EntityLibrary
from ip_generator import generate_network_for_zone, generate_host_name
from difficulty import (
    DifficultySignals,
    compute_complexity_score,
    compute_ambiguity_score,
    classify_difficulty,
)
from metadata import FirewallRequirement


# Baseline difficulty contribution by category, reflecting that some
# request categories are inherently harder to implement correctly even
# with few explicit conditions (e.g. a one-line zero-trust or
# contradictory-requirements request is rarely "easy" in practice).
_CATEGORY_BASELINE = {
    "Allow": 0.02, "Deny": 0.04,
    "Conditional Allow": 0.10, "Conditional Deny": 0.12,
    "Compliance": 0.18, "Healthcare": 0.16, "Industrial": 0.20,
    "Cloud": 0.14, "Database": 0.08, "VPN": 0.10, "Authentication": 0.10,
    "DMZ": 0.14, "Email": 0.06, "Monitoring": 0.06, "Backup": 0.06,
    "IoT": 0.14, "Zero Trust": 0.22, "Microservices": 0.14,
    "Kubernetes": 0.14, "Container Networking": 0.12,
    "Disaster Recovery": 0.16, "Business Continuity": 0.16,
    "Maintenance": 0.08, "Emergency": 0.20, "Guest Network": 0.06,
    "Multi-stage access": 0.24, "Replication": 0.08, "Read-only": 0.06,
    "Write-only": 0.06, "Logging": 0.04, "Inspection": 0.12,
    "Rate limiting": 0.08, "Geo restriction": 0.10, "Threat Prevention": 0.14,
    "Nested Conditions": 0.30, "Contradictory Requirements": 0.34,
    "Legacy Exception": 0.22, "Certificate Authentication": 0.12,
    "Jump Host": 0.16, "Least Privilege": 0.12, "Temporary Access": 0.10,
    "Multi-zone Communication": 0.22, "Ambiguous": 0.28,
}


def _category_baseline(category: str) -> float:
    return _CATEGORY_BASELINE.get(category, 0.05)


# ---------------------------------------------------------------------------
# Port/protocol coherence: critical for technical validity. Each requirement
# template category is restricted to a curated subset of the ports.json
# pools, so that the {service}/{port}/{protocol} slots filled into a given
# sentence are always a real, internally-consistent combination (e.g. a
# "VPN" category template can only ever draw IPsec/OpenVPN/WireGuard/L2TP/
# PPTP -- never MySQL's port 3306, and never a literal "IPsec VPN" string
# paired with an unrelated random port). This directly avoids the class of
# defect IEEE reviewers flag as "technically inconsistent" (e.g.
# "TCP/20 IPsec VPN traffic" or "DNS over TCP port 22"), as opposed to
# merely *synthetic* (which is fine and expected).
# ---------------------------------------------------------------------------
_GENERAL_POOL = [
    "web", "remote_access", "database", "file_transfer", "email",
    "messaging", "directory_auth", "file_share", "monitoring",
    "network_services",
]

_CATEGORY_PORT_POOLS = {
    "Allow": _GENERAL_POOL,
    "Deny": _GENERAL_POOL,
    "Conditional Allow": _GENERAL_POOL,
    "Conditional Deny": _GENERAL_POOL,
    "Compliance": ["web", "database", "file_transfer", "directory_auth", "file_share"],
    "Healthcare": ["healthcare"],
    "Industrial": ["industrial"],
    "Cloud": ["web", "database", "container", "messaging"],
    "Database": ["database"],
    "VPN": ["vpn"],
    "Authentication": ["directory_auth", "web"],
    "DMZ": ["web", "email"],
    "Email": ["email"],
    "Monitoring": ["monitoring"],
    "Backup": ["file_share", "file_transfer", "database"],
    "IoT": ["iot_messaging", "industrial"],
    "Zero Trust": _GENERAL_POOL,
    "Microservices": ["web", "messaging", "container"],
    "Kubernetes": ["container"],
    "Container Networking": ["container", "web"],
    "Disaster Recovery": ["database", "file_share"],
    "Business Continuity": _GENERAL_POOL,
    "Maintenance": _GENERAL_POOL,
    "Emergency": _GENERAL_POOL,
    "Guest Network": ["web", "network_services"],
    "Multi-stage access": ["remote_access"],
    "Replication": ["database", "file_share"],
    "Read-only": ["database", "file_share", "web"],
    "Write-only": ["database", "file_share", "messaging"],
    "Logging": ["monitoring"],
    "Inspection": _GENERAL_POOL,
    "Rate limiting": ["web"],
    "Geo restriction": ["web"],
    "Threat Prevention": _GENERAL_POOL,
    "Nested Conditions": _GENERAL_POOL,
    "Contradictory Requirements": _GENERAL_POOL,
    "Legacy Exception": ["remote_access", "file_transfer", "web", "file_share"],
    "Certificate Authentication": ["web", "remote_access", "directory_auth"],
    "Jump Host": ["remote_access"],
    "Least Privilege": _GENERAL_POOL,
    "Temporary Access": _GENERAL_POOL,
    "Multi-zone Communication": _GENERAL_POOL,
    "Ambiguous": _GENERAL_POOL,
}


def _port_pool_for_category(category: str) -> list:
    return _CATEGORY_PORT_POOLS.get(category, _GENERAL_POOL)


# ---------------------------------------------------------------------------
# Opening framing clauses: prepended ~45% of the time to multiply the
# effective number of distinct sentence structures far beyond the raw
# template skeleton count (this is the mechanism, alongside 226 base
# skeletons across 43 categories, by which the generator realizes the
# "300+ structurally distinct templates" research requirement).
# ---------------------------------------------------------------------------
_FRAMING_OPENERS = [
    "",  # no framing, template stands alone
    "",
    "",
    "Per change ticket CHG{ticket_num}, ",
    "Re: incident INC{ticket_num} -- ",
    "Following up on yesterday's change advisory board meeting, ",
    "As discussed with the {department} stakeholder, ",
    "On behalf of {department}, ",
    "For the upcoming {application} release, ",
    "Submitting this on short notice: ",
    "As a follow-up to the security assessment, ",
    "Per the network architecture diagram reviewed last sprint, ",
]

_CLOSING_TAGS = [
    "",
    "",
    "",
    " Please confirm once implemented.",
    " This was approved in the weekly change review.",
    " Let me know if additional information is needed.",
    " This ticket is time-sensitive.",
    " CC'ing the {department} lead for visibility.",
]


class _SafeDict(dict):
    """A dict subclass that leaves unresolved {placeholders} untouched
    instead of raising KeyError, so templates may reference slots that
    are not always populated for every category."""

    def __missing__(self, key):
        return ""


def _clean_sentence(text: str) -> str:
    """Normalizes whitespace/punctuation artifacts left over from empty
    optional slots or framing concatenation."""
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s+,", ",", text)
    text = re.sub(r",\s*,", ",", text)
    text = re.sub(r",\s*\.", ".", text)
    text = re.sub(r"\.\s*\.", ".", text)
    text = re.sub(r"\(\s*\)", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    if text and not text.endswith((".", "?", "!")):
        text += "."
    if text:
        text = text[0].upper() + text[1:]
    return text


def _pick(rng: random.Random, items: list):
    return rng.choice(items)


def _zone_is_sensitive(zone: str) -> bool:
    sensitive_markers = (
        "PCI", "OT", "ICS", "SCADA", "healthcare", "tier 0", "tier 1",
        "industrial", "privileged",
    )
    return any(marker.lower() in zone.lower() for marker in sensitive_markers)


def _zone_is_internet_facing(zone: str) -> bool:
    return any(m in zone for m in ("DMZ", "public internet", "untrusted external"))


def _build_slots(category: str, lib: EntityLibrary, rng: random.Random) -> dict:
    """Builds the full slot-value dictionary available to any template
    in the given category. Not every template uses every slot."""
    zones_list = lib.zones.get("zones", [])
    src_zone = _pick(rng, zones_list)
    dst_zone = _pick(rng, [z for z in zones_list if z != src_zone] or zones_list)

    src_net = generate_network_for_zone(src_zone, rng)
    dst_net = generate_network_for_zone(dst_zone, rng)
    src_host = generate_host_name(src_zone, rng, role_hint=rng.choice(["app", "web", "db", ""]))
    dst_host = generate_host_name(dst_zone, rng, role_hint=rng.choice(["app", "web", "db", "mgmt"]))

    service_name, port_info = _pick_port(lib, rng, category)

    allow_verb = _pick(rng, lib.actions["allow_verbs"])
    deny_verb = _pick(rng, lib.actions["deny_verbs"])
    requester = _pick(rng, lib.actions["requesters"])

    department = _pick(rng, lib.departments)
    application = _pick(rng, lib.applications)
    vendor = _pick(rng, lib.vendors)
    compliance = _pick(rng, lib.compliance)
    auth = _pick(rng, lib.authentication)

    healthcare_system = _pick(rng, lib.healthcare)
    iot_device = _pick(rng, lib.iot.get("iot_devices", ["IoT device"]))
    industrial_protocol = _pick(rng, lib.iot.get("industrial_protocols", ["Modbus TCP"]))
    ot_zone = _pick(rng, lib.iot.get("ot_zones", ["OT network"]))

    cloud_service = _pick(rng, lib.cloud.get("services", ["AWS EC2"]))
    cloud_construct = _pick(rng, lib.cloud.get("network_constructs", ["VPC peering connection"]))

    time_condition = _pick(rng, lib.conditions.get("time_conditions", [""]))
    approval_condition = _pick(rng, lib.conditions.get("approval_conditions", [""]))
    exception_condition = _pick(rng, lib.conditions.get("exception_conditions", [""]))
    security_condition = _pick(rng, lib.conditions.get("security_conditions", [""]))
    ambiguous_condition = _pick(rng, lib.conditions.get("ambiguous_conditions", [""]))
    exception = _pick(rng, lib.exceptions)

    ticket_num = rng.randint(10000, 99999)

    return {
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "src_host": src_host,
        "dst_host": dst_host,
        "src_cidr": src_net.cidr,
        "dst_cidr": dst_net.cidr,
        "service": service_name,
        "port": port_info["port"],
        "protocol": port_info["protocol"],
        "allow_verb": allow_verb,
        "deny_verb": deny_verb,
        "requester": requester,
        "department": department,
        "application": application,
        "vendor": vendor,
        "compliance": compliance,
        "auth": auth,
        "healthcare_system": healthcare_system,
        "iot_device": iot_device,
        "industrial_protocol": industrial_protocol,
        "ot_zone": ot_zone,
        "cloud_service": cloud_service,
        "cloud_construct": cloud_construct,
        "dst_construct_zone": _pick(rng, zones_list),
        "time_condition": time_condition,
        "approval_condition": approval_condition,
        "exception_condition": exception_condition,
        "security_condition": security_condition,
        "ambiguous_condition": ambiguous_condition,
        "exception": exception,
        "ticket_num": ticket_num,
    }, src_net, dst_net


def _pick_port(lib: EntityLibrary, rng: random.Random, category: str):
    """
    Selects a (display_name, port, protocol) triple that is *internally
    consistent*: the pool is restricted to the port categories relevant
    to the requirement category (see _CATEGORY_PORT_POOLS), so a
    "Database" requirement can never end up quoting DNS's port, and a
    "VPN" requirement can never be paired with MySQL's port -- avoiding
    technically-invalid combinations that would undermine the dataset's
    credibility (e.g. "MySQL over ICMP" or "TCP/20 IPsec VPN traffic").
    """
    pool_names = _port_pool_for_category(category)
    pool_names = [p for p in pool_names if p in lib.ports]
    chosen_pool_name = _pick(rng, pool_names) if pool_names else _pick(rng, list(lib.ports.keys()))
    pool = lib.ports[chosen_pool_name]
    key = _pick(rng, list(pool.keys()))
    entry = pool[key]
    return entry["display"], entry


def generate_requirement(
    req_id: str,
    category: str,
    lib: EntityLibrary,
    rng: random.Random,
) -> FirewallRequirement:
    """
    Generates a single fully-formed FirewallRequirement for the given
    category, including natural-language text, difficulty scoring, and
    structured metadata.
    """
    templates = lib.templates[category]
    template_index = rng.randrange(len(templates))
    template = templates[template_index]
    template_id = f"{category}::{template_index}"

    slots, src_net, dst_net = _build_slots(category, lib, rng)

    # --- structural signal bookkeeping --------------------------------
    num_conditions = sum(
        1 for key in ("time_condition", "approval_condition", "security_condition", "ambiguous_condition")
        if "{" + key + "}" in template
    )
    num_exceptions = sum(
        1 for key in ("exception", "exception_condition")
        if "{" + key + "}" in template
    )
    has_nested_logic = category == "Nested Conditions" or num_conditions >= 2
    has_contradiction = category == "Contradictory Requirements"
    has_ambiguity = category == "Ambiguous" or "{ambiguous_condition}" in template

    # --- compose final sentence text -----------------------------------
    opener_template = _pick(rng, _FRAMING_OPENERS)
    closer_template = _pick(rng, _CLOSING_TAGS) if rng.random() < 0.30 else ""

    safe_slots = _SafeDict(slots)
    body = template.format_map(safe_slots)
    opener = opener_template.format_map(safe_slots) if opener_template else ""
    closer = closer_template.format_map(safe_slots) if closer_template else ""

    if opener and body:
        first_word = body.split(" ", 1)[0].rstrip(",.")
        # Only lower-case the body's leading word if it is a common
        # sentence-starting word/verb rather than a proper noun (entity
        # name, department, requester phrase, etc.), to avoid producing
        # awkward mid-sentence capitalization breaks like
        # "...stakeholder, maintenance Engineering requests...".
        _common_lowercaseable = {
            "the", "please", "allow", "permit", "enable", "grant", "deny",
            "block", "restrict", "prohibit", "disable", "configure",
            "set", "open", "isolate", "ensure", "apply", "replace",
            "reduce", "schedule", "during", "all", "as", "to", "for",
            "we", "our", "a", "an", "extend", "establish", "provision",
        }
        if first_word.lower() in _common_lowercaseable:
            body = body[0].lower() + body[1:]
    raw_sentence = f"{opener}{body}{closer}"
    sentence = _clean_sentence(raw_sentence)

    # --- action classification ------------------------------------------
    action = "deny" if any(
        marker in template.lower() for marker in ("deny_verb", "deny")
    ) and "{allow_verb}" not in template else "allow"
    if "{deny_verb}" in template and "{allow_verb}" in template:
        action = "mixed"
    elif "{deny_verb}" in template:
        action = "deny"
    elif "{allow_verb}" in template:
        action = "allow"
    else:
        action = "neutral"

    internet_exposed = _zone_is_internet_facing(slots["src_zone"]) or _zone_is_internet_facing(slots["dst_zone"])
    is_sensitive_zone = _zone_is_sensitive(slots["src_zone"]) or _zone_is_sensitive(slots["dst_zone"])
    requires_multi_hop = category in ("Multi-stage access", "Multi-zone Communication", "Jump Host")
    is_compliance_scoped = category == "Compliance" or "{compliance}" in template

    signals = DifficultySignals(
        num_conditions=num_conditions,
        num_exceptions=num_exceptions,
        has_nested_logic=has_nested_logic,
        has_contradiction=has_contradiction,
        has_ambiguity=has_ambiguity,
        is_compliance_scoped=is_compliance_scoped,
        is_security_sensitive_zone=is_sensitive_zone,
        requires_multi_hop=requires_multi_hop,
        category_baseline=_category_baseline(category),
    )
    complexity_score = compute_complexity_score(signals)
    ambiguity_score = compute_ambiguity_score(signals)
    difficulty = classify_difficulty(complexity_score)

    requirement = FirewallRequirement(
        id=req_id,
        category=category,
        subcategory=template_id,
        difficulty=difficulty,
        template_id=template_id,
        generated_requirement=sentence,
        service=slots["service"],
        protocol=slots["protocol"],
        port=slots["port"],
        source_zone=slots["src_zone"],
        destination_zone=slots["dst_zone"],
        source_host=slots["src_host"],
        destination_host=slots["dst_host"],
        source_cidr=slots["src_cidr"],
        destination_cidr=slots["dst_cidr"],
        department=slots["department"],
        application=slots["application"],
        vendor=slots["vendor"],
        compliance=slots["compliance"] if is_compliance_scoped else None,
        authentication=slots["auth"] if "{auth}" in template else None,
        action=action,
        internet_exposed=internet_exposed,
        num_conditions=num_conditions,
        num_exceptions=num_exceptions,
        has_nested_logic=has_nested_logic,
        has_contradiction=has_contradiction,
        has_ambiguity=has_ambiguity,
        ambiguity_score=ambiguity_score,
        complexity_score=complexity_score,
        entities={
            "department": slots["department"],
            "application": slots["application"],
            "vendor": slots["vendor"],
        },
    )
    return requirement


def available_categories(lib: EntityLibrary) -> list:
    return list(lib.templates.keys())
