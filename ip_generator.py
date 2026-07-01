"""
ip_generator.py
================
Generates realistic RFC1918 (and occasional RFC6598 / public CIDR for
internet-facing contexts) network addressing for the synthetic corpus.

Rather than hardcoding a single subnet such as 10.0.0.0/24 everywhere
(which would make the dataset trivially fingerprint-able and unrealistic),
this module models a plausible enterprise IP addressing plan: a /8
private supernet subdivided by site, environment, and zone, with
distinct ranges for management, DMZ, PCI, healthcare, OT, and VPN pools.
"""

from __future__ import annotations

import random
from dataclasses import dataclass


# Each entry: (zone_label, octet1_choices, octet2_range, mask)
# Octet1 choices are drawn from the three RFC1918 blocks to keep things
# realistic: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
_ZONE_ADDRESS_PLANS = {
    "corporate LAN": (10, (1, 50), 24),
    "headquarters campus network": (10, (1, 10), 23),
    "branch office network": (10, (60, 120), 24),
    "remote office network": (10, (121, 160), 25),
    "DMZ": (172, (16, 19), 27),
    "external-facing DMZ": (172, (16, 17), 28),
    "internal DMZ": (172, (18, 19), 28),
    "perimeter network": (172, (20, 21), 27),
    "management network": (10, (250, 254), 28),
    "out-of-band management network": (10, (255, 255), 29),
    "guest wireless network": (192, (168, 168), 24),
    "BYOD network": (192, (169, 169), 24),
    "VoIP voice VLAN": (10, (200, 210), 24),
    "data center core network": (10, (30, 40), 23),
    "server farm network": (10, (41, 49), 24),
    "storage network": (10, (180, 190), 25),
    "backup network": (10, (191, 195), 25),
    "disaster recovery site network": (10, (220, 230), 23),
    "PCI cardholder data environment": (172, (24, 25), 27),
    "PCI scoped network": (172, (26, 27), 27),
    "healthcare clinical network": (172, (28, 29), 24),
    "OT network": (172, (30, 31), 25),
    "ICS network": (10, (240, 241), 27),
    "SCADA network": (10, (242, 243), 27),
    "industrial DMZ": (172, (22, 23), 28),
    "research network": (10, (170, 175), 24),
    "development environment network": (10, (100, 105), 24),
    "staging environment network": (10, (106, 110), 24),
    "QA environment network": (10, (111, 115), 24),
    "production environment network": (10, (50, 59), 23),
    "sandbox environment network": (10, (116, 119), 26),
    "partner extranet": (192, (170, 175), 24),
    "vendor extranet": (192, (176, 180), 24),
    "third-party connectivity zone": (192, (181, 185), 25),
    "cloud landing zone": (10, (130, 140), 22),
    "multi-cloud transit zone": (10, (141, 145), 24),
    "VPN client address pool": (10, (210, 215), 22),
    "site-to-site VPN tunnel network": (10, (216, 219), 30),
    "jump host network": (10, (246, 247), 29),
    "bastion network": (10, (248, 249), 29),
    "privileged access zone": (10, (244, 245), 28),
    "identity services network": (10, (42, 43), 25),
    "active directory tier 0 network": (10, (44, 44), 28),
    "active directory tier 1 network": (10, (45, 45), 27),
    "active directory tier 2 network": (10, (46, 47), 26),
    "public internet": (203, (0, 0), 32),
    "untrusted external network": (198, (51, 51), 24),
    "regulatory reporting network": (172, (32, 33), 26),
    "call center network": (10, (150, 155), 24),
    "retail store network": (10, (160, 169), 25),
    "point-of-sale network": (172, (34, 35), 27),
    "warehouse operations network": (10, (176, 179), 24),
    "manufacturing plant floor network": (172, (36, 37), 25),
    "laboratory network": (10, (196, 199), 25),
    "campus residence network": (192, (186, 189), 24),
    "executive isolated network": (10, (252, 253), 29),
}

_DEFAULT_PLAN = (10, (1, 254), 24)


@dataclass(frozen=True)
class NetworkAddress:
    cidr: str
    host_ip: str


def _random_octet(rng: random.Random, bounds: tuple) -> int:
    lo, hi = bounds
    return rng.randint(lo, hi)


def generate_network_for_zone(zone: str, rng: random.Random) -> NetworkAddress:
    """
    Generates a plausible CIDR subnet and an example host IP for a given
    named zone, using a deterministic-per-zone addressing plan so the
    same zone name tends to resolve to addresses from the same realistic
    supernet across the dataset (mirroring how real enterprises assign
    address space per function).
    """
    octet1, octet2_bounds, mask = _ZONE_ADDRESS_PLANS.get(zone, _DEFAULT_PLAN)
    octet2 = _random_octet(rng, octet2_bounds)
    octet3 = rng.randint(0, 255)

    if mask >= 24:
        network_octet4 = 0
        cidr = f"{octet1}.{octet2}.{octet3}.{network_octet4}/{mask}"
        host_last = rng.randint(1, 254)
    else:
        # /22 or /23: align octet3 to a valid block boundary for the mask
        block_size = 2 ** (24 - (mask if mask <= 24 else 24))
        octet3 = (octet3 // max(block_size, 1)) * max(block_size, 1)
        cidr = f"{octet1}.{octet2}.{octet3}.0/{mask}"
        host_last = rng.randint(1, 254)

    host_ip = f"{octet1}.{octet2}.{octet3}.{host_last}"
    return NetworkAddress(cidr=cidr, host_ip=host_ip)


def generate_host_name(zone: str, rng: random.Random, role_hint: str = "") -> str:
    """
    Generates a realistic enterprise hostname, e.g. 'dc-east-app03',
    optionally biased by a role hint (e.g. 'db', 'web', 'app').
    """
    site_codes = ["dc-east", "dc-west", "dc-central", "az-eus2", "az-wus2",
                  "aws-use1", "aws-usw2", "gcp-us-c1", "brn1", "lon2", "sin1"]
    role_codes = {
        "db": ["db", "sql", "ora", "pg"],
        "web": ["web", "www", "nginx", "iis"],
        "app": ["app", "svc", "api"],
        "mgmt": ["mgmt", "jump", "bastion"],
        "": ["host", "srv", "node"],
    }
    site = rng.choice(site_codes)
    role_list = role_codes.get(role_hint, role_codes[""])
    role = rng.choice(role_list)
    number = rng.randint(1, 99)
    return f"{site}-{role}{number:02d}"
