"""
entities.py
============
Loads and exposes all entity libraries from the datasets/ directory as a
single immutable EntityLibrary object. This module is the only place in
the codebase that touches the raw JSON files, so adding a new dataset
file only requires a change here.

Across all datasets combined, the library exposes 1000+ distinct
enterprise entities (departments, applications, services, vendors,
cloud resources, compliance frameworks, healthcare systems, industrial /
IoT assets, network zones, authentication methods, and action verbs),
satisfying the research-scale requirement of the TrustGuard corpus
generator.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from config import DATASETS_DIR


def _load(filename: str) -> Any:
    path = os.path.join(DATASETS_DIR, filename)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


@dataclass(frozen=True)
class EntityLibrary:
    """Immutable, pre-loaded view over every entity dataset."""

    departments: list = field(default_factory=list)
    applications: list = field(default_factory=list)
    services: list = field(default_factory=list)
    vendors: list = field(default_factory=list)
    cloud: dict = field(default_factory=dict)
    compliance: list = field(default_factory=list)
    healthcare: list = field(default_factory=list)
    iot: dict = field(default_factory=dict)
    zones: dict = field(default_factory=dict)
    protocols: list = field(default_factory=list)
    ports: dict = field(default_factory=dict)
    conditions: dict = field(default_factory=dict)
    exceptions: list = field(default_factory=list)
    authentication: list = field(default_factory=list)
    actions: dict = field(default_factory=dict)
    templates: dict = field(default_factory=dict)

    def total_entity_count(self) -> int:
        """Returns the total number of discrete entity strings loaded,
        used for reporting in generation_statistics.json."""
        count = 0
        count += len(self.departments)
        count += len(self.applications)
        count += len(self.services)
        count += len(self.vendors)
        count += sum(len(v) for v in self.cloud.values())
        count += len(self.compliance)
        count += len(self.healthcare)
        count += sum(len(v) for v in self.iot.values())
        count += sum(len(v) for v in self.zones.values())
        count += len(self.protocols)
        count += sum(len(v) for v in self.ports.values())
        count += sum(len(v) for v in self.conditions.values())
        count += len(self.exceptions)
        count += len(self.authentication)
        count += sum(len(v) for v in self.actions.values())
        return count

    def total_template_count(self) -> int:
        return sum(len(v) for v in self.templates.values())


def load_entity_library() -> EntityLibrary:
    """Factory function that reads every JSON dataset file once and
    returns a fully populated, immutable EntityLibrary instance."""
    return EntityLibrary(
        departments=_load("departments.json"),
        applications=_load("applications.json"),
        services=_load("services.json"),
        vendors=_load("vendors.json"),
        cloud=_load("cloud.json"),
        compliance=_load("compliance.json"),
        healthcare=_load("healthcare.json"),
        iot=_load("iot.json"),
        zones=_load("zones.json"),
        protocols=_load("protocols.json"),
        ports=_load("ports.json"),
        conditions=_load("conditions.json"),
        exceptions=_load("exceptions.json"),
        authentication=_load("authentication.json"),
        actions=_load("actions.json"),
        templates=_load("templates.json"),
    )
