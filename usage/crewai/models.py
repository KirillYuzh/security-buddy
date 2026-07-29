#!/usr/bin/env python3
"""
Pydantic models for Security Buddy structured output.
"""

from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Finding(BaseModel):
    id: str = Field(description="Unique finding ID, e.g. SB-2024-001")
    severity: Severity
    cwe: Optional[str] = Field(None, description="CWE identifier like CWE-79")
    cve: Optional[str] = Field(None, description="CVE identifier if applicable")
    location: str = Field(description="File:line or component name")
    description: str
    technical_impact: str
    business_impact: str = ""
    remediation: str
    mitre_attack: Optional[str] = None
    category: str = Field(description="sast | sca | config | architecture | ai_ml | crypto")


class ExploitChain(BaseModel):
    chain_id: str = Field(description="e.g. CHAIN-001")
    severity: Severity
    attack_path: list[str] = Field(description="Step-by-step attack steps linking findings")
    technical_impact: str
    business_impact: str = ""
    mitre_sequence: Optional[str] = None
    chain_breaking_fix: str


class FixResult(BaseModel):
    finding_id: str
    applied: bool
    file_changed: Optional[str] = None
    lines_changed: Optional[str] = None
    diff: Optional[str] = None
    verification_status: str = "pending"
    error: Optional[str] = None


class AuditReport(BaseModel):
    summary: str
    overall_score: float = Field(ge=0.0, le=10.0)
    findings: list[Finding]
    exploit_chains: list[ExploitChain] = []
    risk_score: float = Field(ge=0.0, le=10.0)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    strategic_recommendations: list[str] = []


# Artifact models
class SBOMComponent(BaseModel):
    name: str
    version: str
    license: Optional[str] = None
    purl: Optional[str] = None  # Package URL (CycloneDX format)


class SBOM(BaseModel):
    format: str = "CycloneDX"
    spec_version: str = "1.5"
    components: list[SBOMComponent] = []
    vulnerabilities: list[str] = []  # CVE IDs


class SecurityTodo(BaseModel):
    file_path: str
    line_number: int
    comment: str
    finding_id: Optional[str] = None
    severity: Optional[str] = None
    cwe: Optional[str] = None