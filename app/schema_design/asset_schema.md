# ASSETS
class Assets(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    is_reachable = Column(Boolean, default=False)
    is_autoadded = Column(Boolean, default=False)
    is_authenticated = Column(Boolean, default=False)
    is_archived = Column(Boolean, default=False)
    tags = Column(JSON, nullable=True)
    tenant_name = Column(String, nullable=False)
    has_website = Column(Boolean, default=False)
    asset_type = Column(
        SAEnum(AssetTypeEnum),
        nullable=False,
        default=AssetTypeEnum.SUBDOMAIN
    )
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String, nullable=True)
    updated_by = Column(String, nullable=True)
    # Domain mapping
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True)
    domain = relationship("Domains", back_populates="assets")
    # Findings linked to this asset
    findings = relationship(
        "Findings",
        back_populates="asset",
        cascade="all, delete-orphan"
    )


# IP ADDRESS
class IPAddress(Base):
    __tablename__ = "ip_addresses"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    host = Column(String, nullable=True)
    port = Column(String, nullable=True)
    ipblock = Column(String, nullable=True)
    is_reachable = Column(Boolean, default=False)
    is_autoadded = Column(Boolean, default=False)
    is_archived = Column(Boolean, default=False)
    is_authenticated = Column(Boolean, default=False)
    tags = Column(JSON, nullable=True)
    tenant_name = Column(String, nullable=False)
    has_website = Column(Boolean, default=False)
    risk_score = Column(Integer, nullable=True)
    org_name = Column(String, nullable=True)
    city = Column(String, nullable=True)
    state = Column(String, nullable=True)
    country = Column(String, nullable=True)
    region = Column(String, nullable=True)
    postal = Column(String, nullable=True)
    timezone = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String, nullable=True)
    updated_by = Column(String, nullable=True)
    # Domain mapping
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True)
    domain = relationship("Domains", back_populates="ip_addresses")
    # Findings linked to this IP
    findings = relationship(
        "Findings",
        back_populates="ipaddress",
        cascade="all, delete-orphan"
    )


# DOMAINS
class Domains(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    tenant_name = Column(String, nullable=False)
    is_reachable = Column(Boolean, default=False)
    is_active = Column(Boolean, default=False)
    is_archived = Column(Boolean, default=False)
    is_primary = Column(Boolean, default=False)
    tags = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String, nullable=True)
    updated_by = Column(String, nullable=True)
    # Relationships
    assets = relationship("Assets", back_populates="domain", cascade="all, delete-orphan")
    ip_addresses = relationship("IPAddress", back_populates="domain", cascade="all, delete-orphan")
    findings = relationship(
        "Findings",
        back_populates="domain",
        cascade="all, delete-orphan"
    )


# VULNERABILITIES
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    vid = Column(Integer, unique=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    cvss_score = Column(Integer, nullable=False)
    cvss_vector = Column(String, nullable=False)
    recommendation = Column(String, nullable=False)
    severity = Column(SAEnum(SeverityEnum), nullable=False)
    reference = Column(String, nullable=True)
    findings = relationship("Findings", back_populates="vulnerability")
    # Compliance standards (PCI, HIPAA, ISO etc.)
    complianceStandard = relationship("ComplianceStandard", back_populates="vulnerability")
    # Vulnerability standards (OWASP, CWE, CAPEC)
    vulnStandard = relationship("VulnerabilityStandard", back_populates="vulnerability")


# FINDINGS (Actual issue found)
class Findings(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    wf_name = Column(String, nullable=True)

    is_patched = Column(Boolean, default=False)
    is_manual = Column(Boolean, default=False)
    is_apt_finding = Column(Boolean, default=False)
    is_pt_finding = Column(Boolean, default=False)
    risk_score = Column(Integer) 
    severity = Column(SAEnum(SeverityEnum), nullable=True)
    # Foreign keys
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    ip_address_id = Column(Integer, ForeignKey("ip_addresses.id"), nullable=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    # Relationships
    asset = relationship("Assets", back_populates="findings")
    ipaddress = relationship("IPAddress", back_populates="findings")
    domain = relationship("Domains", back_populates="findings")
    vulnerability = relationship("Vulnerability", back_populates="findings")
    findingPoc = relationship(
        "FindingPOC",
        back_populates="finding",
        cascade="all, delete-orphan"
    )


# FINDING POC
class FindingPOC(Base):
    __tablename__ = "finding_poc"

    id = Column(Integer, primary_key=True, index=True)
    wfname = Column(String, nullable=True)
    poc = Column(String, nullable=True)
    payloads = Column(JSON, nullable=True)
    url = Column(String, nullable=True)
    endpoints = Column(JSON, nullable=True)
    port = Column(String, nullable=True)
    affected_components = Column(JSON, nullable=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    finding = relationship("Findings", back_populates="findingPoc")


# COMPLIANCE STANDARD
class ComplianceStandard(Base):
    __tablename__ = "compliance_standard"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    reference = Column(String, nullable=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    vulnerability = relationship("Vulnerability", back_populates="complianceStandard")


# VULNERABILITY STANDARD (OWASP, CWE, NIST)
class VulnerabilityStandard(Base):
    __tablename__ = "vulnerability_standards"

    id = Column(Integer, primary_key=True, index=True)
    standard_name = Column(String, nullable=False)
    details = Column(String, nullable=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    vulnerability = relationship("Vulnerability", back_populates="vulnStandard")


# SCAN DETAILS
class TriggerScan(Base):
    __tablename__ = "trigger_scan"

    id = Column(Integer, primary_key=True, index=True)
    scan_name = Column(String, nullable=False, unique=True)
    tenant_name = Column(String, nullable=False)
    operation = Column(String, nullable=True) # like submit
    triggerNow = Column(Boolean, default=False)
    scheduled = Column(Boolean, default=False) 
    scan_on = Column(String, nullable=True) # Example: "domain", "subdomain", "web", "port"
    scan_type = Column(SAEnum(ScanTypeEnum), nullable=False)
    scan_status = Column(SAEnum(ScanStatusEnum), nullable=False, default=ScanStatusEnum.REQUESTED)
    # "domain": { id:1, name:"gmail.com" }
    domain = Column(JSON, nullable=True)
    runbook_name = Column(String, nullable=True)
    runbook_version = Column(String, nullable=True)
    # "params": [ {...}, {...}, ... ]
    params = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String, nullable=True)
    updated_by = Column(String, nullable=True)

