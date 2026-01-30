from ctypes import Array
from logging import CRITICAL
import uuid
from annotated_types import LowerCase
from sqlalchemy import ARRAY, Boolean, Column, Integer, Nullable, String, DateTime, ForeignKey, Text, UniqueConstraint, null, text
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
from enum import Enum
from sqlalchemy import Enum as SQLEnum

from sqlalchemy.orm import relationship

from app.database.session import Base


class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Using "username" as email/login in your examples
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

    # Company / tenant stored server-side; included in JWT on login
    tenant = Column(String, nullable=False, default="default")

    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)



class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_name = Column(String, unique=True, nullable=False)
    scan_type = Column(String, nullable=False)
    status = Column(String, nullable=False, default="Running")
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String, nullable=True)  # Optional - table may not have this column yet


class ScheduledScan(Base):
    """
    Scheduled scans (trigger scan at a specific time).
    The scheduler worker will pick due rows and start actual scans.
    """

    __tablename__ = "scheduled_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    scan_name = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)  # "dd" | "subdomain" | "api" (etc.)
    payload_json = Column(Text, nullable=False)  # JSON string

    scheduled_for = Column(DateTime, nullable=False)
    status = Column(String, nullable=False, default="PENDING")  # PENDING | TRIGGERING | TRIGGERED | CANCELLED | FAILED

    triggered_scan_id = Column(UUID(as_uuid=True), nullable=True)
    triggered_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String, nullable=True)

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(UUID(as_uuid=True),primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    domain = Column(String, nullable=False)
    subdomain = Column(String, nullable=False)


class ApiScanReport(Base):
    __tablename__ = "api_scan_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True)

    # Store in MinIO (DD-style)
    asset_url = Column(String, nullable=True)
    minio_bucket = Column(String, nullable=True)
    minio_object_name = Column(String, nullable=True)

    # Optional DB copy of report (fallback)
    report_json = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Report(Base):
    """
    Generated PDF reports (ASM first; later Web/API).
    Stored in MinIO and referenced here for history + downloads.
    """

    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    report_name = Column(String, nullable=False)
    report_type = Column(String, nullable=False)  # "ASM" | "WEB" | "API"
    description = Column(Text, nullable=True)

    # Scope (ASM uses domain_id; future: subdomain_id/url/etc.)
    domain_id = Column(UUID(as_uuid=True), ForeignKey("domains.id", ondelete="SET NULL"), nullable=True)

    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    minio_bucket = Column(String, nullable=True)
    minio_object_name = Column(String, nullable=True)


class Domain(Base):
    __tablename__ = "domains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    domain_name = Column(String, nullable=False)
    # ASN (Optional): Some older DBs won't have this column yet; migration adds it.
    asn = Column(String, nullable=True)
    tags = Column(ARRAY(String), nullable=True)
    discovery_source = Column(String, default="manual")  # "manual" or "auto_discovered"
    is_reachable = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    is_archived = Column(Boolean, default= False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    created_by = Column(String)
    updated_by = Column(String)

    # OPTIONAL relationships (default behavior)
    subdomains = relationship(
        "Subdomain",
        back_populates="domain",
        cascade="all, delete-orphan",
    )

    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="domain",
        cascade="all, delete-orphan",
    )


# TODO: Manaully Added or autodiscovered
class Subdomain(Base):
    __tablename__ = "subdomains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    domain_id = Column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,   # ❗ Subdomain MUST belong to a Domain
    )

    subdomain_name = Column(String, nullable=False)
    tags = Column(ARRAY(String), nullable=True)
    is_reachable = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    is_archived = Column(Boolean, default= False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    created_by = Column(String)
    updated_by = Column(String)

    __table_args__ = (
        UniqueConstraint("domain_id", "subdomain_name"),
    )

    # Relationships
    domain = relationship(
        "Domain",
        back_populates="subdomains",
    )

    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="subdomain",
        cascade="all, delete-orphan",
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # OPTIONAL relationships
    domain_id = Column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=True,
    )

    subdomain_id = Column(
        UUID(as_uuid=True),
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=True,
    )

    vuln_name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    cvss_score = Column(Integer, nullable=True)
    cvss_vectore = Column(Integer, nullable=True)
    recommendation = Column(Text, nullable=True)
    reference = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    tags = Column(ARRAY(String), nullable=True)

    created_at = Column(DateTime, nullable=True, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String, nullable=True)
    updated_by = Column(String, nullable=True)

    # Relationships
    domain = relationship(
        "Domain",
        back_populates="vulnerabilities",
    )

    subdomain = relationship(
        "Subdomain",
        back_populates="vulnerabilities",
    )

class IPAddress(Base):
    __tablename__ = "ipaddress"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    domain_id = Column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
    )

    ipaddress_name = Column(String, nullable=False)
    tags = Column(ARRAY(String), nullable=True)
    is_reachable = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    is_archived = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    created_by = Column(String)
    updated_by = Column(String)

    __table_args__ = (
        UniqueConstraint("domain_id", "ipaddress_name"),
    )

    # Relationships
    domain = relationship(
        "Domain",
        backref="ip_addresses",
    )


class URLAsset(Base):
    __tablename__ = "urls"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    domain_id = Column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
    )

    url_name = Column(String, nullable=False)
    tags = Column(ARRAY(String), nullable=True)
    is_reachable = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    is_archived = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    created_by = Column(String)
    updated_by = Column(String)

    __table_args__ = (
        UniqueConstraint("domain_id", "url_name"),
    )

    domain = relationship(
        "Domain",
        backref="urls",
    )


class AssetGroup(Base):
    __tablename__ = "asset_groups"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    name = Column(String, nullable=False)
    domain_id = Column(UUID(as_uuid=True), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    asset_type = Column(String, nullable=False)  # "SUBDOMAIN" | "IP"
    description = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String, nullable=True)
    updated_by = Column(String, nullable=True)

    domain = relationship(
        "Domain",
        backref="asset_groups",
    )

    items = relationship(
        "AssetGroupItem",
        back_populates="group",
        cascade="all, delete-orphan",
    )


class AssetGroupItem(Base):
    __tablename__ = "asset_group_items"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    asset_group_id = Column(UUID(as_uuid=True), ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=False)
    asset_type = Column(String, nullable=False)  # "SUBDOMAIN" | "IP"
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=True)
    ip_id = Column(UUID(as_uuid=True), ForeignKey("ipaddress.id", ondelete="CASCADE"), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    group = relationship(
        "AssetGroup",
        back_populates="items",
    )

    subdomain = relationship(
        "Subdomain",
        backref="asset_group_items",
    )

    ip_address = relationship(
        "IPAddress",
        backref="asset_group_items",
    )

    __table_args__ = (
        UniqueConstraint("asset_group_id", "subdomain_id"),
        UniqueConstraint("asset_group_id", "ip_id"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    finding_name = Column(String, nullable=False)
    description = Column(Text, nullable=True)

    severity = Column(
        SQLEnum(SeverityEnum, name="severity_enum"),
        nullable=False,
        default=SeverityEnum.MEDIUM
    )

    risk_score = Column(Integer, nullable=True)
    is_patched = Column(Boolean, default=False)
    is_manual = Column(Boolean, default=False)

    # 🔗 Foreign Keys
    vulnerability_id = Column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )

    domain_id = Column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="SET NULL"),
        nullable=True,
    )

    subdomain_id = Column(
        UUID(as_uuid=True),
        ForeignKey("subdomains.id", ondelete="SET NULL"),
        nullable=True,
    )

    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    created_by = Column(String)
    updated_by = Column(String)

    # 🔁 Relationships
    vulnerability = relationship(
        "Vulnerability",
        backref="findings",
    )

    domain = relationship(
        "Domain",
        backref="findings",
    )

    subdomain = relationship(
        "Subdomain",
        backref="findings",
    )

    scan = relationship(
        "Scan",
        backref="findings",
    )

    
