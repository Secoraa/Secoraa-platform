from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List, Optional
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.auth import get_token_claims, get_tenant_usernames
from app.database.models import Domain, Report, Subdomain, Vulnerability
from app.database.session import get_db
from app.storage.minio_client import upload_bytes_to_minio, get_object_stream, object_exists, MINIO_BUCKET, is_minio_configured

# Local fallback directory for PDF storage when MinIO is unavailable
_LOCAL_REPORTS_DIR = Path("local_reports")
_LOCAL_REPORTS_DIR.mkdir(exist_ok=True)


router = APIRouter(prefix="/reports", tags=["Reports"], dependencies=[Depends(get_token_claims)])


def _severity_weight(sev: str) -> int:
    s = (sev or "").upper()
    return {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 55, "LOW": 25, "INFO": 10}.get(s, 10)


def _count_words(s: str) -> int:
    return len([w for w in (s or "").split() if w.strip()])


def _safe_pdf_text(value: Any) -> str:
    """
    fpdf core fonts (Helvetica, etc.) are not Unicode and only support latin-1.
    Normalize common unicode punctuation to ASCII and replace any remaining
    unsupported characters so PDF generation never crashes.
    """
    s = "" if value is None else str(value)
    # Common unicode punctuation → ASCII equivalents
    s = (
        s.replace("\u2013", "-")   # en dash
        .replace("\u2014", "-")   # em dash
        .replace("\u2212", "-")   # minus sign
        .replace("\u2018", "'")   # left single quote
        .replace("\u2019", "'")   # right single quote
        .replace("\u201C", '"')   # left double quote
        .replace("\u201D", '"')   # right double quote
        .replace("\u2026", "...") # ellipsis
        .replace("\u00A0", " ")   # non-breaking space
    )
    # Force to latin-1 safely (replace any remaining unsupported chars)
    return s.encode("latin-1", "replace").decode("latin-1")


def _infer_environment(asset: str) -> str:
    """
    Infer environment from existing ASM asset naming conventions only.
    This does NOT add new detections; it simply categorizes already-known assets.
    """
    s = (asset or "").lower()
    # Common environment markers
    prod_markers = ["prod", "production"]
    preprod_markers = ["preprod", "prerelease", "pre-release", "staging", "stage", "uat"]
    nonprod_markers = ["qa", "test", "dev", "demo", "sandbox", "stg"]

    def _has_any(markers: List[str]) -> bool:
        return any(m in s for m in markers)

    if _has_any(prod_markers) and not _has_any(nonprod_markers + preprod_markers):
        return "prod"
    if _has_any(preprod_markers):
        return "preprod"
    if _has_any(nonprod_markers):
        return "non-prod"
    return "unknown"


def _theme_for_vuln(name: str, description: str) -> str:
    n = (name or "").lower()
    d = (description or "").lower()
    text = f"{n} {d}"
    if "takeover" in text:
        return "subdomain_takeover"
    if "backup" in text or ".zip" in text or ".tar" in text or ".sql" in text or "dump" in text:
        return "backups_artifacts"
    if "metrics" in text or "debug" in text or "actuator" in text or "health" in text or "status" in text or "swagger" in text or "openapi" in text:
        return "diagnostics"
    if "admin" in text or "console" in text or "manage" in text or "jenkins" in text or "grafana" in text or "kibana" in text:
        return "admin_surface"
    if "misconfiguration" in text or "security header" in text or "header" in text:
        return "misconfiguration"
    if n.startswith("exposure:") or "exposed" in text:
        return "exposed_resource"
    return "other"


def _story_template(theme: str) -> Dict[str, str]:
    """
    Business-friendly narratives. No OWASP/CVE dump language.
    """
    # Titles are intentionally human and short.
    if theme == "admin_surface":
        return {
            "title": "Internet-exposed management surfaces expand takeover risk",
            "why": "Management and admin interfaces are high-impact entry points. If they are reachable from the internet, they become a direct path to service disruption or unauthorized changes.",
            "what_could_happen": "An attacker could attempt credential abuse, misconfiguration changes, or privileged actions that lead to outage, data access, or loss of control over the service.",
            "who": "CTO, Engineering Managers, Platform/SRE, Security Lead",
            "next": "Restrict access to admin paths (allowlist/VPN/SSO gateway), confirm ownership, and remove any unused admin endpoints from public routing.",
        }
    if theme == "diagnostics":
        return {
            "title": "Diagnostic endpoints expose internal signals to the internet",
            "why": "Diagnostics can reveal system details (routes, dependencies, versions, configuration hints). This reduces attacker effort and speeds up targeted abuse.",
            "what_could_happen": "Faster identification of weak points, targeted account attacks, or exploitation of misconfigurations leading to downtime or data exposure.",
            "who": "Engineering Managers, Backend Engineers, SRE, Security Lead",
            "next": "Move diagnostics behind internal access controls and keep only minimal public health checks if required.",
        }
    if theme == "backups_artifacts":
        return {
            "title": "Backup and artifact exposure increases data loss risk",
            "why": "Backups and artifacts often contain sensitive data or configuration and can bypass application controls entirely if downloaded directly.",
            "what_could_happen": "Data exposure, credential leakage, or the ability to reconstruct internal systems from leaked artifacts.",
            "who": "CTO, Security Lead, Data Owners, Platform/SRE",
            "next": "Remove public access to backup paths, relocate artifacts to protected storage, and rotate any credentials found in leaked files.",
        }
    if theme == "subdomain_takeover":
        return {
            "title": "Subdomain takeover signals indicate brand and phishing risk",
            "why": "Takeover conditions can allow external parties to host content under a trusted subdomain, impacting customer trust and enabling phishing.",
            "what_could_happen": "Malicious hosting under your domain, credential capture campaigns, or traffic interception.",
            "who": "CTO, Security Lead, Brand/Trust Owners, Platform/SRE",
            "next": "Confirm DNS targets are valid, remove orphaned records, and enforce domain ownership checks for third-party services.",
        }
    if theme == "misconfiguration":
        return {
            "title": "Security misconfigurations increase exploitability",
            "why": "Misconfigurations (especially in production) make it easier to exploit otherwise minor issues and can weaken protective controls.",
            "what_could_happen": "Broader attack paths, easier phishing/session abuse, and increased probability of data exposure during incidents.",
            "who": "Engineering Managers, Backend Engineers, Security Lead",
            "next": "Standardize baseline security settings (headers, TLS settings, safe defaults) and apply them consistently across environments.",
        }
    if theme == "exposed_resource":
        return {
            "title": "Exposed resources create direct access paths",
            "why": "Exposed resources often represent unintended public access to internal functionality or data.",
            "what_could_happen": "Unauthorized reads, leaks of internal content, or discovery of additional sensitive endpoints.",
            "who": "Engineering Managers, Backend Engineers, Security Lead",
            "next": "Validate whether exposure is intentional, restrict public routing, and add authentication/authorization where appropriate.",
        }
    return {
        "title": "Attack surface findings require ownership and routing hygiene",
        "why": "Unowned or unclear exposures slow incident response and increase the chance of overlooked entry points.",
        "what_could_happen": "Unexpected compromise paths through forgotten or misrouted assets.",
        "who": "Engineering Managers, Platform/SRE, Security Lead",
        "next": "Assign owners for exposed assets, remove unused routes, and ensure consistent access controls per environment.",
    }


def _api_theme_for_finding(issue: str, description: str = "") -> str:
    t = f"{issue or ''} {description or ''}".lower()
    if "missing authentication" in t or "unauthorized" in t or "broken auth" in t:
        return "api_missing_auth"
    if "bola" in t or "object level authorization" in t or "broken object" in t:
        return "api_access_control"
    if "injection" in t:
        return "api_injection"
    if "security headers" in t or "header" in t:
        return "api_security_headers"
    return "api_other"


def _build_exposure_stories_pdf(
    *,
    tenant: str,
    report_name: str,
    description: str,
    created_by: str,
    created_at: datetime,
    domain: Optional[str],
    assets_list: List[str],
    vuln_rows: List[Dict[str, Any]],
    cover_title: Optional[str] = None,
    executive_intro: Optional[str] = None,
) -> bytes:
    """
    Narrative-style report for leadership. Uses only existing ASM data already collected.
    """
    from fpdf import FPDF  # type: ignore

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    if hasattr(pdf, "alias_nb_pages"):
        pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=14)

    logo_path = Path(__file__).resolve().parent.parent / "swagger" / "nexveil-logo.png"

    gold = (224, 177, 43)
    dark = (17, 24, 39)
    page_bg = (18, 15, 24)
    card_bg = (26, 23, 33)
    text_light = (245, 243, 247)
    text_muted = (184, 182, 186)
    border_subtle = (40, 35, 50)

    def dark_page_bg():
        """Fill current page with dark background."""
        pdf.set_fill_color(*page_bg)
        pdf.rect(0, 0, 210, 297, style="F")

    def section_header(title: str):
        dark_page_bg()
        top_y = 10
        logo_w = 22
        if logo_path.exists():
            pdf.image(str(logo_path), x=10, y=top_y, w=logo_w)
            title_y = top_y + logo_w + 8
        else:
            pdf.set_xy(10, top_y + 2)
            pdf.set_font("Helvetica", "B", 16)
            pdf.set_text_color(*gold)
            pdf.cell(0, 8, _safe_pdf_text("NexVeil"), ln=1)
            title_y = top_y + 18

        pdf.set_xy(10, title_y)
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(*gold)
        pdf.cell(0, 10, _safe_pdf_text(title), ln=1)
        pdf.set_text_color(*text_muted)

        pdf.set_draw_color(*border_subtle)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(6)

    def footer(*, dark: bool = False):
        pdf.set_auto_page_break(auto=False)
        pdf.set_draw_color(*gold)
        pdf.set_line_width(0.4)
        pdf.line(10, 278, 200, 278)
        pdf.set_line_width(0.2)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*gold)
        brand = _safe_pdf_text("NEXVEIL SECURITY")
        brand_w = pdf.get_string_width(brand)
        pdf.set_xy((210 - brand_w) / 2, 279)
        pdf.cell(brand_w, 4, brand, 0, 1, "L")
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(*text_muted)
        year_str = str(datetime.utcnow().year)
        copy = _safe_pdf_text(f"{year_str} NexVeil Security. All Rights Reserved.")
        copy_w = pdf.get_string_width(copy)
        pdf.set_xy((210 - copy_w) / 2, 283)
        pdf.cell(copy_w, 4, copy, 0, 0, "L")
        pdf.set_auto_page_break(auto=True, margin=14)
        pdf.set_text_color(*text_muted)

    # -------------------------
    # Cover page (dark theme)
    # -------------------------
    pdf.set_auto_page_break(auto=False, margin=14)
    pdf.add_page()
    pdf.set_fill_color(*page_bg)
    pdf.rect(0, 0, 210, 297, style="F")

    if logo_path.exists():
        pdf.image(str(logo_path), x=12, y=18, w=55)

    pdf.set_xy(12, 92)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(*gold)
    pdf.multi_cell(0, 12, _safe_pdf_text(cover_title or "ATTACK SURFACE MANAGEMENT\n(ASM) EXECUTIVE SUMMARY"))

    pdf.set_draw_color(34, 197, 94)
    pdf.set_line_width(1.2)
    pdf.line(12, pdf.get_y() + 2, 110, pdf.get_y() + 2)
    pdf.set_line_width(0.2)

    cover_block_shift_mm = 30
    base_x = 12
    move_other_up_mm = 20
    y = (235 - cover_block_shift_mm) - move_other_up_mm

    pdf.set_xy(base_x, y)
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(*text_light)
    pdf.cell(0, 8, _safe_pdf_text("Prepared for"), 0, 1, "L")
    y += 12

    pdf.set_xy(base_x, y)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*gold)
    pdf.cell(0, 12, _safe_pdf_text(tenant), 0, 1, "L")
    y += 16

    if domain:
        pdf.set_xy(base_x, y)
        pdf.set_font("Helvetica", "", 18)
        pdf.set_text_color(*text_light)
        pdf.cell(0, 10, _safe_pdf_text(domain), 0, 1, "L")
        y += 18

    if description:
        pdf.set_xy(base_x, y)
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(*text_muted)
        desc = _safe_pdf_text(description)
        if len(desc) > 200:
            desc = desc[:197] + "..."
        pdf.multi_cell(186, 6, desc)
        y = pdf.get_y() + 6

    generated_y = (274 - cover_block_shift_mm) + 20
    if generated_y > 268:
        generated_y = 268
    pdf.set_xy(base_x, generated_y)
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(*text_light)
    pdf.cell(0, 8, _safe_pdf_text(f"Generated on {created_at.strftime('%m-%d-%Y')}"), 0, 0, "L")
    footer(dark=True)
    pdf.set_text_color(*text_muted)
    pdf.set_auto_page_break(auto=True, margin=14)

    # -------------------------
    # Executive summary (short)
    # -------------------------
    pdf.add_page()
    section_header("Executive Summary")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*text_light)

    total_assets = len([a for a in assets_list if a])
    total_vulns = len(vuln_rows)
    env_counts: Dict[str, int] = {}
    for a in assets_list:
        env = _infer_environment(a)
        env_counts[env] = env_counts.get(env, 0) + 1

    intro = executive_intro or (
        "This report translates attack surface findings into risk narratives that align with how an attacker would approach your internet-exposed systems."
    )
    pdf.multi_cell(
        0,
        6,
        _safe_pdf_text(
            f"{intro}\n\n"
            f"Assets in scope: {total_assets}\n"
            f"Findings in scope: {total_vulns}\n"
            f"Environment signals (from asset naming): prod={env_counts.get('prod',0)}, preprod={env_counts.get('preprod',0)}, non-prod={env_counts.get('non-prod',0)}"
        ),
    )
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*gold)
    pdf.cell(0, 8, _safe_pdf_text("How we prioritized"), ln=1)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*text_muted)
    pdf.multi_cell(
        0,
        6,
        _safe_pdf_text(
            "- Internet exposure and whether the entry point appears to be intended for public access\n"
            "- Asset sensitivity inferred from context (admin/diagnostics/backups are treated as high impact)\n"
            "- Environment signals (production is prioritized over non-production)\n"
        ),
    )
    footer()

    # -------------------------
    # Build stories
    # -------------------------
    # Group vulns into themes with examples
    grouped: Dict[str, Dict[str, Any]] = {}
    for v in vuln_rows:
        name = str(v.get("name") or v.get("vuln_name") or "")
        desc = str(v.get("description") or "")
        asset = str(v.get("asset") or v.get("subdomain") or v.get("domain") or "")
        theme = _theme_for_vuln(name, desc)
        g = grouped.setdefault(theme, {"count": 0, "examples": [], "env_boost": 0})
        g["count"] += 1
        if asset:
            if len(g["examples"]) < 5 and asset not in g["examples"]:
                g["examples"].append(asset)
            env = _infer_environment(asset)
            g["env_boost"] += {"prod": 30, "preprod": 15, "non-prod": 8, "unknown": 0}.get(env, 0)

    base_priority = {
        "admin_surface": 90,
        "backups_artifacts": 85,
        "subdomain_takeover": 80,
        "diagnostics": 70,
        "misconfiguration": 55,
        "exposed_resource": 50,
        "other": 35,
    }
    story_list = []
    for theme, g in grouped.items():
        score = base_priority.get(theme, 30) + int(g.get("env_boost") or 0)
        story_list.append((score, theme, g))
    story_list.sort(key=lambda x: x[0], reverse=True)

# Each story starts on its own page to avoid broken/fragmented headings (What/Why/Who/Next)
    # and to keep a consistent, readable layout.
    max_stories = 6
    for idx, (score, theme, g) in enumerate(story_list[:max_stories]):
        pdf.add_page()
        section_header("High-Risk Exposure Stories" if idx == 0 else "High-Risk Exposure Stories (continued)")
        tpl = _story_template(theme)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*gold)
        pdf.multi_cell(0, 7, _safe_pdf_text(tpl["title"]))
        pdf.set_text_color(*text_muted)

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(10)
        pdf.set_text_color(*gold)
        pdf.cell(0, 6, _safe_pdf_text("What was found"), ln=1)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(*text_light)
        examples = g.get("examples") or []
        ex_text = ", ".join(examples[:3]) + (f" (+{max(0, len(examples)-3)} more)" if len(examples) > 3 else "")
        pdf.set_x(10)
        pdf.multi_cell(0, 6, _safe_pdf_text(f"{g.get('count')} related finding(s). Example asset(s): {ex_text or '-'})"))

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(10)
        pdf.set_text_color(*gold)
        pdf.cell(0, 6, _safe_pdf_text("Why it matters"), ln=1)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(*text_light)
        pdf.set_x(10)
        pdf.multi_cell(0, 6, _safe_pdf_text(tpl["why"]))

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(10)
        pdf.set_text_color(*gold)
        pdf.cell(0, 6, _safe_pdf_text("What could happen if abused"), ln=1)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(*text_light)
        pdf.set_x(10)
        pdf.multi_cell(0, 6, _safe_pdf_text(tpl["what_could_happen"]))

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(10)
        pdf.set_text_color(*gold)
        pdf.cell(0, 6, _safe_pdf_text("Who should care"), ln=1)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(*text_light)
        pdf.set_x(10)
        pdf.multi_cell(0, 6, _safe_pdf_text(tpl["who"]))

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(10)
        pdf.set_text_color(*gold)
        pdf.cell(0, 6, _safe_pdf_text("Next action (specific)"), ln=1)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(*text_light)
        pdf.set_x(10)
        pdf.multi_cell(0, 6, _safe_pdf_text(tpl["next"]))

        footer()

    # -------------------------
    # Supporting details (minimal)
    # -------------------------
    pdf.add_page()
    section_header("Supporting Technical Details")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*text_light)
    pdf.multi_cell(
        0,
        6,
        _safe_pdf_text(
            "This section provides minimal supporting detail to help engineering teams validate ownership and routing.\n"
            "It avoids raw URL dumps; examples are limited and intended as starting points."
        ),
    )
    pdf.ln(4)

    # Theme summary table
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(*card_bg)
    pdf.set_text_color(*text_muted)
    pdf.cell(80, 7, _safe_pdf_text("Theme"), 1, 0, "L", True)
    pdf.cell(20, 7, _safe_pdf_text("Count"), 1, 0, "C", True)
    pdf.cell(90, 7, _safe_pdf_text("Example assets"), 1, 1, "L", True)
    pdf.set_font("Helvetica", "", 9)

    for score, theme, g in story_list:
        name = {
            "admin_surface": "Admin & management access",
            "diagnostics": "Diagnostics & monitoring",
            "backups_artifacts": "Backups & artifacts",
            "subdomain_takeover": "Subdomain takeover signals",
            "misconfiguration": "Security misconfiguration",
            "exposed_resource": "Exposed resources",
            "other": "Other",
        }.get(theme, theme)
        ex = ", ".join((g.get("examples") or [])[:2])
        pdf.set_text_color(*text_light)
        pdf.cell(80, 7, _safe_pdf_text(name), 1, 0)
        pdf.cell(20, 7, _safe_pdf_text(str(g.get("count") or 0)), 1, 0, "C")
        pdf.set_text_color(*text_muted)
        pdf.cell(90, 7, _safe_pdf_text(ex or "-"), 1, 1)

    footer()

    raw = pdf.output(dest="S")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return str(raw).encode("latin-1")


def _build_api_details_pdf(
    *,
    tenant: str,
    report_name: str,
    description: str,
    created_by: str,
    created_at: datetime,
    domain: Optional[str],
    total_endpoints: int,
    vulnerabilities_total: int,
    severity_counts: Dict[str, int],
    findings_rows: List[Dict[str, Any]],
):
    """
    API Testing Details report styled like the provided reference:
    table of contents, assessment scope, executive summary, methodology, and
    vulnerabilities classification sections.
    """
    from fpdf import FPDF  # type: ignore

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    if hasattr(pdf, "alias_nb_pages"):
        pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=16)

    gold = (224, 177, 43)
    blue = (90, 70, 160)
    dark = (17, 24, 39)
    page_bg = (18, 15, 24)       # --bg-secondary
    card_bg = (26, 23, 33)       # --bg-tertiary
    text_light = (245, 243, 247) # --text-primary
    text_muted = (184, 182, 186) # --text-secondary
    border_subtle = (40, 35, 50)

    sev_colors = {
        "CRITICAL": (255, 76, 76),
        "HIGH": (255, 107, 107),
        "MEDIUM": (255, 138, 0),
        "LOW": (24, 169, 153),
        "INFORMATIONAL": (40, 199, 111),
    }

    def dark_page_bg():
        """Fill current page with dark background."""
        pdf.set_fill_color(*page_bg)
        pdf.rect(0, 0, 210, 297, style="F")

    def page_header():
        """Uniform header: NEXVEIL SECURITY + subtitle + page number."""
        pdf.set_xy(10, 8)
        page_no = pdf.page_no() if hasattr(pdf, "page_no") else 1
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*text_muted)
        pdf.cell(190, 6, _safe_pdf_text(str(page_no)), 0, 0, "R")
        pdf.set_y(12)

    def page_footer():
        """Uniform footer: gold line + branding."""
        pdf.set_auto_page_break(auto=False)
        pdf.set_draw_color(*gold)
        pdf.set_line_width(0.4)
        pdf.line(10, 278, 200, 278)
        pdf.set_line_width(0.2)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*gold)
        brand = _safe_pdf_text("NEXVEIL SECURITY")
        brand_w = pdf.get_string_width(brand)
        pdf.set_xy((210 - brand_w) / 2, 279)
        pdf.cell(brand_w, 4, brand, 0, 1, "L")
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(*text_muted)
        # pdf.cell(210, 4, _safe_pdf_text("Start your API Security Journey with NexVeil"), 0, 1, "C")
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(*text_muted)
        year_str = str(created_at.year)
        copy = _safe_pdf_text(f"{year_str} NexVeil Security. All Rights Reserved.")
        copy_w = pdf.get_string_width(copy)
        pdf.set_xy((210 - copy_w) / 2, 283)
        pdf.cell(copy_w, 4, copy, 0, 0, "L")
        pdf.set_auto_page_break(auto=True, margin=30)

    def new_dark_page():
        """Add a new page with dark bg + header. Returns with cursor at y=22."""
        pdf.set_auto_page_break(auto=False, margin=30)
        pdf.add_page()
        dark_page_bg()
        page_header()

    def section_heading(title: str):
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(*gold)
        y = pdf.get_y()
        pdf.set_fill_color(*gold)
        pdf.rect(10, y + 1.5, 3, 7, style="F")
        pdf.set_xy(15, y)
        pdf.cell(0, 10, _safe_pdf_text(title), ln=1)

    def wrap_text(text: str, max_width_mm: float) -> List[str]:
        if max_width_mm <= 2:
            return ["-"]
        s = _safe_pdf_text(text or "").strip()
        if not s:
            return ["-"]
        words = s.split()
        lines: List[str] = []
        cur = ""
        for w in words:
            test = f"{cur} {w}".strip()
            if pdf.get_string_width(test) <= max_width_mm:
                cur = test
            else:
                if cur:
                    lines.append(cur)
                if pdf.get_string_width(w) <= max_width_mm:
                    cur = w
                else:
                    chunk = ""
                    for ch in w:
                        test2 = chunk + ch
                        if pdf.get_string_width(test2) <= max_width_mm:
                            chunk = test2
                        else:
                            if chunk:
                                lines.append(chunk)
                            chunk = ch
                    cur = chunk
        if cur:
            lines.append(cur)
        return lines

    def body_text(text: str, h: float = 5.0):
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*text_light)
        pdf.set_x(10)
        pdf.multi_cell(0, h, _safe_pdf_text(text))

    def muted_text(text: str, h: float = 5.0):
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*text_muted)
        pdf.set_x(10)
        pdf.multi_cell(0, h, _safe_pdf_text(text))

    # -------------------------
    # Cover page
    # -------------------------
    pdf.set_auto_page_break(auto=False, margin=16)
    pdf.add_page()
    pdf.set_fill_color(8, 9, 12)
    pdf.rect(0, 0, 210, 297, style="F")

    # Gold accent line at top
    pdf.set_fill_color(*gold)
    pdf.rect(0, 0, 210, 3, style="F")

    logo_path = Path(__file__).resolve().parent.parent / "swagger" / "nexveil-logo.png"
    if logo_path.exists():
        pdf.image(str(logo_path), x=12, y=20, w=50)

    pdf.set_xy(12, 78)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*gold)
    pdf.cell(0, 8, _safe_pdf_text("NEXVEIL SECURITY"), 0, 1, "L")

    pdf.set_xy(12, 100)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*gold)
    pdf.multi_cell(0, 13, _safe_pdf_text("API TESTING\nDETAILS REPORT"))

    pdf.set_draw_color(*gold)
    pdf.set_line_width(1.2)
    pdf.line(12, pdf.get_y() + 4, 120, pdf.get_y() + 4)
    pdf.set_line_width(0.2)

    pdf.set_xy(12, 160)
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(*text_muted)
    pdf.cell(0, 7, _safe_pdf_text("Prepared for"), 0, 1, "L")
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*gold)
    pdf.cell(0, 12, _safe_pdf_text(tenant), 0, 1, "L")
    if domain:
        pdf.set_font("Helvetica", "", 14)
        pdf.set_text_color(*text_light)
        pdf.cell(0, 9, _safe_pdf_text(domain), 0, 1, "L")
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*text_muted)
    pdf.cell(0, 7, _safe_pdf_text(f"Generated on {created_at.strftime('%m-%d-%Y')}"), 0, 1, "L")

    pdf.ln(8)
    pdf.set_draw_color(*border_subtle)
    pdf.line(12, pdf.get_y(), 198, pdf.get_y())
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*text_muted)
    pdf.cell(0, 6, _safe_pdf_text(f"Total Endpoints: {total_endpoints}   |   Findings: {vulnerabilities_total}"), 0, 1, "L")
    pdf.cell(0, 6, _safe_pdf_text(f"Created by: {created_by}"), 0, 1, "L")
    page_footer()

    # -------------------------
    # Table of Content + Disclosure
    # -------------------------
    new_dark_page()
    section_heading("Table Of Content")
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*text_light)
    toc = [
        "A. Assessment Scope",
        # "B. Executive Summary",
        "B. Vulnerabilities Summary",
        "C. Testing Methodology",
        "   1. Introduction",
        # "   2. Web Application Assessment",
        "   2. Vulnerabilities Classification",
        "D. API Findings",
    ]
    for line in toc:
        pdf.cell(0, 7, _safe_pdf_text(line), ln=1)
    pdf.ln(6)

    section_heading("Disclosure Statement")
    body_text(
        "This document contains sensitive information about the computer security environment, practices, "
        "and current weaknesses of the client's security infrastructure. This document is subject to the "
        "terms and conditions of a non-disclosure agreement between NexVeil and the Client."
    )
    pdf.ln(4)
    section_heading("Document Information")
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*gold)
    pdf.cell(0, 6, _safe_pdf_text("Engagement scope"), ln=1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*text_light)
    pdf.cell(0, 6, _safe_pdf_text(f"{total_endpoints} endpoint(s)"), ln=1)
    page_footer()

    # -------------------------
    # Assessment Scope + Executive Summary
    # -------------------------
    new_dark_page()
    section_heading("A. Assessment Scope")
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*gold)
    # pdf.cell(0, 8, _safe_pdf_text("Web Application Automated Penetration Test"), ln=1)
    pdf.ln(2)
    pdf.set_draw_color(*border_subtle)
    # Table with gold header
    pdf.set_fill_color(*gold)
    pdf.set_text_color(*page_bg)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(45, 10, _safe_pdf_text("Organization"), 1, 0, "L", True)
    pdf.set_fill_color(*card_bg)
    pdf.set_text_color(*text_light)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(145, 10, _safe_pdf_text(tenant), 1, 1, "L", True)
    pdf.set_fill_color(*gold)
    pdf.set_text_color(*page_bg)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(45, 10, _safe_pdf_text("Asset(s)"), 1, 0, "L", True)
    pdf.set_fill_color(*card_bg)
    pdf.set_text_color(*text_light)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(145, 10, _safe_pdf_text(domain or "-"), 1, 1, "L", True)
    pdf.ln(6)

    # section_heading("B. Executive Summary")
    # body_text(
    #     "An Automated Penetration Test (APT) was conducted on the target web application. "
    #     "The objective was to identify security gaps and validate exposure of the attack surface."
    # )
    # pdf.ln(2)
    # body_text(
    #     f"During the assessment, we identified {severity_counts.get('CRITICAL',0)} Critical, "
    #     f"{severity_counts.get('HIGH',0)} High, {severity_counts.get('MEDIUM',0)} Medium, "
    #     f"{severity_counts.get('LOW',0)} Low, {severity_counts.get('INFO',0)} Informational findings."
    # )
    # # pdf.ln(3)
    # if vulnerabilities_total == 0:
    #     pdf.set_font("Helvetica", "B", 10)
    #     pdf.set_text_color(40, 199, 111)
    #     pdf.cell(0, 8, _safe_pdf_text("No vulnerabilities were found during the assessment."), ln=1, align="C")
    page_footer()

    # -------------------------
    # Vulnerabilities Summary + Testing Methodology
    # -------------------------
    new_dark_page()
    section_heading("C. Vulnerabilities Summary")
    muted_text(
        "The risk ratings allocated to each vulnerability are determined using CVSS scoring. "
        "Severity is derived directly from CVSS score ranges."
    )
    pdf.ln(3)

    # Severity bar
    bar_x = 12
    bar_y = pdf.get_y() + 2
    bar_w = 186
    bar_h = 5
    segments = [
        ("CRITICAL", (255, 76, 76), severity_counts.get("CRITICAL", 0)),
        ("HIGH", (255, 107, 107), severity_counts.get("HIGH", 0)),
        ("MEDIUM", (255, 138, 0), severity_counts.get("MEDIUM", 0)),
        ("LOW", (24, 169, 153), severity_counts.get("LOW", 0)),
        ("INFO", (40, 199, 111), severity_counts.get("INFO", 0)),
    ]
    seg_w = bar_w / len(segments)
    for idx, (_, color, _) in enumerate(segments):
        pdf.set_fill_color(*color)
        pdf.rect(bar_x + idx * seg_w, bar_y, seg_w, bar_h, style="F")
    pdf.ln(9)
    pdf.set_font("Helvetica", "B", 9)
    for label, color, count in segments:
        pdf.set_text_color(*color)
        pdf.cell(36.5, 6, _safe_pdf_text(f"{count} {label}"), 0, 0, "L")
    pdf.ln(8)

    severity_descriptions = [
        ("CRITICAL", "Critical risk vulnerabilities have a very high threat impact and require immediate action."),
        ("HIGH", "High risk vulnerabilities can cause serious adverse effects on business operations."),
        ("MEDIUM", "Medium risk vulnerabilities could have a noticeable impact and should be remediated."),
        ("LOW", "Low risk issues do not usually alter normal behavior but can aid further attacks."),
        ("INFORMATIONAL", "Informational findings highlight exposures that may not require action."),
    ]
    label_w = 38
    x0 = pdf.l_margin
    for name, desc in severity_descriptions:
        y0 = pdf.get_y()
        desc_w = pdf.w - pdf.r_margin - x0 - label_w
        if desc_w < 40:
            desc_w = max(40.0, pdf.w - pdf.r_margin - x0 - 30.0)
        pdf.set_xy(x0, y0)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*text_light)
        pdf.multi_cell(label_w, 6, _safe_pdf_text(name), align="L")
        y_after_label = pdf.get_y()
        pdf.set_xy(x0 + label_w, y0)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*text_muted)
        pdf.multi_cell(desc_w, 6, _safe_pdf_text(desc), align="L")
        y_after_desc = pdf.get_y()
        pdf.set_y(max(y_after_label, y_after_desc))
    pdf.ln(6)

    # Testing Methodology (same page)
    section_heading("D. Testing Methodology")
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*gold)
    pdf.cell(0, 7, _safe_pdf_text("1. Introduction"), ln=1)
    body_text(
        "This methodology is based on OWASP API testing guidelines. "
        "The approach focuses on identifying weaknesses across authentication, session management, "
        "input validation, and security configuration."
    )
    body_text(
        "The process combines automated discovery with validation-oriented analysis. "
        "Automated checks are used to identify potential weak points quickly, and findings are then "
        "normalized and correlated to reduce noise and improve triage quality."
    )
    body_text(
        "Each confirmed issue is documented with severity, endpoint context, impact narrative, and "
        "remediation guidance so engineering teams can move directly from detection to fix planning."
    )
    pdf.ln(2)

    test_types = [
        ("Black Box", [
            "No prior knowledge of the target environment",
            "Testing emulates external attacker behavior",
            "Publicly available information is leveraged for discovery",
        ]),
        ("White Box", [
            "Full system knowledge is available for assessment",
            "Testing focuses on verifying controls and code paths",
        ]),
        ("Grey Box", [
            "Limited knowledge is provided to simulate a realistic attacker",
            "Combination of black and white box approaches",
        ]),
    ]
    for box_name, items in test_types:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*text_light)
        pdf.cell(0, 5, _safe_pdf_text(f"{box_name} testing:"), ln=1)
        for item in items:
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*text_muted)
            pdf.set_x(14)
            pdf.cell(0, 4.5, _safe_pdf_text(f"- {item}"), ln=1)
        pdf.ln(1)

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*text_light)
    pdf.cell(0, 5, _safe_pdf_text("Execution workflow:"), ln=1)
    for item in [
        "Scope validation and target profiling before active test execution.",
        "Endpoint-level security checks across auth, input handling, and misconfiguration.",
        "Evidence-driven verification to reduce false positives and improve confidence.",
        "Risk scoring and severity normalization for consistent prioritization.",
        "Remediation-focused output to support implementation and retesting.",
    ]:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*text_muted)
        pdf.set_x(14)
        pdf.cell(0, 4.5, _safe_pdf_text(f"- {item}"), ln=1)
    pdf.ln(1)
    page_footer()

    # -------------------------
    # Vulnerability Classification
    # -------------------------
    new_dark_page()
    section_heading("2. Vulnerabilities Classification")
    muted_text(
        "Classification methodology is based on OWASP Risk Rating Methodology. Each finding is analyzed "
        "in two aspects: likelihood and impact."
    )
    muted_text(
        "Likelihood captures exploit feasibility, while impact captures technical and business consequences. "
        "Combined scoring is used to assign practical remediation urgency."
    )
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*text_light)
    pdf.cell(0, 5, _safe_pdf_text("Threat Agent Factors"), ln=1)
    for item in [
        "Skill level: How technically skilled the threat agent is (1-9).",
        "Motive: How motivated the agent is to find or exploit the issue (1-9).",
        "Opportunity: Resources required to find or exploit the issue (1-9).",
        "Size: How large the threat agent group is (1-9).",
    ]:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*text_muted)
        pdf.set_x(14)
        pdf.cell(0, 4.5, _safe_pdf_text(f"- {item}"), ln=1)
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*text_light)
    pdf.cell(0, 5, _safe_pdf_text("Vulnerability Factors"), ln=1)
    for item in [
        "Ease of discovery: Difficulty for agents to discover the vulnerability (1-9).",
        "Ease of exploit: Difficulty for agents to exploit the vulnerability (1-9).",
        "Awareness: How well known the vulnerability is to agents (1-9).",
        "Intrusion detection: Likelihood an exploit would be detected (1-9).",
    ]:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*text_muted)
        pdf.set_x(14)
        pdf.cell(0, 4.5, _safe_pdf_text(f"- {item}"), ln=1)

    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*text_light)
    pdf.cell(0, 5, _safe_pdf_text("Severity interpretation:"), ln=1)
    for item in [
        "Critical: immediate mitigation and urgent fix verification required.",
        "High: prioritize in the near-term release with clear ownership.",
        "Medium: schedule remediation with compensating controls where needed.",
        "Low/Informational: track and address as part of hardening and hygiene.",
    ]:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*text_muted)
        pdf.set_x(14)
        pdf.cell(0, 4.5, _safe_pdf_text(f"- {item}"), ln=1)
    page_footer()

    # -------------------------
    # Findings Summary Table
    # -------------------------
    new_dark_page()
    section_heading("E. API Findings")
    muted_text(
        "This section lists identified vulnerabilities for the selected API asset. "
        "Endpoints are included for actionability."
    )
    pdf.ln(3)

    col_ep = 70
    col_fn = 70
    col_sv = 20
    col_sc = 20
    x_start = 10

    def table_header():
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(*gold)
        pdf.set_text_color(*page_bg)
        pdf.set_draw_color(*border_subtle)
        pdf.cell(col_ep, 7, _safe_pdf_text("Endpoint"), 1, 0, "L", True)
        pdf.cell(col_fn, 7, _safe_pdf_text("Finding"), 1, 0, "L", True)
        pdf.cell(col_sv, 7, _safe_pdf_text("Severity"), 1, 0, "C", True)
        pdf.cell(col_sc, 7, _safe_pdf_text("Score"), 1, 1, "C", True)
        pdf.set_font("Helvetica", "", 8)

    table_header()
    bottom_y = 268

    if not findings_rows:
        pdf.set_text_color(*text_muted)
        pdf.cell(180, 8, _safe_pdf_text("No findings available."), 1, 1)
        page_footer()
        raw = pdf.output(dest="S")
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw)
        return str(raw).encode("latin-1")

    for row in findings_rows:
        endpoint = str(row.get("endpoint") or "-").replace("\n", " ")
        finding = str(row.get("issue") or row.get("name") or row.get("title") or "-").replace("\n", " ")
        severity = str(row.get("severity") or "INFO").upper()
        score = row.get("score")
        score_text = f"{float(score):.1f}" if score not in (None, "") else "-"

        endpoint_lines = wrap_text(endpoint, col_ep - 3)
        finding_lines = wrap_text(finding, col_fn - 3)
        lines = max(len(endpoint_lines), len(finding_lines))
        row_h = 5 * lines

        if pdf.get_y() + row_h > bottom_y:
            page_footer()
            new_dark_page()
            section_heading("E. API Findings (continued)")
            table_header()

        y_start = pdf.get_y()

        pdf.set_fill_color(*card_bg)
        pdf.set_text_color(*text_light)
        pdf.set_xy(x_start, y_start)
        pdf.multi_cell(col_ep, 5, _safe_pdf_text("\n".join(endpoint_lines)), 1, "L", True)
        y_after_ep = pdf.get_y()

        pdf.set_xy(x_start + col_ep, y_start)
        pdf.multi_cell(col_fn, 5, _safe_pdf_text("\n".join(finding_lines)), 1, "L", True)
        y_after_fn = pdf.get_y()

        pdf.set_xy(x_start + col_ep + col_fn, y_start)
        sc = sev_colors.get(severity, (100, 100, 100))
        pdf.set_text_color(*sc)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(col_sv, row_h, _safe_pdf_text(severity), 1, 0, "C", True)
        pdf.set_text_color(*text_light)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(col_sc, row_h, _safe_pdf_text(score_text), 1, 1, "C", True)

        pdf.set_y(max(y_after_ep, y_after_fn, y_start + row_h))

    page_footer()

    # -------------------------
    # Detailed Findings (dark-themed professional pages)
    # -------------------------

    for idx, row in enumerate(findings_rows):
        finding_name = str(row.get("issue") or row.get("name") or row.get("title") or "Finding")
        severity = str(row.get("severity") or "INFO").upper()
        score = row.get("score")
        score_text = f"{float(score):.1f}" if score not in (None, "") else "-"
        endpoint = str(row.get("endpoint") or "-")
        desc = str(row.get("description") or "").strip()
        impact = str(row.get("impact") or "").strip()
        remediation = str(row.get("remediation") or "").strip()
        cvss_vector = str(row.get("cvss_vector") or "").strip()
        confidence = str(row.get("confidence") or "").strip()
        evidence = str(row.get("evidence") or row.get("proof") or "").strip()
        references = row.get("references") or row.get("reference") or ""
        if isinstance(references, list):
            ref_list = references
        elif isinstance(references, str) and references.strip():
            ref_list = [r.strip() for r in references.replace("\n", ",").split(",") if r.strip()]
        else:
            ref_list = []

        new_dark_page()

        # --- Finding title bar ---
        pdf.set_fill_color(30, 27, 38)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(190, 9, _safe_pdf_text(f"  Finding {idx + 1}: {finding_name}"), 0, 1, "L", True)
        pdf.ln(3)

        # --- Severity / CVSS / Confidence pills ---
        x_pill = 10
        sc = sev_colors.get(severity, (100, 100, 100))
        # Severity pill (filled)
        pdf.set_fill_color(*sc)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 8)
        sev_w = max(pdf.get_string_width(severity) + 10, 28)
        pdf.set_xy(x_pill, pdf.get_y())
        pdf.cell(sev_w, 7, _safe_pdf_text(severity), 0, 0, "C", True)
        x_pill += sev_w + 4
        # CVSS pill (outlined)
        pdf.set_xy(x_pill, pdf.get_y())
        pdf.set_draw_color(*text_muted)
        pdf.set_text_color(*text_light)
        pdf.set_font("Helvetica", "", 8)
        cvss_label = f"CVSS: {score_text}"
        cvss_w = pdf.get_string_width(cvss_label) + 10
        pdf.cell(cvss_w, 7, _safe_pdf_text(cvss_label), 1, 0, "C")
        x_pill += cvss_w + 4
        # Confidence pill (gold outline)
        if confidence:
            pdf.set_xy(x_pill, pdf.get_y())
            pdf.set_draw_color(*gold)
            pdf.set_text_color(*gold)
            conf_label = f"Confidence: {confidence}"
            conf_w = pdf.get_string_width(conf_label) + 10
            pdf.cell(conf_w, 7, _safe_pdf_text(conf_label), 1, 0, "C")
        pdf.ln(10)

        # --- Endpoint bar ---
        y_ep = pdf.get_y()
        pdf.set_draw_color(*gold)
        pdf.set_line_width(0.6)
        pdf.line(10, y_ep, 10, y_ep + 7)
        pdf.set_line_width(0.2)
        pdf.set_xy(12, y_ep)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*gold)
        pdf.cell(28, 7, _safe_pdf_text("ENDPOINT"), 0, 0, "L")
        pdf.set_fill_color(30, 27, 38)
        pdf.set_text_color(*text_light)
        pdf.set_font("Courier", "B", 9)
        pdf.cell(160, 7, _safe_pdf_text(endpoint), 0, 1, "L", True)
        pdf.ln(5)

        pdf.set_auto_page_break(auto=True, margin=30)

        # --- Description ---
        if desc:
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*gold)
            pdf.cell(0, 6, _safe_pdf_text("Description"), ln=1)
            pdf.ln(1)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*text_light)
            pdf.set_x(14)
            pdf.multi_cell(180, 5, _safe_pdf_text(desc))
            pdf.ln(4)

        # --- Proof of Concept / Evidence ---
        if evidence:
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*gold)
            pdf.cell(0, 6, _safe_pdf_text("Proof of Concept"), ln=1)
            pdf.ln(1)
            # Dark code block
            pdf.set_fill_color(26, 23, 33)
            pdf.set_draw_color(*border_subtle)
            code_x = 12
            code_w = 184
            code_lines = evidence.split("\n")
            code_h = len(code_lines) * 4.5 + 6
            pdf.rect(code_x, pdf.get_y(), code_w, code_h, style="FD")
            pdf.set_xy(code_x + 3, pdf.get_y() + 3)
            pdf.set_font("Courier", "", 7)
            pdf.set_text_color(200, 200, 180)
            for cl in code_lines:
                pdf.cell(0, 4.5, _safe_pdf_text(cl), ln=1)
                pdf.set_x(code_x + 3)
            pdf.ln(4)

        # --- Impact ---
        if impact:
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*gold)
            pdf.cell(0, 6, _safe_pdf_text("Impact"), ln=1)
            pdf.ln(1)
            impact_lines = [l.strip() for l in impact.replace("\n", ". ").split(". ") if l.strip()]
            if len(impact_lines) <= 1:
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*text_light)
                pdf.set_x(14)
                pdf.multi_cell(180, 5, _safe_pdf_text(impact))
            else:
                for il in impact_lines:
                    pdf.set_font("Helvetica", "", 9)
                    pdf.set_text_color(*gold)
                    pdf.set_x(14)
                    pdf.cell(4, 5, _safe_pdf_text("-"), 0, 0)
                    pdf.set_text_color(*text_light)
                    pdf.multi_cell(174, 5, _safe_pdf_text(il))
            pdf.ln(4)

        # --- Remediation ---
        if remediation:
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*gold)
            pdf.cell(0, 6, _safe_pdf_text("Remediation"), ln=1)
            pdf.ln(1)
            rem_lines = [l.strip() for l in remediation.replace("\n", ". ").split(". ") if l.strip()]
            if len(rem_lines) <= 1:
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*text_light)
                pdf.set_x(14)
                pdf.multi_cell(180, 5, _safe_pdf_text(remediation))
            else:
                for rl in rem_lines:
                    pdf.set_font("Helvetica", "", 9)
                    pdf.set_text_color(*blue)
                    pdf.set_x(14)
                    pdf.cell(4, 5, _safe_pdf_text("-"), 0, 0)
                    pdf.set_text_color(*text_light)
                    pdf.multi_cell(174, 5, _safe_pdf_text(rl))
            pdf.ln(4)

        # --- References ---
        if ref_list:
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*gold)
            pdf.cell(0, 6, _safe_pdf_text("References"), ln=1)
            pdf.ln(1)
            pdf.set_font("Helvetica", "", 8)
            for ref in ref_list[:5]:
                pdf.set_text_color(*gold)
                pdf.set_x(14)
                pdf.cell(6, 5, _safe_pdf_text("->"), 0, 0)
                pdf.set_text_color(180, 160, 100)
                pdf.cell(0, 5, _safe_pdf_text(ref), ln=1)
            pdf.ln(3)

        # --- Remediation Tracker table ---
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*gold)
        pdf.cell(0, 6, _safe_pdf_text("Remediation Tracker"), ln=1)
        pdf.ln(1)
        # Table header
        tracker_cols = [("Finding", 55), ("Severity", 30), ("Status", 25), ("Owner", 40), ("Due Date", 40)]
        pdf.set_fill_color(*gold)
        pdf.set_text_color(18, 15, 24)
        pdf.set_font("Helvetica", "B", 8)
        for col_name, col_w in tracker_cols:
            pdf.cell(col_w, 7, _safe_pdf_text(col_name), 0, 0, "C", True)
        pdf.ln()
        # Table row
        pdf.set_fill_color(30, 27, 38)
        pdf.set_text_color(*text_light)
        pdf.set_font("Helvetica", "", 8)
        short_name = finding_name[:30] + "..." if len(finding_name) > 30 else finding_name
        row_vals = [short_name, severity, "Open", "________", "________"]
        for (_, col_w), val in zip(tracker_cols, row_vals):
            pdf.cell(col_w, 7, _safe_pdf_text(val), 0, 0, "C", True)
        pdf.ln()

        page_footer()

    # -------------------------
    # Closing Page -- CTA
    # -------------------------
    pdf.set_auto_page_break(auto=False, margin=16)
    pdf.add_page()
    pdf.set_fill_color(8, 9, 12)
    pdf.rect(0, 0, 210, 297, style="F")

    # Logo (larger)
    if logo_path.exists():
        pdf.image(str(logo_path), x=75, y=20, w=60)

    # Headline centered
    pdf.set_xy(0, 80)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*text_light)
    pdf.cell(210, 15, _safe_pdf_text("Start your API Security"), 0, 1, "C")
    pdf.set_x(0)
    pdf.cell(210, 15, _safe_pdf_text("Journey with"), 0, 1, "C")
    pdf.set_x(0)
    pdf.set_text_color(*gold)
    pdf.cell(210, 15, _safe_pdf_text("NexVeil"), 0, 1, "C")

    # Description paragraph centered
    desc_w = 150
    desc_x = (210 - desc_w) / 2
    pdf.set_xy(desc_x, 140)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*text_muted)
    pdf.multi_cell(desc_w, 7, _safe_pdf_text(
        "NexVeil seamlessly combines automated and expert-led security "
        "testing to continuously protect your APIs and attack surface. "
        "Our platform delivers Penetration Testing, API Security "
        "Scanning, and Vulnerability Assessments -- all in one place "
        "-- so you can discover, prioritize, and remediate threats "
        "before attackers do."
    ), align="C")

    # Service pills
    pills = [
        "API Security Testing",
        "Penetration Testing",
        "CI/CD Integration",
        "Vulnerability Assessments",
        "OWASP-aligned Methodology",
    ]
    pill_y = 200
    pill_x = 14
    pdf.set_draw_color(80, 70, 60)
    pdf.set_font("Helvetica", "B", 9)
    for pill_text in pills:
        pw = pdf.get_string_width(pill_text) + 14
        total_pw = pw + 10  # extra space for dot area
        if pill_x + total_pw > 196:
            pill_y += 13
            pill_x = 14
        # Pill border + text (draw first so dot overlays cleanly)
        pdf.set_xy(pill_x, pill_y)
        pdf.set_text_color(*text_light)
        pdf.cell(total_pw, 8, "", 1, 0, "L")  # empty bordered box
        # Gold dot inside the pill
        pdf.set_fill_color(*gold)
        pdf.ellipse(pill_x + 4, pill_y + 2.8, 2.5, 2.5, style="F")
        # Text after the dot
        pdf.set_xy(pill_x + 9, pill_y)
        pdf.cell(total_pw - 9, 8, _safe_pdf_text(pill_text), 0, 0, "L")
        pill_x += total_pw + 5

    # Use the same footer style on last page as all other pages.
    page_footer()

    raw = pdf.output(dest="S")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return str(raw).encode("latin-1")


def _build_asm_pdf(
    *,
    tenant: str,
    report_name: str,
    report_type: str,
    description: str,
    created_by: str,
    created_at: datetime,
    prepared_for: str,
    domain: Optional[str],
    data: Dict[str, Any],
    template: Optional[Dict[str, Any]] = None,
) -> bytes:
    # Using fpdf2 (already in requirements). If missing, raise a clear error.
    from fpdf import FPDF  # type: ignore

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    # Enables total pages placeholder {nb} in PyFPDF/fpdf2
    if hasattr(pdf, "alias_nb_pages"):
        pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=14)

    logo_path = Path(__file__).resolve().parent.parent / "swagger" / "nexveil-logo.png"

    sev_colors = {
        "CRITICAL": (255, 76, 76),
        "HIGH": (255, 107, 107),
        "MEDIUM": (255, 138, 0),
        "LOW": (24, 169, 153),
        "INFO": (40, 199, 111),
        "INFORMATIONAL": (40, 199, 111),
    }

    gold = (224, 177, 43)
    dark = (17, 24, 39)
    page_bg = (18, 15, 24)
    card_bg = (26, 23, 33)
    text_light = (245, 243, 247)
    text_muted = (184, 182, 186)
    border_subtle = (40, 35, 50)

    def _sev_color(sev: str) -> tuple:
        s = str(sev or "INFO").upper()
        return sev_colors.get(s, (100, 100, 100))

    def section_header(title: str):
        """
        Dark-themed header with logo on left + section title.
        """
        dark_page_bg()
        top_y = 10
        title_y = top_y + 2

        pdf.set_xy(10, title_y)
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(*gold)
        pdf.cell(0, 10, _safe_pdf_text(title), ln=1)
        pdf.set_text_color(*text_muted)

        pdf.set_draw_color(*border_subtle)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(6)

    def dark_page_bg():
        """Fill current page with dark background."""
        pdf.set_fill_color(*page_bg)
        pdf.rect(0, 0, 210, 297, style="F")

    def footer(*, dark: bool = False):
        """
        IMPORTANT: don't print near the bottom margin while auto page-break is enabled,
        otherwise FPDF will silently add a new blank page.
        """
        # Match API report footer style exactly.
        pdf.set_auto_page_break(auto=False)
        pdf.set_draw_color(*gold)
        pdf.set_line_width(0.4)
        pdf.line(10, 278, 200, 278)
        pdf.set_line_width(0.2)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*gold)
        brand = _safe_pdf_text("NEXVEIL SECURITY")
        brand_w = pdf.get_string_width(brand)
        pdf.set_xy((210 - brand_w) / 2, 279)
        pdf.cell(brand_w, 4, brand, 0, 1, "L")
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(*text_muted)
        # pdf.cell(210, 4, _safe_pdf_text("Start your API Security Journey with NexVeil"), 0, 1, "C")
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(*text_muted)
        year_str = str(created_at.year)
        copy = _safe_pdf_text(f"{year_str} NexVeil Security. All Rights Reserved.")
        copy_w = pdf.get_string_width(copy)
        pdf.set_xy((210 - copy_w) / 2, 283)
        pdf.cell(copy_w, 4, copy, 0, 0, "L")
        pdf.set_auto_page_break(auto=True, margin=14)

    def summary_card(*, x: float, y: float, w: float, h: float, value: str, label: str):
        """
        Dark-themed summary card (big number + diagonal accent + label).
        """
        pdf.set_draw_color(*border_subtle)
        pdf.set_fill_color(*card_bg)
        pdf.rect(x, y, w, h, style="DF")

        # Accent icon square
        pdf.set_fill_color(*gold)
        pdf.rect(x + 8, y + 10, 12, 12, style="F")

        # Value
        pdf.set_xy(x + 26, y + 8)
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(*gold)
        pdf.cell(0, 12, _safe_pdf_text(value))

        # Label
        pdf.set_xy(x + 10, y + h - 12)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*text_light)
        pdf.cell(0, 8, _safe_pdf_text(label))
        pdf.set_text_color(*text_muted)

    def _draw_arc(cx: float, cy: float, r: float, start_deg: float, end_deg: float, *, color: tuple[int, int, int], lw: float = 6.0):
        """
        Draw an arc approximation using short line segments (works in PyFPDF/fpdf2).
        """
        import math

        pdf.set_draw_color(*color)
        pdf.set_line_width(lw)
        step = 4  # degrees per segment
        a = start_deg
        prev = None
        while a <= end_deg:
            rad = math.radians(a)
            x = cx + r * math.cos(rad)
            y = cy + r * math.sin(rad)
            if prev is not None:
                pdf.line(prev[0], prev[1], x, y)
            prev = (x, y)
            a += step
        pdf.set_line_width(0.2)
        pdf.set_draw_color(0, 0, 0)

    def risk_gauge_card(*, x: float, y: float, w: float, h: float, value: float):
        """
        Dark-themed card with a semi-circle gauge + big value.
        """
        # Card background
        pdf.set_draw_color(*border_subtle)
        pdf.set_fill_color(*card_bg)
        pdf.rect(x, y, w, h, style="DF")

        # Gauge geometry
        cx = x + w * 0.48
        cy = y + h * 0.55
        r = min(w, h) * 0.33

        # Arc segments (left->right)
        _draw_arc(cx, cy, r, 200, 240, color=(34, 197, 94), lw=6.0)    # green
        _draw_arc(cx, cy, r, 241, 285, color=(59, 130, 246), lw=6.0)   # blue
        _draw_arc(cx, cy, r, 286, 325, color=(245, 158, 11), lw=6.0)   # amber
        _draw_arc(cx, cy, r, 326, 350, color=(239, 68, 68), lw=6.0)    # red

        # Needle (simple dot + line)
        import math
        v = max(0.0, min(100.0, float(value)))
        # map 0..100 to 200..350 degrees
        ang = 200 + (v / 100.0) * 150.0
        rad = math.radians(ang)
        nx = cx + r * 0.9 * math.cos(rad)
        ny = cy + r * 0.9 * math.sin(rad)
        pdf.set_draw_color(*dark)
        pdf.set_line_width(1.2)
        pdf.line(cx, cy, nx, ny)
        pdf.set_fill_color(*dark)
        pdf.ellipse(cx - 2.2, cy - 2.2, 4.4, 4.4, style="F")
        pdf.set_line_width(0.2)

        # Value
        pdf.set_xy(x, y + 22)
        pdf.set_font("Helvetica", "B", 40)
        pdf.set_text_color(*gold)
        pdf.cell(w, 18, _safe_pdf_text(f"{v:.1f}"), 0, 1, "C")
        pdf.set_text_color(*text_light)

        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*text_muted)
        pdf.set_xy(x + 10, y + h - 16)
        pdf.cell(w - 20, 8, _safe_pdf_text("OVERALL RISK"), 0, 0, "L")
        pdf.set_text_color(*text_muted)

    def wrap_text(text: str, max_width_mm: float) -> List[str]:
        """
        Word-wrap text to fit within max_width_mm using current font.
        Works with PyFPDF/fpdf2 get_string_width().
        """
        s = _safe_pdf_text(text or "").strip()
        if not s:
            return [""]
        words = s.split()
        lines: List[str] = []
        cur = ""
        for w in words:
            test = f"{cur} {w}".strip()
            if pdf.get_string_width(test) <= max_width_mm:
                cur = test
            else:
                if cur:
                    lines.append(cur)
                # If a single word is too long, hard-split it
                if pdf.get_string_width(w) <= max_width_mm:
                    cur = w
                else:
                    chunk = ""
                    for ch in w:
                        test2 = (chunk + ch)
                        if pdf.get_string_width(test2) <= max_width_mm:
                            chunk = test2
                        else:
                            if chunk:
                                lines.append(chunk)
                            chunk = ch
                    cur = chunk
        if cur:
            lines.append(cur)
        return lines

    def clamp_text_lines(text: str, max_width_mm: float, max_lines: int) -> str:
        lines = wrap_text(text, max_width_mm)
        if len(lines) <= max_lines:
            return "\n".join(lines)
        # Truncate with ellipsis on last line
        trimmed = lines[:max_lines]
        last = trimmed[-1]
        while last and pdf.get_string_width(last + "...") > max_width_mm:
            last = last[:-1]
        trimmed[-1] = (last + "...") if last else "..."
        return "\n".join(trimmed)

    def clamp_chars(text: str, max_chars: int) -> str:
        s = _safe_pdf_text(text or "")
        if len(s) <= max_chars:
            return s
        return (s[: max(0, max_chars - 3)] + "...")

    def assets_pages(assets: List[str], total_assets: int):
        """
        Render assets summary + paginated assets table across as many pages as needed.
        """
        # First assets page
        pdf.add_page()
        section_header(str((template or {}).get("assets_section_title") or "Assets"))
        # pdf.set_font("Helvetica", "", 11)
        # pdf.set_text_color(*text_light)
        # pdf.multi_cell(
        #     0,
        #     6,
        #     _safe_pdf_text(
        #         str((template or {}).get("assets_intro") or (
        #             # f"{tenant} ran its scans to find the known and unknown assets below. "
        #             # "Assets include Domains, Subdomains, IP Addresses, and URLs for your team's reference."
        #         ))
        #     ),
        # )
        # pdf.set_text_color(*text_muted)
        # pdf.ln(4)

        summary_y = pdf.get_y() + 2
        summary_h = 52
        summary_card(
            x=10,
            y=summary_y,
            w=190,
            h=summary_h,
            value=str(total_assets),
            label=str((template or {}).get("assets_total_label") or "TOTAL ASSETS"),
        )

        if (template or {}).get("assets_show_table") is False:
            footer()
            return

        # Table card rendering (paginated)
        def start_table_page(table_y: float):
            pdf.set_draw_color(*border_subtle)
            pdf.set_fill_color(*card_bg)
            # Fill down to just above footer zone
            card_h = 268 - table_y
            if card_h < 90:
                card_h = 90
            pdf.rect(10, table_y, 190, card_h, style="DF")

            pdf.set_xy(16, table_y + 8)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(*gold)
            pdf.cell(0, 8, _safe_pdf_text(str((template or {}).get("assets_table_title") or "Assets")))
            pdf.ln(10)

            pdf.set_x(16)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*text_muted)
            pdf.cell(0, 7, _safe_pdf_text(str((template or {}).get("assets_table_col_name") or "Name")))
            pdf.set_draw_color(*border_subtle)
            pdf.line(16, pdf.get_y() + 1, 194, pdf.get_y() + 1)
            pdf.ln(6)
            pdf.set_text_color(*text_light)
            pdf.set_font("Helvetica", "", 11)

        start_table_page(summary_y + summary_h + 8)

        left_x = 16
        right_x = 194
        max_w = right_x - left_x
        row_h = 8
        bottom_y = 268  # keep above footer

        if not assets:
            pdf.set_x(left_x)
            pdf.set_text_color(*text_muted)
            pdf.cell(0, row_h, _safe_pdf_text("No assets available."), ln=1)
            pdf.set_text_color(*text_muted)
            footer()
            return

        for i, name in enumerate(assets):
            # If we're close to the bottom, start a new page for more assets
            if pdf.get_y() + row_h > bottom_y:
                footer()
                pdf.add_page()
                section_header("Assets")
                # Reduce whitespace on continued pages: start table right after header
                start_table_page(max(60, pdf.get_y() + 6))

            pdf.set_x(left_x)
            pdf.set_text_color(*text_light)

            # Wrap/truncate long asset names to avoid overlap
            txt = clamp_text_lines(name, max_w, max_lines=2)
            lines = txt.split("\n")
            # Compute dynamic height for wrapped rows
            height = row_h * len(lines)
            if pdf.get_y() + height > bottom_y:
                footer()
                pdf.add_page()
                section_header("Assets")
                start_table_page(max(60, pdf.get_y() + 6))

            # Render row (multi_cell advances y)
            pdf.multi_cell(max_w, row_h, txt)
            y = pdf.get_y()
            pdf.set_draw_color(*border_subtle)
            pdf.line(left_x, y, right_x, y)

        footer()

    def vulnerabilities_pages(vuln_rows: List[Dict[str, Any]], vulnerabilities_total: int):
        """
        Render vulnerabilities table across pages to avoid overlaps.
        """
        pdf.add_page()
        section_header(str((template or {}).get("vuln_section_title") or "Vulnerabilities"))
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*text_light)
        pdf.multi_cell(
            0,
            5,
            _safe_pdf_text(
                str((template or {}).get("vuln_intro") or (
                    "This section lists vulnerabilities found on your assets. "
                    "They are segregated by risk level (Severity)."
                ))
            ),
        )
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*gold)
        pdf.cell(
            0,
            8,
            _safe_pdf_text(
                f"{str((template or {}).get('vuln_total_label') or 'TOTAL VULNERABILITIES')}: {vulnerabilities_total}"
            ),
            ln=1,
        )
        pdf.ln(2)

        def table_header():
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_fill_color(*card_bg)
            pdf.set_text_color(*text_muted)
            pdf.cell(110, 7, _safe_pdf_text(str((template or {}).get("vuln_col_name") or "Name")), 1, 0, "L", True)
            pdf.cell(40, 7, _safe_pdf_text(str((template or {}).get("vuln_col_impacted") or "Assets Impacted")), 1, 0, "C", True)
            pdf.cell(40, 7, _safe_pdf_text(str((template or {}).get("vuln_col_risk") or "Risk")), 1, 1, "C", True)
            pdf.set_font("Helvetica", "", 9)

        table_header()
        bottom_y = 268

        if not vuln_rows:
            pdf.cell(190, 8, _safe_pdf_text("No vulnerability data available."), 1, 1)
            footer()
            return

        for r in vuln_rows:
            if pdf.get_y() + 7 > bottom_y:
                footer()
                pdf.add_page()
                section_header("Vulnerabilities (continued)")
                table_header()

            name = str(r.get("name") or r.get("issue") or "-")
            assets_imp = str(r.get("assets_impacted") or "1")
            risk = str(r.get("severity") or r.get("risk") or "INFO").upper()
            pdf.set_text_color(*text_light)
            pdf.cell(110, 7, _safe_pdf_text(name[:90]), 1, 0)
            pdf.cell(40, 7, _safe_pdf_text(assets_imp), 1, 0, "C")
            sc = _sev_color(risk)
            pdf.set_text_color(*sc)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(40, 7, _safe_pdf_text(risk), 1, 1, "C")
            pdf.set_text_color(*text_muted)
            pdf.set_font("Helvetica", "", 9)

        footer()

    # -------------------------
    # Cover page
    # -------------------------
    # Disable auto-page-break for cover to prevent accidental blank pages being inserted
    pdf.set_auto_page_break(auto=False, margin=14)
    pdf.add_page()
    # Full-page dark background (black theme)
    pdf.set_fill_color(*page_bg)
    pdf.rect(0, 0, 210, 297, style="F")

    # Brand: use local Secoraa logo if available; otherwise render text (top-left like sample)
    logo_path = Path(__file__).resolve().parent.parent / "swagger" / "nexveil-logo.png"
    if logo_path.exists():
        # Place logo top-left
        pdf.image(str(logo_path), x=12, y=18, w=55)
        brand_y = 46
    else:
        brand_y = 28

    # If we don't have an image logo, render "Secoraa" wordmark.
    if not logo_path.exists():
        pdf.set_xy(12, brand_y - 6)
        pdf.set_font("Helvetica", "B", 28)
        pdf.set_text_color(*text_light)
        pdf.cell(0, 10, _safe_pdf_text("NexVeil"), ln=1, align="L")


    # Title (gold) like API report
    pdf.set_xy(12, 92)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(*gold)
    cover_title = str((template or {}).get("cover_title") or "ATTACK SURFACE MANAGEMENT\n(ASM) DETAILS REPORT")
    pdf.multi_cell(0, 12, _safe_pdf_text(cover_title))

    # Green separator line
    pdf.set_draw_color(34, 197, 94)
    pdf.set_line_width(1.2)
    pdf.line(12, pdf.get_y() + 2, 110, pdf.get_y() + 2)
    pdf.set_line_width(0.2)

    # Prepared for block — enforce consistent spacing by using explicit Y positions
    cover_block_shift_mm = 30  # moved up by ~3cm
    base_x = 12
    # Keep "Generated on" where it is, and move the rest of the block upwards.
    move_other_up_mm = 20  # ~2cm up
    y = (235 - cover_block_shift_mm) - move_other_up_mm

    # "Prepared for"
    pdf.set_xy(base_x, y)
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(*text_light)
    pdf.cell(0, 8, _safe_pdf_text("Prepared for"), 0, 1, "L")
    # tighter gap between "Prepared for" and org name
    y += 12

    # Org name
    pdf.set_xy(base_x, y)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*gold)
    pdf.cell(0, 12, _safe_pdf_text(prepared_for or tenant), 0, 1, "L")
    y += 16

    # Domain
    if domain:
        pdf.set_xy(base_x, y)
        pdf.set_font("Helvetica", "", 18)
        pdf.set_text_color(*text_light)
        pdf.cell(0, 10, _safe_pdf_text(domain), 0, 1, "L")
        y += 18

    # Description (<=150 chars) below domain with consistent spacing
    if description:
        pdf.set_xy(base_x, y)
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(*text_muted)
        safe_desc = clamp_text_lines(clamp_chars(description, 200), max_width_mm=186, max_lines=3)
        pdf.multi_cell(186, 6, safe_desc)
        y = pdf.get_y() + 6

    # Generated-on line: keep at its current fixed position (do NOT move with the rest of the block)
    generated_y = (274 - cover_block_shift_mm) + 20  # fixed position we already had
    # Keep it above footer zone
    if generated_y > 268:
        generated_y = 268
    pdf.set_xy(base_x, generated_y)
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(*text_light)
    pdf.cell(0, 8, _safe_pdf_text(f"Generated on {created_at.strftime('%m-%d-%Y')}"), 0, 0, "L")
    footer(dark=True)
    pdf.set_text_color(*text_muted)
    # Re-enable auto-page-break for the rest of the report
    pdf.set_auto_page_break(auto=True, margin=14)

    # -------------------------
    # Assets + Vulnerabilities (2-column summary style, simplified)
    # -------------------------
    assets_total = int(data.get("assets_total") or 0)
    vulnerabilities_total = int(data.get("vulnerabilities_total") or 0)

    assets_list: List[str] = data.get("assets_list") or []
    vuln_rows: List[Dict[str, Any]] = data.get("vulnerabilities") or []

    # Assets (paginated)
    assets_pages(assets_list, assets_total)

    # Vulnerabilities (paginated)
    vulnerabilities_pages(vuln_rows, vulnerabilities_total)

    # -------------------------
    # Risk pages (gauge + tables)
    # -------------------------
    pdf.add_page()
    section_header("Risk")
    sev_counts: Dict[str, int] = data.get("severity_counts") or {}
    total = max(1, vulnerabilities_total)
    avg_risk = float(data.get("avg_risk") or 0.0)

    # Intro text
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*text_light)
    pdf.multi_cell(
        0,
        6,
        _safe_pdf_text(
            "The NexVeil team analyzed your assets and vulnerabilities. "
            "The overall risk value is derived from the severities found."
        ),
    )
    pdf.set_text_color(*text_muted)
    pdf.ln(4)

    y0 = pdf.get_y()
    summary_card(
        x=10,
        y=y0,
        w=190,
        h=52,
        value=f"{avg_risk:.1f}",
        label="OVERALL RISK SCORE",
    )

    # Vulnerabilities by Risk (table)
    pdf.set_y(y0 + 60)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*gold)
    pdf.cell(0, 8, _safe_pdf_text("Vulnerabilities by Risk"), ln=1)
    pdf.set_text_color(*text_muted)

    pdf.set_fill_color(*card_bg)
    pdf.set_draw_color(*border_subtle)
    x0 = 10
    table_w = 190
    sev_w = 125
    count_w = table_w - sev_w
    header_h = 12
    bottom_y = 268
    available_h = max(70, bottom_y - pdf.get_y())
    row_h = max(12, (available_h - header_h) / 5.0)

    pdf.set_x(x0)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(sev_w, header_h, _safe_pdf_text("Severity"), 1, 0, "C", True)
    pdf.cell(count_w, header_h, _safe_pdf_text("Count"), 1, 1, "C", True)
    for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        y_row = pdf.get_y()
        pdf.set_draw_color(*border_subtle)
        pdf.rect(x0, y_row, sev_w, row_h)
        pdf.rect(x0 + sev_w, y_row, count_w, row_h)

        pdf.set_text_color(*_sev_color(k))
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_xy(x0, y_row + (row_h - 10) / 2)
        pdf.cell(sev_w, 10, _safe_pdf_text(k), 0, 0, "C")

        pdf.set_text_color(*text_muted)
        pdf.set_font("Helvetica", "", 18)
        pdf.set_xy(x0 + sev_w, y_row + (row_h - 10) / 2)
        pdf.cell(count_w, 10, _safe_pdf_text(str(int(sev_counts.get(k, 0)))), 0, 0, "C")
        pdf.set_y(y_row + row_h)

    footer()

    # (3) Hardcoded severity explanation table (new page)
    pdf.add_page()
    section_header("Risk Legend")
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*gold)
    pdf.cell(0, 8, _safe_pdf_text("Risk level definitions"), ln=1)
    pdf.set_text_color(*text_muted)
    pdf.ln(2)

    legend_rows = [
        ("CRITICAL", "Critical risk vulnerabilities could be expected to have a very high threat to a company's data and should be fixed as a top-priority basis. Critical vulnerabilities can allow a hacker to compromise the environment or cause other severe impacts."),
        ("HIGH", "High risk vulnerabilities could be expected to have a catastrophic adverse effect on organizational operations, organizational assets, or individuals."),
        ("MEDIUM", "Medium risk vulnerabilities could be expected to have a serious adverse effect on organizational operations, organizational assets, or individuals."),
        ("LOW", "These are security issues that do not functionally alter normal systems behavior, but which may aid or enable further attacks against the system under other circumstances. Vulnerabilities may not violate either the system's security model or any security objectives."),
        ("INFORMATIONAL", "Informational findings highlight low-risk observations that improve security visibility and hygiene. They typically do not indicate direct exploitability but should be reviewed as part of continuous hardening."),
    ]

    pdf.set_fill_color(*card_bg)
    pdf.set_draw_color(*border_subtle)
    pdf.set_font("Helvetica", "B", 11)
    x0 = 10
    table_w = 190
    sev_w = 48
    desc_w = table_w - sev_w
    header_h = 12
    line_h = 5.5
    pad = 3.0
    min_row_h = 24
    bottom_y = 268  # keep above footer zone

    def legend_table_header():
        pdf.set_fill_color(*card_bg)
        pdf.set_draw_color(*border_subtle)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_x(x0)
        pdf.cell(sev_w, header_h, _safe_pdf_text("Severity"), 1, 0, "C", True)
        pdf.cell(desc_w, header_h, _safe_pdf_text("Description"), 1, 1, "C", True)
        pdf.set_font("Helvetica", "", 10)

    legend_table_header()
    table_top_y = pdf.get_y()
    available_h = max(0.0, bottom_y - table_top_y)
    desc_texts: List[str] = []
    needed_heights: List[float] = []

    for _sev, desc in legend_rows:
        desc_text = clamp_text_lines(desc, max_width_mm=(desc_w - pad * 2), max_lines=8)
        desc_lines = desc_text.split("\n")
        desc_texts.append(desc_text)
        needed_heights.append(max(min_row_h, (pad * 2) + (line_h * len(desc_lines))))

    total_needed_h = sum(needed_heights)
    extra_h = max(0.0, available_h - total_needed_h)
    per_row_extra = (extra_h / len(legend_rows)) if legend_rows else 0.0
    row_heights = [h + per_row_extra for h in needed_heights]

    for idx, (sev, _desc) in enumerate(legend_rows):
        row_h = row_heights[idx]
        desc_lines = desc_texts[idx].split("\n")
        y_row = pdf.get_y()

        pdf.set_draw_color(*border_subtle)
        pdf.rect(x0, y_row, sev_w, row_h)
        pdf.rect(x0 + sev_w, y_row, desc_w, row_h)

        pdf.set_xy(x0, y_row + (row_h - 8) / 2)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(sev_w, 8, _safe_pdf_text(sev), 0, 0, "C")

        pdf.set_font("Helvetica", "", 10)
        x_text = x0 + sev_w + pad
        text_block_h = line_h * len(desc_lines)
        y_text = y_row + max(pad, (row_h - text_block_h) / 2.0)
        max_lines_fit = int((row_h - pad * 2) / line_h) if line_h > 0 else len(desc_lines)
        for i, line in enumerate(desc_lines[:max_lines_fit]):
            pdf.set_xy(x_text, y_text + i * line_h)
            pdf.cell(desc_w - (pad * 2), line_h, _safe_pdf_text(line), 0, 0, "C")

        pdf.set_y(y_row + row_h)

    footer()

    # -------------------------
    # Closing Page -- CTA (same as API report)
    # -------------------------
    pdf.set_auto_page_break(auto=False, margin=16)
    pdf.add_page()
    pdf.set_fill_color(8, 9, 12)
    pdf.rect(0, 0, 210, 297, style="F")

    # Centered logo
    if logo_path.exists():
        pdf.image(str(logo_path), x=75, y=20, w=60)

    # Centered headline
    pdf.set_xy(0, 80)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*text_light)
    pdf.cell(210, 15, _safe_pdf_text("Start your API Security"), 0, 1, "C")
    pdf.set_x(0)
    pdf.cell(210, 15, _safe_pdf_text("Journey with"), 0, 1, "C")
    pdf.set_x(0)
    pdf.set_text_color(*gold)
    pdf.cell(210, 15, _safe_pdf_text("NexVeil"), 0, 1, "C")

    # Centered description
    desc_w = 150
    desc_x = (210 - desc_w) / 2
    pdf.set_xy(desc_x, 140)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*text_muted)
    pdf.multi_cell(desc_w, 7, _safe_pdf_text(
        "NexVeil seamlessly combines automated and expert-led security "
        "testing to continuously protect your APIs and attack surface. "
        "Our platform delivers Penetration Testing, API Security "
        "Scanning, and Vulnerability Assessments -- all in one place "
        "-- so you can discover, prioritize, and remediate threats "
        "before attackers do."
    ), align="C")

    # Service pills (same as API report closing page)
    pills = [
        "API Security Testing",
        "Penetration Testing",
        "CI/CD Integration",
        "Vulnerability Assessments",
        "OWASP-aligned Methodology",
    ]
    pill_y = 200
    pill_x = 14
    pdf.set_draw_color(80, 70, 60)
    pdf.set_font("Helvetica", "B", 9)
    for pill_text in pills:
        pw = pdf.get_string_width(pill_text) + 14
        total_pw = pw + 10
        if pill_x + total_pw > 196:
            pill_y += 13
            pill_x = 14
        pdf.set_xy(pill_x, pill_y)
        pdf.set_text_color(*text_light)
        pdf.cell(total_pw, 8, "", 1, 0, "L")
        pdf.set_fill_color(*gold)
        pdf.ellipse(pill_x + 4, pill_y + 2.8, 2.5, 2.5, style="F")
        pdf.set_xy(pill_x + 9, pill_y)
        pdf.cell(total_pw - 9, 8, _safe_pdf_text(pill_text), 0, 0, "L")
        pill_x += total_pw + 5

    # Use the same footer style on last page as all other pages.
    footer()

    # fpdf2 versions differ: output(dest="S") may return str, bytes, or bytearray.
    raw = pdf.output(dest="S")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return str(raw).encode("latin-1")


class CreateReportRequest(BaseModel):
    report_name: str = Field(..., min_length=1, max_length=200)
    report_type: str = Field(..., description="EXEC_SUMMARY|DETAILS_SUMMARY (EXPOSURE_STORIES/ASM are accepted as legacy aliases)")
    # Requirement: description should be only 200 letters
    description: Optional[str] = Field(default=None, max_length=200)
    domain_name: Optional[str] = Field(default=None, description="Required for ASM reports")
    assessment_type: str = Field(default="DOMAIN", description="DOMAIN|VULNERABILITY_SCAN|WEBSCAN|API_TESTING|NETWORK_SCAN")
    subdomain_name: Optional[str] = Field(default=None, description="Required for VULNERABILITY_SCAN/WEBSCAN reports")
    scan_id: Optional[str] = Field(default=None, description="Required for API_TESTING and NETWORK_SCAN reports (scan_id of the underlying scan)")


class ReportRow(BaseModel):
    id: str
    report_name: str
    report_type: str
    created_by: Optional[str] = None
    created_at: str
    domain_name: Optional[str] = None
    minio_object_name: Optional[str] = None


@router.get("/asm.pdf")
def download_asm_report_pdf(
    claims: Dict[str, Any] = Depends(get_token_claims),
    db: Session = Depends(get_db),
    domain: Optional[str] = Query(default=None, description="Optional domain filter"),
):
    """
    Generate and download an ASM PDF report (multi-page) similar to the provided sample layout.
    """
    tenant = str(claims.get("tenant") or "NexVeil").strip()
    prepared_for = str(claims.get("tenant") or tenant).strip()
    created_by = str(claims.get("sub") or claims.get("username") or "user").strip()
    created_at = datetime.utcnow()

    # Assets
    tenant_users = get_tenant_usernames(db, claims)
    domain_q = db.query(Domain).filter(Domain.created_by.in_(tenant_users))
    if domain:
        domain_q = domain_q.filter(Domain.domain_name == domain)
    domains = domain_q.order_by(Domain.created_at.desc()).all()
    domain_ids = [d.id for d in domains]

    sub_q = db.query(Subdomain)
    if domain_ids:
        sub_q = sub_q.filter(Subdomain.domain_id.in_(domain_ids))
    subdomains = sub_q.order_by(Subdomain.created_at.desc()).all()

    assets_list = [d.domain_name for d in domains] + [s.subdomain_name for s in subdomains]
    assets_total = len(assets_list)

    # Vulnerabilities (DB only; API findings are also in UI, but this is enough for the template)
    vq = db.query(Vulnerability)
    if domain_ids:
        vq = vq.filter(Vulnerability.domain_id.in_(domain_ids))
    vulns = vq.order_by(Vulnerability.id.desc()).all()

    vuln_rows: List[Dict[str, Any]] = []
    sev_counts: Dict[str, int] = {}
    total_weight = 0

    for v in vulns:
        sev = str(getattr(v, "severity", None) or "INFO").upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        total_weight += _severity_weight(sev)
        vuln_rows.append(
            {
                "name": getattr(v, "vuln_name", None),
                "severity": sev,
                "assets_impacted": 1,
            }
        )

    vulnerabilities_total = len(vuln_rows)
    avg_risk = (total_weight / max(1, vulnerabilities_total)) if vulnerabilities_total else 0.0

    pdf_bytes = _build_asm_pdf(
        tenant=tenant,
        report_name="ATTACK SURFACE MANAGEMENT (ASM) REPORT",
        report_type="ASM",
        description="",
        created_by=created_by,
        created_at=created_at,
        prepared_for=prepared_for,
        domain=domain,
        data={
            "assets_total": assets_total,
            "assets_list": assets_list,
            "vulnerabilities_total": vulnerabilities_total,
            "vulnerabilities": vuln_rows,
            "severity_counts": sev_counts,
            "avg_risk": avg_risk,
        },
    )

    filename = f"asm-report-{tenant}-{datetime.utcnow().strftime('%Y%m%d')}.pdf".replace(" ", "-")
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("")
def list_reports(
    claims: Dict[str, Any] = Depends(get_token_claims),
    db: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    tenant_users = get_tenant_usernames(db, claims)
    q = db.query(Report).filter(Report.created_by.in_(tenant_users)).order_by(Report.created_at.desc())
    rows = q.offset(offset).limit(limit).all()

    domain_ids = [r.domain_id for r in rows if r.domain_id]
    domains_by_id: Dict[Any, str] = {}
    if domain_ids:
        for d in db.query(Domain).filter(Domain.id.in_(domain_ids), Domain.created_by.in_(tenant_users)).all():
            domains_by_id[d.id] = d.domain_name

    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "id": str(r.id),
                "report_name": r.report_name,
                "report_type": r.report_type,
                "created_by": r.created_by,
                "created_at": (r.created_at or datetime.utcnow()).isoformat(),
                "domain_name": domains_by_id.get(r.domain_id) if r.domain_id else None,
                "minio_object_name": r.minio_object_name,
            }
        )
    return {"data": out, "limit": limit, "offset": offset}


@router.post("")
def create_report(
    req: CreateReportRequest,
    claims: Dict[str, Any] = Depends(get_token_claims),
    db: Session = Depends(get_db),
):
    tenant = str(claims.get("tenant") or "NexVeil").strip()
    prepared_for = str(claims.get("tenant") or tenant).strip()
    created_by = str(claims.get("sub") or claims.get("username") or "user").strip()
    created_at = datetime.utcnow()

    rtype_in = (req.report_type or "").strip().upper()
    # Per product naming:
    # - Executive Summary = narrative (previously called EXPOSURE_STORIES)
    # - Details Summary   = existing PDF (legacy ASM)
    if rtype_in in {"EXPOSURE_STORIES", "EXEC_SUMMARY", "EXECUTIVE_SUMMARY"}:
        variant = "EXEC_SUMMARY"
    elif rtype_in in {"ASM", "DETAILS_SUMMARY", "DETAIL_SUMMARY", "DETAILS_REPORT", "DETAIL_REPORT"}:
        variant = "DETAILS_REPORT"
    else:
        variant = rtype_in

    if variant not in {"EXEC_SUMMARY", "DETAILS_REPORT"}:
        raise HTTPException(status_code=400, detail="Invalid report_type. Use EXEC_SUMMARY or DETAILS_SUMMARY.")

    assessment = (req.assessment_type or "DOMAIN").strip().upper()
    # Backward compatibility: WEBSCAN maps to VULNERABILITY_SCAN
    if assessment == "WEBSCAN":
        assessment = "VULNERABILITY_SCAN"
    if assessment not in {"DOMAIN", "VULNERABILITY_SCAN", "API_TESTING", "NETWORK_SCAN"}:
        raise HTTPException(status_code=400, detail="Invalid assessment_type. Use DOMAIN, VULNERABILITY_SCAN, WEBSCAN, API_TESTING, or NETWORK_SCAN.")

    # Scope validation
    # Network scans target IPs (no associated Domain row), so domain_name
    # is not required for NETWORK_SCAN reports. Every other assessment
    # type still operates against a Domain.
    domain_obj: Optional[Domain] = None
    tenant_users = get_tenant_usernames(db, claims)
    if assessment != "NETWORK_SCAN":
        if not req.domain_name:
            raise HTTPException(status_code=400, detail="domain_name is required for reports.")
        domain_obj = (
            db.query(Domain)
            .filter(Domain.domain_name == req.domain_name, Domain.created_by.in_(tenant_users))
            .first()
        )
        if not domain_obj:
            raise HTTPException(status_code=404, detail="Domain not found.")

    cover_domain_line: Optional[str] = req.domain_name
    template: Dict[str, Any] = {}
    assets_list: List[str] = []
    assets_total = 0
    vuln_rows: List[Dict[str, Any]] = []
    sev_counts: Dict[str, int] = {}
    total_weight = 0

    if assessment == "DOMAIN":
        # Domain ASM: domain + subdomains + vulns under the domain
        domains = [domain_obj]
        domain_ids = [domain_obj.id]
        subdomains = (
            db.query(Subdomain)
            .filter(Subdomain.domain_id.in_(domain_ids))
            .order_by(Subdomain.created_at.desc())
            .all()
        )
        assets_list = [d.domain_name for d in domains] + [s.subdomain_name for s in subdomains]
        assets_total = len(assets_list)

        sub_by_id = {s.id: s.subdomain_name for s in subdomains if getattr(s, "id", None)}
        vulns = (
            db.query(Vulnerability)
            .filter(Vulnerability.domain_id.in_(domain_ids))
            .order_by(Vulnerability.id.desc())
            .all()
        )
        for v in vulns:
            sev = str(getattr(v, "severity", None) or "INFO").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            total_weight += _severity_weight(sev)
            sid = getattr(v, "subdomain_id", None)
            asset = sub_by_id.get(sid) if sid else None
            vuln_rows.append(
                {
                    "name": getattr(v, "vuln_name", None),
                    "description": getattr(v, "description", None),
                    "severity": sev,
                    "assets_impacted": 1,
                    "asset": asset or req.domain_name,
                }
            )

        template = {
            "cover_title": "ATTACK SURFACE MANAGEMENT\n(ASM) DETAILS REPORT",
        }

    elif assessment == "VULNERABILITY_SCAN":
        # Webscan (Subdomain): focus report on a single subdomain
        if not req.subdomain_name:
            raise HTTPException(status_code=400, detail="subdomain_name is required for VULNERABILITY_SCAN reports.")
        sub = (
            db.query(Subdomain)
            .filter(Subdomain.domain_id == domain_obj.id, Subdomain.subdomain_name == req.subdomain_name)
            .first()
        )
        if not sub:
            raise HTTPException(status_code=404, detail="Subdomain not found for the selected domain.")

        cover_domain_line = req.subdomain_name
        assets_list = [req.subdomain_name]
        assets_total = 1
        vulns = (
            db.query(Vulnerability)
            .filter(Vulnerability.subdomain_id == sub.id)
            .order_by(Vulnerability.id.desc())
            .all()
        )
        for v in vulns:
            sev = str(getattr(v, "severity", None) or "INFO").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            total_weight += _severity_weight(sev)
            vuln_rows.append(
                {
                    "name": getattr(v, "vuln_name", None),
                    "description": getattr(v, "description", None),
                    "severity": sev,
                    "assets_impacted": 1,
                    "asset": req.subdomain_name,
                }
            )
        template = {
            "cover_title": "VULNERABILITY_SCAN\n(SUBDOMAIN) DETAILS REPORT",
            "assets_intro": "This report summarizes web-facing exposure and vulnerabilities for the selected subdomain.",
            "assets_total_label": "TOTAL SUBDOMAINS",
            "assets_section_title": "Assets",
            "assets_table_title": "Subdomain",
        }

    elif assessment == "NETWORK_SCAN":
        # Network scan: scope by scan_id. Network scans don't link to Domain
        # rows, so we identify the source scan and pull every Vulnerability
        # whose tags include the matching `ip:` value plus a network plugin.
        if not req.scan_id:
            raise HTTPException(status_code=400, detail="scan_id is required for NETWORK_SCAN reports.")
        from app.database.models import Scan as _Scan
        scan = (
            db.query(_Scan)
            .filter(_Scan.id == req.scan_id, _Scan.created_by.in_(tenant_users))
            .first()
        )
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")
        if str(getattr(scan, "scan_type", "")).lower() != "network":
            raise HTTPException(status_code=400, detail="scan_id must reference a network scan.")

        # The network scan's target IP lives on its ScanResult.domain row.
        from app.database.models import ScanResult as _ScanResult
        sr = db.query(_ScanResult).filter(_ScanResult.scan_id == scan.id).first()
        target_ip = (sr.domain if sr else None) or "unknown-host"

        # Pull every Vulnerability tagged with this IP (added by the network
        # scanner persistence path in app/api/scans.py).
        from sqlalchemy.dialects.postgresql import ARRAY
        from sqlalchemy import String as _String, cast as _cast
        ip_tag = f"ip:{target_ip}"
        try:
            vulns = (
                db.query(Vulnerability)
                .filter(
                    Vulnerability.created_by.in_(tenant_users),
                    Vulnerability.tags.op("@>")(_cast([ip_tag], ARRAY(_String))),
                )
                .order_by(Vulnerability.id.desc())
                .all()
            )
        except Exception:
            # Tag-array containment isn't supported on this driver — fall back
            # to created_by + scan timing window.
            vulns = (
                db.query(Vulnerability)
                .filter(Vulnerability.created_by.in_(tenant_users))
                .order_by(Vulnerability.id.desc())
                .all()
            )
            vulns = [
                v for v in vulns
                if any(str(t) == ip_tag for t in (getattr(v, "tags", None) or []))
            ]

        cover_domain_line = target_ip
        assets_list = [target_ip]
        assets_total = 1
        for v in vulns:
            sev = str(getattr(v, "severity", None) or "INFO").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            total_weight += _severity_weight(sev)
            # Pull port from tags so the report shows IP:port for each finding.
            port = None
            for t in (getattr(v, "tags", None) or []):
                tag_str = str(t)
                if tag_str.startswith("port:"):
                    port = tag_str.split(":", 1)[1]
                    break
            asset_label = f"{target_ip}:{port}" if port else target_ip
            vuln_rows.append(
                {
                    "name": getattr(v, "vuln_name", None),
                    "description": getattr(v, "description", None),
                    "severity": sev,
                    "assets_impacted": 1,
                    "asset": asset_label,
                }
            )

        template = {
            "cover_title": "NETWORK SCAN\nDETAILS REPORT",
            "assets_intro": "This report summarizes network-layer exposures and service-level vulnerabilities for the scanned host.",
            "assets_total_label": "TOTAL HOSTS",
            "assets_section_title": "Host",
            "assets_table_title": "IP Address",
            "vuln_section_title": "Network Findings",
            "vuln_intro": "Findings produced by the network scanner plugins (open ports, banner disclosure, TLS audit, exposed databases, etc.).",
        }

    else:
        # API testing: build report from ApiScanReport (no raw endpoint lists in PDF)
        if not req.scan_id:
            raise HTTPException(status_code=400, detail="scan_id is required for API_TESTING reports.")
        from app.storage.minio_client import download_json
        from app.database.models import Scan, ApiScanReport
        import json as _json

        scan = db.query(Scan).filter(Scan.id == req.scan_id, Scan.created_by.in_(tenant_users)).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")
        if str(getattr(scan, "scan_type", "")).lower() != "api":
            raise HTTPException(status_code=400, detail="scan_id must reference an API scan.")

        api_report = db.query(ApiScanReport).filter(ApiScanReport.scan_id == scan.id).first()
        if not api_report:
            raise HTTPException(status_code=404, detail="API scan report not found.")

        report_obj: Dict[str, Any] = {}
        if getattr(api_report, "minio_object_name", None):
            try:
                report_obj = download_json(api_report.minio_object_name) or {}
            except Exception:
                report_obj = {}
        if not report_obj:
            try:
                report_obj = _json.loads(api_report.report_json or "{}")
            except Exception:
                report_obj = {}

        # Normalize wrapper shapes from storage (may be {result:{...}} or {result:{report:{...}}})
        report_data = report_obj
        if isinstance(report_data, dict) and isinstance(report_data.get("result"), dict):
            report_data = report_data.get("result") or report_data
        if isinstance(report_data, dict) and isinstance(report_data.get("report"), dict):
            report_data = report_data.get("report") or report_data

        # Use the actual target URL as the asset name, not the domain
        api_target_url = (
            report_data.get("base_url")
            or report_data.get("target_url")
            or report_data.get("target")
            or ""
        )
        if api_target_url:
            cover_domain_line = api_target_url

        total_endpoints = int(report_data.get("total_endpoints") or 0)
        findings = report_data.get("findings") or []
        if not isinstance(findings, list):
            findings = []

        # Build summarized rows and keep endpoint details for report tables.
        by_issue: Dict[str, Dict[str, Any]] = {}
        findings_rows: List[Dict[str, Any]] = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            issue = str(f.get("title") or f.get("issue") or f.get("name") or "Finding").strip() or "Finding"
            sev = str(f.get("severity") or "INFO").upper()
            endpoint = (
                f.get("endpoint")
                or f.get("path")
                or f.get("url")
                or f.get("endpoint_url")
                or ""
            )
            score = (
                f.get("cvss_score")
                or f.get("cvss")
                or f.get("score")
            )
            findings_rows.append(
                {
                    "endpoint": endpoint,
                    "issue": issue,
                    "severity": sev,
                    "score": score,
                    "description": f.get("description") or "",
                    "impact": f.get("impact") or "",
                    "remediation": f.get("remediation") or "",
                    "cvss_vector": f.get("cvss_vector") or f.get("vector") or "",
                    "confidence": f.get("confidence") or "",
                }
            )
            g = by_issue.setdefault(issue, {"count": 0, "severity": sev})
            g["count"] += 1
            # keep the worst severity for that issue
            if _severity_weight(sev) > _severity_weight(str(g.get("severity") or "INFO")):
                g["severity"] = sev

        # Assets section: do not list endpoints; only show totals.
        assets_list = []
        assets_total = total_endpoints

        for issue, g in sorted(by_issue.items(), key=lambda kv: (-_severity_weight(str(kv[1].get("severity"))), -int(kv[1].get("count") or 0), kv[0])):
            sev = str(g.get("severity") or "INFO").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + int(g.get("count") or 0)
            total_weight += _severity_weight(sev) * int(g.get("count") or 0)
            vuln_rows.append(
                {
                    "name": issue,
                    "description": None,
                    "severity": sev,
                    "assets_impacted": int(g.get("count") or 0),  # # endpoints flagged, without listing them
                    "asset": req.domain_name,
                }
            )

        template = {
            "cover_title": "API TESTING\nDETAILS REPORT",
            "assets_section_title": "API Inventory",
            "assets_intro": "This report summarizes API testing results for the selected scan. It intentionally avoids listing raw endpoints in the PDF.",
            "assets_total_label": "TOTAL ENDPOINTS",
            "assets_show_table": False,
            "vuln_section_title": "Findings",
            "vuln_intro": "This section summarizes issues identified during API testing. Endpoint paths are intentionally omitted; counts reflect the number of endpoints flagged per issue type.",
            "vuln_total_label": "TOTAL FINDINGS",
            "vuln_col_name": "Finding",
            "vuln_col_impacted": "Endpoints Flagged",
            "vuln_col_risk": "Risk",
        }

    vulnerabilities_total = len(vuln_rows)
    avg_risk = (total_weight / max(1, vulnerabilities_total)) if vulnerabilities_total else 0.0

    if variant == "EXEC_SUMMARY":
        if assessment == "DOMAIN":
            cover_title = "ATTACK SURFACE MANAGEMENT\n(ASM) EXECUTIVE SUMMARY"
            exec_intro = "This report summarizes external exposure patterns and priorities for leadership."
        elif assessment == "VULNERABILITY_SCAN":
            cover_title = "VULNERABILITY_SCAN\n(SUBDOMAIN) EXECUTIVE SUMMARY"
            exec_intro = "This report summarizes web-facing exposure patterns for the selected subdomain in a leadership-ready narrative."
        elif assessment == "NETWORK_SCAN":
            cover_title = "NETWORK SCAN\nEXECUTIVE SUMMARY"
            exec_intro = "This report summarizes network-layer exposure for the scanned host: open services, banner disclosure, weak TLS posture, and unauthenticated databases."
        else:
            cover_title = "API TESTING\nEXECUTIVE SUMMARY"
            exec_intro = "This report summarizes API testing results into decision-ready risk narratives. It avoids raw endpoint listings."
        pdf_bytes = _build_exposure_stories_pdf(
            tenant=tenant,
            report_name=req.report_name,
            description=(req.description or "").strip(),
            created_by=created_by,
            created_at=created_at,
            domain=cover_domain_line,
            assets_list=assets_list,
            vuln_rows=vuln_rows,
            cover_title=cover_title,
            executive_intro=exec_intro,
        )
    else:
        # API testing uses the details-style template requested by the user.
        if assessment == "API_TESTING":
            pdf_bytes = _build_api_details_pdf(
                tenant=tenant,
                report_name=req.report_name,
                description=(req.description or "").strip(),
                created_by=created_by,
                created_at=created_at,
                domain=cover_domain_line,
                total_endpoints=assets_total,
                vulnerabilities_total=vulnerabilities_total,
                severity_counts=sev_counts,
                findings_rows=findings_rows,
            )
        else:
            # Keep existing layout, adjust labels per assessment type.
            pdf_bytes = _build_asm_pdf(
                tenant=tenant,
                report_name=req.report_name,
                report_type="ASM",
                description=(req.description or "").strip(),
                created_by=created_by,
                created_at=created_at,
                prepared_for=prepared_for,
                domain=cover_domain_line,
                data={
                    "assets_total": assets_total,
                    "assets_list": assets_list,
                    "vulnerabilities_total": vulnerabilities_total,
                    "vulnerabilities": vuln_rows,
                    "severity_counts": sev_counts,
                    "avg_risk": avg_risk,
                },
                template=template,
            )

    report_id = uuid.uuid4()
    stored_type = f"{assessment}_{variant}"
    object_name = f"reports/{tenant}/{assessment.lower()}/{variant.lower()}/{report_id}.pdf"

    bucket, obj = "", ""
    if is_minio_configured():
        try:
            bucket, obj = upload_bytes_to_minio(pdf_bytes, object_name=object_name, content_type="application/pdf")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        # Local file fallback when MinIO is not available
        local_path = _LOCAL_REPORTS_DIR / f"{report_id}.pdf"
        local_path.write_bytes(pdf_bytes)
        obj = f"local:{report_id}.pdf"

    rec = Report(
        id=report_id,
        report_name=req.report_name,
        report_type=stored_type,
        # enforce 200-char limit at storage too
        description=(req.description[:200] if req.description else None),
        # domain_id is nullable — network scans target IPs and have no Domain row.
        domain_id=domain_obj.id if domain_obj is not None else None,
        created_by=created_by,
        created_at=created_at,
        minio_bucket=bucket,
        minio_object_name=obj,
    )
    db.add(rec)
    db.commit()

    return {"id": str(report_id)}


@router.get("/{report_id}/download")
def download_report_pdf(
    report_id: str,
    claims: Dict[str, Any] = Depends(get_token_claims),
    db: Session = Depends(get_db),
):
    tenant_users = get_tenant_usernames(db, claims)
    rec = db.query(Report).filter(Report.id == report_id, Report.created_by.in_(tenant_users)).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Report not found.")
    if not rec.minio_object_name:
        raise HTTPException(status_code=404, detail="Report file not available.")

    filename = f"{(rec.report_name or 'report').strip().replace(' ', '-')}.pdf"

    # Local file fallback
    if rec.minio_object_name.startswith("local:"):
        local_file = _LOCAL_REPORTS_DIR / rec.minio_object_name.removeprefix("local:")
        if not local_file.exists():
            raise HTTPException(status_code=404, detail="Report file not found on disk.")
        return StreamingResponse(
            open(local_file, "rb"),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    if not object_exists(rec.minio_object_name):
        raise HTTPException(status_code=404, detail="Report file not found in MinIO.")

    resp = get_object_stream(rec.minio_object_name)
    return StreamingResponse(
        resp,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

