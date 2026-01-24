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

from app.api.auth import get_token_claims
from app.database.models import Domain, Report, Subdomain, Vulnerability
from app.database.session import get_db
from app.storage.minio_client import upload_bytes_to_minio, get_object_stream, object_exists, MINIO_BUCKET


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

    # Keep the cover + section styling identical to the existing ASM PDF.
    # (No new detections; this is purely a presentation layer.)
    logo_path = Path(__file__).resolve().parent.parent / "swagger" / "secoraa.jpg"

    def section_header(title: str):
        top_y = 10
        logo_w = 22
        if logo_path.exists():
            pdf.image(str(logo_path), x=10, y=top_y, w=logo_w)
            title_y = top_y + logo_w + 8
        else:
            pdf.set_xy(10, top_y + 2)
            pdf.set_font("Helvetica", "B", 16)
            pdf.set_text_color(20, 40, 80)
            pdf.cell(0, 8, _safe_pdf_text("Secoraa"), ln=1)
            title_y = top_y + 18

        pdf.set_xy(10, title_y)
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(20, 40, 80)
        pdf.cell(0, 10, _safe_pdf_text(title), ln=1)
        pdf.set_text_color(0, 0, 0)

        pdf.set_draw_color(225, 225, 225)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(6)

    def footer(*, dark: bool = False):
        pdf.set_y(-23)
        pdf.set_font("Helvetica", "", 8)
        if dark:
            pdf.set_text_color(200, 200, 200)
        else:
            pdf.set_text_color(120, 120, 120)
        left = _safe_pdf_text(f"Copyright {datetime.utcnow().year} {tenant}. All Rights Reserved")
        page_no = pdf.page_no() if hasattr(pdf, "page_no") else 1
        right = _safe_pdf_text(f"Page {page_no} / {{nb}}")
        pdf.cell(150, 6, left, 0, 0, "L")
        pdf.cell(40, 6, right, 0, 0, "R")
        pdf.set_text_color(0, 0, 0)

    # -------------------------
    # Cover page (IDENTICAL styling to existing ASM PDF)
    # -------------------------
    pdf.set_auto_page_break(auto=False, margin=14)
    pdf.add_page()
    pdf.set_fill_color(6, 16, 26)
    pdf.rect(0, 0, 210, 297, style="F")

    if logo_path.exists():
        pdf.image(str(logo_path), x=12, y=18, w=55)

    # Device mock (same as existing)
    pdf.set_draw_color(220, 220, 220)
    pdf.set_fill_color(12, 28, 45)
    pdf.rect(122, 22, 76, 50, style="DF")
    pdf.set_fill_color(8, 20, 34)
    pdf.rect(126, 26, 68, 42, style="F")
    pdf.set_draw_color(34, 197, 94)
    for i, h in enumerate([10, 18, 14, 22, 12]):
        x = 132 + i * 8
        pdf.line(x, 66, x, 66 - h)
    pdf.set_draw_color(220, 220, 220)

    # Same cover style as the existing report, but clearly labeled for leadership.
    pdf.set_xy(12, 92)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(249, 115, 22)
    pdf.multi_cell(0, 12, _safe_pdf_text(cover_title or "ATTACK SURFACE MANAGEMENT\n(ASM) EXECUTIVE SUMMARY"))

    # Green separator line
    pdf.set_draw_color(34, 197, 94)
    pdf.set_line_width(1.2)
    pdf.line(12, pdf.get_y() + 2, 110, pdf.get_y() + 2)
    pdf.set_line_width(0.2)

    # Prepared for block (same spacing logic as existing report)
    cover_block_shift_mm = 30
    base_x = 12
    move_other_up_mm = 20
    y = (235 - cover_block_shift_mm) - move_other_up_mm

    pdf.set_xy(base_x, y)
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(230, 230, 230)
    pdf.cell(0, 8, _safe_pdf_text("Prepared for"), 0, 1, "L")
    y += 12

    pdf.set_xy(base_x, y)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(249, 115, 22)
    pdf.cell(0, 12, _safe_pdf_text(tenant), 0, 1, "L")
    y += 16

    if domain:
        pdf.set_xy(base_x, y)
        pdf.set_font("Helvetica", "", 18)
        pdf.set_text_color(230, 230, 230)
        pdf.cell(0, 10, _safe_pdf_text(domain), 0, 1, "L")
        y += 18

    if description:
        pdf.set_xy(base_x, y)
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(200, 200, 200)
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
    pdf.set_text_color(230, 230, 230)
    pdf.cell(0, 8, _safe_pdf_text(f"Generated on {created_at.strftime('%m-%d-%Y')}"), 0, 0, "L")
    footer(dark=True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_auto_page_break(auto=True, margin=14)

    # -------------------------
    # Executive summary (short)
    # -------------------------
    pdf.add_page()
    section_header("Executive Summary")
    pdf.set_font("Helvetica", "", 11)

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
    pdf.cell(0, 8, _safe_pdf_text("How we prioritized"), ln=1)
    pdf.set_font("Helvetica", "", 11)
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
        pdf.set_text_color(20, 40, 80)
        pdf.multi_cell(0, 7, _safe_pdf_text(tpl["title"]))
        pdf.set_text_color(0, 0, 0)

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(10)
        pdf.cell(0, 6, _safe_pdf_text("What was found"), ln=1)
        pdf.set_font("Helvetica", "", 11)
        examples = g.get("examples") or []
        ex_text = ", ".join(examples[:3]) + (f" (+{max(0, len(examples)-3)} more)" if len(examples) > 3 else "")
        pdf.set_x(10)
        pdf.multi_cell(0, 6, _safe_pdf_text(f"{g.get('count')} related finding(s). Example asset(s): {ex_text or '-'}"))

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(10)
        pdf.cell(0, 6, _safe_pdf_text("Why it matters"), ln=1)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_x(10)
        pdf.multi_cell(0, 6, _safe_pdf_text(tpl["why"]))

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(10)
        pdf.cell(0, 6, _safe_pdf_text("What could happen if abused"), ln=1)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_x(10)
        pdf.multi_cell(0, 6, _safe_pdf_text(tpl["what_could_happen"]))

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(10)
        pdf.cell(0, 6, _safe_pdf_text("Who should care"), ln=1)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_x(10)
        pdf.multi_cell(0, 6, _safe_pdf_text(tpl["who"]))

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(10)
        pdf.cell(0, 6, _safe_pdf_text("Next action (specific)"), ln=1)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_x(10)
        pdf.multi_cell(0, 6, _safe_pdf_text(tpl["next"]))

        footer()

    # -------------------------
    # Supporting details (minimal)
    # -------------------------
    pdf.add_page()
    section_header("Supporting Technical Details")
    pdf.set_font("Helvetica", "", 11)
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
    pdf.set_fill_color(245, 245, 245)
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
        pdf.cell(80, 7, _safe_pdf_text(name), 1, 0)
        pdf.cell(20, 7, _safe_pdf_text(str(g.get("count") or 0)), 1, 0, "C")
        pdf.cell(90, 7, _safe_pdf_text(ex or "-"), 1, 1)

    footer()

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

    logo_path = Path(__file__).resolve().parent.parent / "swagger" / "secoraa.jpg"

    def section_header(title: str):
        """
        White-page header like the sample: logo on left + section title.
        """
        top_y = 10
        logo_w = 22  # keep small so it never collides with title
        if logo_path.exists():
            # Keep small in header
            pdf.image(str(logo_path), x=10, y=top_y, w=logo_w)
            title_y = top_y + logo_w + 8
        else:
            pdf.set_xy(10, top_y + 2)
            pdf.set_font("Helvetica", "B", 16)
            pdf.set_text_color(20, 40, 80)
            pdf.cell(0, 8, _safe_pdf_text("Secoraa"), ln=1)
            title_y = top_y + 18

        pdf.set_xy(10, title_y)
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(20, 40, 80)
        pdf.cell(0, 10, _safe_pdf_text(title), ln=1)
        pdf.set_text_color(0, 0, 0)

        pdf.set_draw_color(225, 225, 225)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(6)

    def footer(*, dark: bool = False):
        """
        IMPORTANT: don't print near the bottom margin while auto page-break is enabled,
        otherwise FPDF will silently add a new blank page.
        """
        pdf.set_y(-23)  # keep safely above page-break trigger (A4 height 297mm, margin 14mm)
        pdf.set_font("Helvetica", "", 8)
        if dark:
            pdf.set_text_color(200, 200, 200)
        else:
            pdf.set_text_color(120, 120, 120)

        left = _safe_pdf_text(f"Copyright {datetime.utcnow().year} {tenant}. All Rights Reserved")
        page_no = pdf.page_no() if hasattr(pdf, "page_no") else 1
        # {nb} will be replaced by total pages if alias_nb_pages is supported
        right = _safe_pdf_text(f"Page {page_no} / {{nb}}")
        pdf.cell(150, 6, left, 0, 0, "L")
        pdf.cell(40, 6, right, 0, 0, "R")
        pdf.set_text_color(0, 0, 0)

    def summary_card(*, x: float, y: float, w: float, h: float, value: str, label: str):
        """
        A light summary card similar to the sample (big number + diagonal accent + label).
        """
        pdf.set_draw_color(230, 233, 238)
        pdf.set_fill_color(248, 250, 252)
        pdf.rect(x, y, w, h, style="DF")

        # Accent icon square
        pdf.set_fill_color(255, 237, 213)  # light orange
        pdf.rect(x + 8, y + 10, 12, 12, style="F")

        # Value
        pdf.set_xy(x + 26, y + 8)
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(249, 115, 22)
        pdf.cell(0, 12, _safe_pdf_text(value))

        # Diagonal line accent
        pdf.set_draw_color(249, 115, 22)
        pdf.line(x + 6, y + h - 16, x + w, y + h - 34)

        # Label
        pdf.set_xy(x + 10, y + h - 12)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(20, 40, 80)
        pdf.cell(0, 8, _safe_pdf_text(label))
        pdf.set_text_color(0, 0, 0)

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
        Card with a semi-circle gauge + big value, similar to the screenshot.
        """
        # Card background
        pdf.set_draw_color(230, 233, 238)
        pdf.set_fill_color(248, 250, 252)
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
        pdf.set_draw_color(31, 41, 55)
        pdf.set_line_width(1.2)
        pdf.line(cx, cy, nx, ny)
        pdf.set_fill_color(31, 41, 55)
        pdf.ellipse(cx - 2.2, cy - 2.2, 4.4, 4.4, style="F")
        pdf.set_line_width(0.2)

        # Value
        pdf.set_xy(x, y + 22)
        pdf.set_font("Helvetica", "B", 40)
        pdf.set_text_color(37, 99, 235)
        pdf.cell(w, 18, _safe_pdf_text(f"{v:.1f}"), 0, 1, "C")
        pdf.set_text_color(0, 0, 0)

        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(20, 40, 80)
        pdf.set_xy(x + 10, y + h - 16)
        pdf.cell(w - 20, 8, _safe_pdf_text("OVERALL RISK"), 0, 0, "L")
        pdf.set_text_color(0, 0, 0)

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
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(35, 35, 35)
        pdf.multi_cell(
            0,
            6,
            _safe_pdf_text(
                str((template or {}).get("assets_intro") or (
                    f"{tenant} ran its scans to find the known and unknown assets below. "
                    "Assets include Domains, Subdomains, IP Addresses, and URLs for your team's reference."
                ))
            ),
        )
        pdf.set_text_color(0, 0, 0)
        pdf.ln(4)

        summary_card(
            x=10,
            y=52,
            w=190,
            h=52,
            value=str(total_assets),
            label=str((template or {}).get("assets_total_label") or "TOTAL ASSETS"),
        )

        if (template or {}).get("assets_show_table") is False:
            footer()
            return

        # Table card rendering (paginated)
        def start_table_page(table_y: float):
            pdf.set_draw_color(230, 233, 238)
            pdf.set_fill_color(248, 250, 252)
            # Fill down to just above footer zone
            card_h = 268 - table_y
            if card_h < 90:
                card_h = 90
            pdf.rect(10, table_y, 190, card_h, style="DF")

            pdf.set_xy(16, table_y + 8)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(20, 40, 80)
            pdf.cell(0, 8, _safe_pdf_text(str((template or {}).get("assets_table_title") or "Assets")))
            pdf.ln(10)

            pdf.set_x(16)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(55, 65, 81)
            pdf.cell(0, 7, _safe_pdf_text(str((template or {}).get("assets_table_col_name") or "Name")))
            pdf.set_draw_color(200, 200, 200)
            pdf.line(16, pdf.get_y() + 1, 194, pdf.get_y() + 1)
            pdf.ln(6)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 11)

        start_table_page(112)

        left_x = 16
        right_x = 194
        max_w = right_x - left_x
        row_h = 8
        bottom_y = 268  # keep above footer

        if not assets:
            pdf.set_x(left_x)
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, row_h, _safe_pdf_text("No assets available."), ln=1)
            pdf.set_text_color(0, 0, 0)
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
            pdf.set_text_color(17, 24, 39)

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
            pdf.set_draw_color(220, 220, 220)
            pdf.line(left_x, y, right_x, y)

        footer()

    def vulnerabilities_pages(vuln_rows: List[Dict[str, Any]], vulnerabilities_total: int):
        """
        Render vulnerabilities table across pages to avoid overlaps.
        """
        pdf.add_page()
        section_header(str((template or {}).get("vuln_section_title") or "Vulnerabilities"))
        pdf.set_font("Helvetica", "", 10)
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
            pdf.set_fill_color(245, 245, 245)
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
            pdf.cell(110, 7, _safe_pdf_text(name[:90]), 1, 0)
            pdf.cell(40, 7, _safe_pdf_text(assets_imp), 1, 0, "C")
            pdf.cell(40, 7, _safe_pdf_text(risk), 1, 1, "C")

        footer()

    # -------------------------
    # Cover page
    # -------------------------
    # Disable auto-page-break for cover to prevent accidental blank pages being inserted
    pdf.set_auto_page_break(auto=False, margin=14)
    pdf.add_page()
    # Full-page dark background (black theme)
    pdf.set_fill_color(6, 16, 26)  # near-black/navy
    pdf.rect(0, 0, 210, 297, style="F")

    # Brand: use local Secoraa logo if available; otherwise render text (top-left like sample)
    logo_path = Path(__file__).resolve().parent.parent / "swagger" / "secoraa.jpg"
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
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 10, _safe_pdf_text("Secoraa"), ln=1, align="L")

    # Device mock (right side) to mimic sample cover without needing an image
    # Outer frame
    pdf.set_draw_color(220, 220, 220)
    pdf.set_fill_color(12, 28, 45)
    # keep aligned with brand area
    pdf.rect(122, 22, 76, 50, style="DF")
    # Inner screen
    pdf.set_fill_color(8, 20, 34)
    pdf.rect(126, 26, 68, 42, style="F")
    # Small chart bars
    pdf.set_draw_color(34, 197, 94)  # green accent
    for i, h in enumerate([10, 18, 14, 22, 12]):
        x = 132 + i * 8
        pdf.line(x, 66, x, 66 - h)
    pdf.set_draw_color(220, 220, 220)

    # Title (orange) like sample
    pdf.set_xy(12, 92)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(249, 115, 22)  # orange
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
    pdf.set_text_color(230, 230, 230)
    pdf.cell(0, 8, _safe_pdf_text("Prepared for"), 0, 1, "L")
    # tighter gap between "Prepared for" and org name
    y += 12

    # Org name
    pdf.set_xy(base_x, y)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(249, 115, 22)
    pdf.cell(0, 12, _safe_pdf_text(prepared_for or tenant), 0, 1, "L")
    y += 16

    # Domain
    if domain:
        pdf.set_xy(base_x, y)
        pdf.set_font("Helvetica", "", 18)
        pdf.set_text_color(230, 230, 230)
        pdf.cell(0, 10, _safe_pdf_text(domain), 0, 1, "L")
        y += 18

    # Description (<=150 chars) below domain with consistent spacing
    if description:
        pdf.set_xy(base_x, y)
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(200, 200, 200)
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
    pdf.set_text_color(230, 230, 230)
    pdf.cell(0, 8, _safe_pdf_text(f"Generated on {created_at.strftime('%m-%d-%Y')}"), 0, 0, "L")
    footer(dark=True)
    pdf.set_text_color(0, 0, 0)
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
    pdf.set_text_color(35, 35, 35)
    pdf.multi_cell(
        0,
        6,
        _safe_pdf_text(
            "The Secoraa team analyzed your assets and vulnerabilities. "
            "The overall risk value is derived from the severities found."
        ),
    )
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    y0 = pdf.get_y()
    # Left: gauge card
    risk_gauge_card(x=10, y=y0, w=95, h=70, value=avg_risk)

    # Right: Point (2) as a table (instead of bullets)
    tx = 110
    ty = y0
    tw = 90
    th = 70
    pdf.set_draw_color(230, 233, 238)
    pdf.set_fill_color(248, 250, 252)
    pdf.rect(tx, ty, tw, th, style="DF")
    pdf.set_xy(tx + 8, ty + 8)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(20, 40, 80)
    pdf.cell(0, 6, _safe_pdf_text("Notes"), ln=1)
    pdf.set_text_color(0, 0, 0)

    notes = [
        "This chart contains overall risk value.",
        "Value range is between 0 to 100.",
        "It is average value of all the CVSS score collected from all the assets.",
    ]
    pdf.set_font("Helvetica", "", 10)
    y_notes = ty + 20
    for n in notes:
        pdf.set_xy(tx + 8, y_notes)
        pdf.multi_cell(tw - 16, 5, _safe_pdf_text(n))
        y_notes = pdf.get_y() + 2

    # Vulnerabilities by Risk (table) under the cards
    pdf.set_y(y0 + 78)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(20, 40, 80)
    pdf.cell(0, 8, _safe_pdf_text("Vulnerabilities by Risk"), ln=1)
    pdf.set_text_color(0, 0, 0)

    pdf.set_fill_color(225, 241, 255)
    pdf.set_draw_color(180, 210, 245)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(60, 8, _safe_pdf_text("Severity"), 1, 0, "L", True)
    pdf.cell(30, 8, _safe_pdf_text("Count"), 1, 1, "C", True)
    pdf.set_font("Helvetica", "", 11)
    for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        pdf.cell(60, 8, _safe_pdf_text(k), 1, 0, "L")
        pdf.cell(30, 8, _safe_pdf_text(str(int(sev_counts.get(k, 0)))), 1, 1, "C")

    footer()

    # (3) Hardcoded severity explanation table (new page)
    pdf.add_page()
    section_header("Risk Legend")
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(20, 40, 80)
    pdf.cell(0, 8, _safe_pdf_text("Risk level definitions"), ln=1)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)

    legend_rows = [
        ("CRITICAL", "Critical risk vulnerabilities could be expected to have a very high threat to a company's data and should be fixed as a top-priority basis. Critical vulnerabilities can allow a hacker to compromise the environment or cause other severe impacts."),
        ("HIGH", "High risk vulnerabilities could be expected to have a catastrophic adverse effect on organizational operations, organizational assets, or individuals."),
        ("MEDIUM", "Medium risk vulnerabilities could be expected to have a serious adverse effect on organizational operations, organizational assets, or individuals."),
        ("LOW", "These are security issues that do not functionally alter normal systems behavior, but which may aid or enable further attacks against the system under other circumstances. Vulnerabilities may not violate either the system's security model or any security objectives."),
    ]

    pdf.set_fill_color(225, 241, 255)
    pdf.set_draw_color(180, 210, 245)
    pdf.set_font("Helvetica", "B", 11)
    x0 = 10
    sev_w = 35
    desc_w = 155
    header_h = 10
    line_h = 5.5
    pad = 2.5
    min_row_h = 22
    bottom_y = 268  # keep above footer zone

    def legend_table_header():
        pdf.set_fill_color(225, 241, 255)
        pdf.set_draw_color(180, 210, 245)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_x(x0)
        pdf.cell(sev_w, header_h, _safe_pdf_text("Severity"), 1, 0, "L", True)
        pdf.cell(desc_w, header_h, _safe_pdf_text("Description"), 1, 1, "L", True)
        pdf.set_font("Helvetica", "", 10)

    legend_table_header()

    for sev, desc in legend_rows:
        # Wrap description to fit inside cell with padding; cap lines to keep table tidy.
        # IMPORTANT: render lines manually to avoid "justified" word spacing and overflow.
        desc_text = clamp_text_lines(desc, max_width_mm=(desc_w - pad * 2), max_lines=6)
        desc_lines = desc_text.split("\n")
        row_h = max(min_row_h, (pad * 2) + (line_h * len(desc_lines)))

        # Page break if needed
        if pdf.get_y() + row_h > bottom_y:
            footer()
            pdf.add_page()
            section_header("Risk Legend")
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(20, 40, 80)
            pdf.cell(0, 8, _safe_pdf_text("Risk level definitions (continued)"), ln=1)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)
            legend_table_header()

        y_row = pdf.get_y()

        # Draw cell borders first (so we control a single clean border per cell)
        pdf.set_draw_color(180, 210, 245)
        pdf.rect(x0, y_row, sev_w, row_h)
        pdf.rect(x0 + sev_w, y_row, desc_w, row_h)

        # Severity text (vertically centered-ish)
        pdf.set_xy(x0 + 2, y_row + (row_h / 2) - 4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(sev_w - 4, 8, _safe_pdf_text(sev), 0, 0, "L")

        # Description text (manual line rendering, always left aligned)
        pdf.set_font("Helvetica", "", 10)
        x_text = x0 + sev_w + pad
        y_text = y_row + pad
        max_lines_fit = int((row_h - pad * 2) / line_h) if line_h > 0 else len(desc_lines)
        for i, line in enumerate(desc_lines[:max_lines_fit]):
            pdf.set_xy(x_text, y_text + i * line_h)
            pdf.cell(desc_w - (pad * 2), line_h, _safe_pdf_text(line), 0, 0, "L")

        # Move cursor to next row start
        pdf.set_y(y_row + row_h)

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
    assessment_type: str = Field(default="DOMAIN", description="DOMAIN|WEBSCAN|API_TESTING")
    subdomain_name: Optional[str] = Field(default=None, description="Required for WEBSCAN reports")
    scan_id: Optional[str] = Field(default=None, description="Required for API_TESTING reports (scan_id of an API scan)")


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
    tenant = str(claims.get("tenant") or "Secoraa").strip()
    prepared_for = str(claims.get("tenant") or tenant).strip()
    created_by = str(claims.get("sub") or claims.get("username") or "user").strip()
    created_at = datetime.utcnow()

    # Assets
    domain_q = db.query(Domain)
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
    q = db.query(Report).order_by(Report.created_at.desc())
    rows = q.offset(offset).limit(limit).all()

    domain_ids = [r.domain_id for r in rows if r.domain_id]
    domains_by_id: Dict[Any, str] = {}
    if domain_ids:
        for d in db.query(Domain).filter(Domain.id.in_(domain_ids)).all():
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
    tenant = str(claims.get("tenant") or "Secoraa").strip()
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
    if assessment not in {"DOMAIN", "WEBSCAN", "API_TESTING"}:
        raise HTTPException(status_code=400, detail="Invalid assessment_type. Use DOMAIN, WEBSCAN, or API_TESTING.")

    # Scope validation
    domain_obj: Optional[Domain] = None
    if not req.domain_name:
        raise HTTPException(status_code=400, detail="domain_name is required for reports.")
    domain_obj = db.query(Domain).filter(Domain.domain_name == req.domain_name).first()
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

    elif assessment == "WEBSCAN":
        # Webscan (Subdomain): focus report on a single subdomain
        if not req.subdomain_name:
            raise HTTPException(status_code=400, detail="subdomain_name is required for WEBSCAN reports.")
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
            "cover_title": "WEBSCAN\n(SUBDOMAIN) DETAILS REPORT",
            "assets_intro": "This report summarizes web-facing exposure and vulnerabilities for the selected subdomain.",
            "assets_total_label": "TOTAL SUBDOMAINS",
            "assets_section_title": "Assets",
            "assets_table_title": "Subdomain",
        }

    else:
        # API testing: build report from ApiScanReport (no raw endpoint lists in PDF)
        if not req.scan_id:
            raise HTTPException(status_code=400, detail="scan_id is required for API_TESTING reports.")
        from app.storage.minio_client import download_json
        from app.database.models import Scan, ApiScanReport
        import json as _json

        scan = db.query(Scan).filter(Scan.id == req.scan_id).first()
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

        total_endpoints = int(report_obj.get("total_endpoints") or 0)
        findings = report_obj.get("findings") or []
        if not isinstance(findings, list):
            findings = []

        # Build summarized rows WITHOUT including endpoint paths.
        by_issue: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            if not isinstance(f, dict):
                continue
            issue = str(f.get("issue") or f.get("name") or "Finding").strip() or "Finding"
            sev = str(f.get("severity") or "INFO").upper()
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
        cover_title = (
            "ATTACK SURFACE MANAGEMENT\n(ASM) EXECUTIVE SUMMARY"
            if assessment == "DOMAIN"
            else "WEBSCAN\n(SUBDOMAIN) EXECUTIVE SUMMARY"
            if assessment == "WEBSCAN"
            else "API TESTING\nEXECUTIVE SUMMARY"
        )
        exec_intro = (
            "This report summarizes external exposure patterns and priorities for leadership."
            if assessment == "DOMAIN"
            else "This report summarizes web-facing exposure patterns for the selected subdomain in a leadership-ready narrative."
            if assessment == "WEBSCAN"
            else "This report summarizes API testing results into decision-ready risk narratives. It avoids raw endpoint listings."
        )
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
    try:
        bucket, obj = upload_bytes_to_minio(pdf_bytes, object_name=object_name, content_type="application/pdf")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    rec = Report(
        id=report_id,
        report_name=req.report_name,
        report_type=stored_type,
        # enforce 200-char limit at storage too
        description=(req.description[:200] if req.description else None),
        domain_id=domain_obj.id,
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
    rec = db.query(Report).filter(Report.id == report_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Report not found.")
    if not rec.minio_object_name:
        raise HTTPException(status_code=404, detail="Report file not available.")
    if not object_exists(rec.minio_object_name):
        raise HTTPException(status_code=404, detail="Report file not found in MinIO.")

    resp = get_object_stream(rec.minio_object_name)
    filename = f"{(rec.report_name or 'report').strip().replace(' ', '-')}.pdf"
    return StreamingResponse(
        resp,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

