import json

try:
    # fpdf2 provides `from fpdf import FPDF`
    from fpdf import FPDF  # type: ignore
except Exception:  # pragma: no cover
    FPDF = None


def export_json(report: dict, path="report.json"):
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path


def export_pdf(report: dict, path="report.pdf"):
    if FPDF is None:
        raise RuntimeError(
            "PDF export dependency missing. Install `fpdf2` to enable PDF export."
        )
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)

    for key, value in report.items():
        pdf.multi_cell(0, 8, f"{key}: {value}")

    pdf.output(path)
    return path
