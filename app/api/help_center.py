from __future__ import annotations

import math
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.auth import get_token_claims


router = APIRouter(prefix="/help", tags=["Help"], dependencies=[Depends(get_token_claims)])


class AskRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=500)
    max_sources: int = Field(default=3, ge=1, le=8)


class SourceRow(BaseModel):
    page: int
    title: Optional[str] = None
    excerpt: str


class AskResponse(BaseModel):
    answer: str
    sources: List[SourceRow]


def _safe_text(s: str) -> str:
    # Normalize whitespace, keep readable
    s = (s or "").replace("\r", " ").replace("\t", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _tokenize(text: str) -> List[str]:
    t = (text or "").lower()
    # keep only alnum tokens, drop very short
    toks = re.findall(r"[a-z0-9]{2,}", t)
    # mild stopwording (tiny list; keep it simple)
    stop = {
        "the", "and", "for", "with", "that", "this", "from", "into", "then", "than",
        "your", "you", "are", "was", "were", "will", "can", "how", "what", "where",
        "when", "page", "scan", "scans",
    }
    return [x for x in toks if x not in stop]


def _unescape_pdf_literal(s: str) -> str:
    # Handle our generator's escaping: \( \) \\  and common sequences.
    out = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt in ("\\", "(", ")"):
                out.append(nxt)
                i += 2
                continue
            # ignore unknown escape as literal next
            out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_Tj_RE = re.compile(r"\((?:\\.|[^\\()])*\)\s*Tj")


def _extract_pdf_text_lines(pdf_bytes: bytes) -> List[str]:
    """
    Extract text from our simple PDF by pulling literal strings used in `(...) Tj`.
    This is NOT a generic PDF parser; it's intentionally scoped to the generated docs PDF.
    """
    try:
        s = pdf_bytes.decode("latin-1", errors="ignore")
    except Exception:
        s = str(pdf_bytes)

    lines: List[str] = []
    for m in _Tj_RE.finditer(s):
        literal = m.group(0)
        # literal looks like "(... ) Tj" - find inside first (...) pair
        start = literal.find("(")
        end = literal.rfind(")")
        if start == -1 or end == -1 or end <= start:
            continue
        raw = literal[start + 1 : end]
        txt = _safe_text(_unescape_pdf_literal(raw))
        if txt:
            lines.append(txt)
    return lines


@dataclass(frozen=True)
class _DocSection:
    page: int
    title: Optional[str]
    text: str  # full page text (readable)


@dataclass(frozen=True)
class _Chunk:
    """
    Retrieval chunk for RAG-like behavior (BM25 over chunks).
    """
    page: int
    section_title: Optional[str]
    chunk_title: Optional[str]
    text: str


def _build_sections(lines: List[str]) -> List[_DocSection]:
    """
    Split extracted lines into per-page sections using the footer marker "Page X / Y".
    """
    sections: List[_DocSection] = []
    cur_lines: List[str] = []
    cur_page: Optional[int] = None

    page_re = re.compile(r"^Page\s+(\d+)\s*/\s*(\d+)$", re.IGNORECASE)

    def flush():
        nonlocal cur_lines, cur_page
        if cur_page is None:
            cur_lines = []
            return
        # Determine title: first non-empty line that is not the global footer label
        title = None
        for l in cur_lines:
            if l.lower().startswith("secoraa asm platform - user flows"):
                continue
            title = l
            break
        text = "\n".join([l for l in cur_lines if not l.lower().startswith("secoraa asm platform - user flows")])
        sections.append(_DocSection(page=cur_page, title=title, text=text.strip()))
        cur_lines = []
        cur_page = None

    for l in lines:
        m = page_re.match(l)
        if m:
            # footer line; set current page and flush page on seeing footer
            try:
                page_num = int(m.group(1))
            except Exception:
                page_num = None
            # if we didn't know the page yet, set it now
            if cur_page is None and page_num is not None:
                cur_page = page_num
            # include footer? no
            flush()
            continue

        # Accumulate; if page not known yet, we'll attach when we hit footer (page line)
        cur_lines.append(l)

    # If last page didn't flush (shouldn't happen), best effort ignore.
    return sections


def _split_into_chunks(sections: List[_DocSection]) -> List[_Chunk]:
    """
    Split each page into smaller "flow" chunks to improve retrieval quality.
    Heuristics:
    - A chunk often starts with a short title line followed by a 'Path:' line.
    - We then include subsequent bullet lines starting with '- ' until next title/path.
    If heuristics fail, we fall back to a single chunk per page.
    """
    chunks: List[_Chunk] = []

    def is_path(l: str) -> bool:
        return l.lower().startswith("path:")

    def is_bullet(l: str) -> bool:
        return l.startswith("- ")

    def looks_like_title(l: str) -> bool:
        if not l:
            return False
        low = l.lower()
        if low.startswith("path:") or low.startswith("notes") or low.startswith("- "):
            return False
        # avoid footer-like lines
        if low.startswith("secoraa asm platform"):
            return False
        # Titles are usually short-ish and not sentencey
        if len(l) > 70:
            return False
        # Prefer lines with letters
        return bool(re.search(r"[a-zA-Z]", l))

    for sec in sections:
        lines = [x.strip() for x in sec.text.split("\n")]
        lines = [x for x in lines if x]
        if not lines:
            continue

        i = 0
        emitted_any = False
        while i < len(lines):
            # Look for "Title" + "Path:" pattern
            if looks_like_title(lines[i]) and i + 1 < len(lines) and is_path(lines[i + 1]):
                c_title = lines[i]
                buf = [lines[i + 1]]  # Path line
                i += 2
                # Collect bullets + Notes blocks until next title/path
                while i < len(lines):
                    if looks_like_title(lines[i]) and i + 1 < len(lines) and is_path(lines[i + 1]):
                        break
                    # keep bullets and "Notes:" and its bullets
                    if is_bullet(lines[i]) or lines[i].lower().startswith("notes"):
                        buf.append(lines[i])
                    i += 1
                chunks.append(_Chunk(page=sec.page, section_title=sec.title, chunk_title=c_title, text="\n".join(buf).strip()))
                emitted_any = True
                continue
            i += 1

        if not emitted_any:
            chunks.append(_Chunk(page=sec.page, section_title=sec.title, chunk_title=None, text=sec.text.strip()))

    return chunks


@lru_cache(maxsize=1)
def _load_user_flows_sections() -> List[_DocSection]:
    root = Path(__file__).resolve().parents[2]
    pdf_path = root / "docs" / "Secoraa-ASM-User-Flows.pdf"
    if not pdf_path.exists():
        raise FileNotFoundError(f"Missing PDF: {pdf_path}")
    pdf_bytes = pdf_path.read_bytes()
    lines = _extract_pdf_text_lines(pdf_bytes)
    sections = _build_sections(lines)
    if not sections:
        raise ValueError("Could not extract any text from the PDF.")
    return sections


def _bm25_rank(question: str, chunks: List[_Chunk]) -> List[Tuple[float, _Chunk]]:
    """
    BM25 retrieval over chunks (RAG-style retrieval without external embeddings).
    """
    q_toks = _tokenize(question)
    if not q_toks:
        return [(0.0, c) for c in chunks]

    # document frequency
    df: Dict[str, int] = {}
    doc_toks: List[List[str]] = []
    doc_lens: List[int] = []
    for ch in chunks:
        toks = _tokenize(ch.text)
        doc_toks.append(toks)
        doc_lens.append(len(toks))
        for t in set(toks):
            df[t] = df.get(t, 0) + 1

    N = max(1, len(chunks))
    avgdl = (sum(doc_lens) / max(1, len(doc_lens))) if doc_lens else 1.0

    # BM25 params
    k1 = 1.4
    b = 0.75

    q_counts: Dict[str, int] = {}
    for t in q_toks:
        q_counts[t] = q_counts.get(t, 0) + 1

    scored: List[Tuple[float, _Chunk]] = []
    for ch, toks, dl in zip(chunks, doc_toks, doc_lens):
        tf: Dict[str, int] = {}
        for t in toks:
            if t in q_counts:
                tf[t] = tf.get(t, 0) + 1

        score = 0.0
        for t, qf in q_counts.items():
            f = tf.get(t, 0)
            if f <= 0:
                continue
            # BM25 IDF
            idf = math.log(1 + (N - df.get(t, 0) + 0.5) / (df.get(t, 0) + 0.5))
            denom = f + k1 * (1 - b + b * (dl / max(1e-9, avgdl)))
            score += idf * ((f * (k1 + 1)) / denom) * (1 + math.log(1 + qf))

        # Prefer chunks that have a Path line (actual workflows)
        if "path:" in ch.text.lower():
            score *= 1.10

        scored.append((score, ch))

    scored.sort(key=lambda x: x[0], reverse=True)
    return scored


def _format_workflow_only(text: str) -> str:
    """
    Keep only Path + bullet lines, in the exact plain format requested.
    """
    lines = [l.strip() for l in (text or "").split("\n") if l.strip()]
    out: List[str] = []
    for l in lines:
        low = l.lower()
        if low.startswith("path:") or l.startswith("- "):
            out.append(l)
    return _safe_text("\n".join(out))


def _make_answer(question: str, top: List[_Chunk]) -> str:
    # Return ONLY the actionable steps (no citations, no page references).
    if not top:
        return "I couldn’t find a matching workflow in the User Flows document for that question."

    qlow = (question or "").lower()

    # Special-case: "run scan/live" should return all flows in that section (DD + Subdomain + API)
    if ("run scan" in qlow) or ("live scan" in qlow) or ("run live" in qlow):
        # gather all chunks whose parent section title matches "Run Scan"
        run_chunks = [c for c in top if (c.section_title or "").lower().startswith("run scan")]
        if not run_chunks:
            # try broader: any chunk that mentions "ASM > Scan > Run Scan"
            run_chunks = [c for c in top if "asm > scan > run scan" in (c.text or "").lower()]
        # If we have candidates, expand by scanning all chunks (cached) to include all from that section.
        try:
            all_chunks = _load_user_flows_chunks()
            extra = [c for c in all_chunks if (c.section_title or "").lower().startswith("run scan")]
            if extra:
                run_chunks = extra
        except Exception:
            pass

        blocks = []
        for c in run_chunks:
            blk = _format_workflow_only(c.text)
            if blk:
                blocks.append(blk)
        # De-dupe preserving order
        seen = set()
        uniq = []
        for btxt in blocks:
            if btxt in seen:
                continue
            seen.add(btxt)
            uniq.append(btxt)
        return "\n\n".join(uniq[:3]) if uniq else _format_workflow_only(top[0].text)

    # Default: return best chunk (Path + steps only)
    return _format_workflow_only(top[0].text) or _safe_text(top[0].text)


def _excerpt(sec: _DocSection, max_chars: int = 260) -> str:
    txt = _safe_text(sec.text.replace("\n", " "))
    if len(txt) <= max_chars:
        return txt
    return txt[: max_chars - 3].rstrip() + "..."


@lru_cache(maxsize=1)
def _load_user_flows_chunks() -> List[_Chunk]:
    secs = _load_user_flows_sections()
    return _split_into_chunks(secs)


@router.post("/qa", response_model=AskResponse)
def ask_user_flows(req: AskRequest) -> AskResponse:
    try:
        chunks = _load_user_flows_chunks()
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load user flows PDF: {e}")

    scored = _bm25_rank(req.question, chunks)
    top_chunks = [c for score, c in scored if score > 0][: req.max_sources]
    if not top_chunks and scored:
        top_chunks = [scored[0][1]]

    answer = _make_answer(req.question, top_chunks)
    # Do not return citations/sources in the product UI (per requirement).
    return AskResponse(answer=answer, sources=[])

