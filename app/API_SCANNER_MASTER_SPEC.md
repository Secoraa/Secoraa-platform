# API Security Scanner – Master Specification

## Purpose

This document is the **single source of truth** for building a **production-grade, documentation-driven API Security Scanner**.

This file is intended to be given directly to **Cursor (LLM-based coding tool)**.  
All instructions in this file must be treated as **implementation requirements**, not high-level ideas.

The scanner must be:
- Headless (no UI)
- Framework-agnostic
- CI/CD compatible
- Plugin-based
- OWASP-aligned

---

## Scanner Type (Industry Classification)

**Specification / Contract-Based API Security Scanner**

- Uses API documentation as input
- Does not rely on proxies or crawling
- Executes known endpoints deterministically
- Matches modern API security tooling

---

## High-Level Architecture

