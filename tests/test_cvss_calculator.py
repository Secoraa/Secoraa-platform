"""Tests for cvss_calculator — CVSS scoring and severity mapping."""
import pytest

from app.scanners.api_scanner.reporter.cvss_calculator import (
    calculate_cvss,
    severity_from_score,
)


class TestCalculateCvss:
    def test_valid_high_vector(self):
        score = calculate_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        assert score > 0.0
        assert score <= 10.0

    def test_valid_low_vector(self):
        score = calculate_cvss("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")
        assert score > 0.0

    def test_invalid_vector(self):
        score = calculate_cvss("INVALID")
        assert score == 0.0

    def test_empty_vector(self):
        score = calculate_cvss("")
        assert score == 0.0


class TestSeverityFromScore:
    def test_critical(self):
        assert severity_from_score(9.0) == "CRITICAL"
        assert severity_from_score(10.0) == "CRITICAL"

    def test_high(self):
        assert severity_from_score(7.0) == "HIGH"
        assert severity_from_score(8.9) == "HIGH"

    def test_medium(self):
        assert severity_from_score(4.0) == "MEDIUM"
        assert severity_from_score(6.9) == "MEDIUM"

    def test_low(self):
        assert severity_from_score(0.1) == "LOW"
        assert severity_from_score(3.9) == "LOW"

    def test_informational(self):
        assert severity_from_score(0.0) == "INFORMATIONAL"
