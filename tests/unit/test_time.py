from app.utils.time import format_duration, now_iso, parse_iso


class TestNowIso:
    def test_format(self):
        result = now_iso()
        assert "T" in result
        assert "+" in result or "Z" in result


class TestParseIso:
    def test_roundtrip(self):
        iso_str = now_iso()
        parsed = parse_iso(iso_str)
        assert parsed.tzinfo is not None


class TestFormatDuration:
    def test_seconds(self):
        assert format_duration(5.3) == "5.3s"

    def test_minutes(self):
        assert format_duration(125) == "2m 5s"

    def test_zero(self):
        assert format_duration(0) == "0.0s"
