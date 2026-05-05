from app.utils.slug import safe_filename, slugify


class TestSlugify:
    def test_basic(self):
        assert slugify("hello world") == "hello-world"

    def test_special_chars(self):
        result = slugify("CVE-2024-21413: Outlook RCE!")
        assert result == "cve-2024-21413-outlook-rce"

    def test_chinese(self):
        result = slugify("微软Outlook漏洞")
        assert result == "outlook"

    def test_max_length(self):
        result = slugify("a" * 50, max_len=10)
        assert len(result) <= 10

    def test_empty(self):
        assert slugify("") == "query"

    def test_consecutive_hyphens(self):
        result = slugify("a---b")
        assert "--" not in result

    def test_strip_hyphens(self):
        result = slugify("-hello-")
        assert result == "hello"


class TestSafeFilename:
    def test_cve_filename(self):
        name = safe_filename("cve", "CVE-2024-21413", "20260505-1430", "md")
        assert name == "ti-cve-cve-2024-21413-20260505-1430.md"

    def test_pdf_extension(self):
        name = safe_filename("cve", "test query", "20260505", "pdf")
        assert name.endswith(".pdf")
        assert name.startswith("ti-cve-")
