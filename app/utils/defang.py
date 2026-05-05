from __future__ import annotations

import re


def defang(value: str, ioc_type: str = "") -> str:
    if ioc_type in ("ipv4", "ipv6"):
        return value.replace(".", "[.]")
    if ioc_type == "domain":
        return value.replace(".", "[.]")
    if ioc_type == "url":
        return value.replace("http", "hxxp").replace(".", "[.]")
    if ioc_type in ("md5", "sha1", "sha256"):
        return value
    # Generic: try to defang IPs and domains in text
    result = re.sub(r"(\d)\.(\d)", r"\1[.]\2", value)
    result = result.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return result


def refang(value: str) -> str:
    return (
        value.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
        .replace("[. ]", ".")
        .replace("hxxp://", "http://")
        .replace("hxxps://", "https://")
    )
