"""Server-side DNS boundary for this AutoIP installation.

An administrator editing agent settings cannot expand provider access. DNS
mutations must use these same guards when an approved write adapter is added.
"""

import re

MANAGED_DNS_ZONE = "vetka.rest"
_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


def managed_zone(value):
    value = value.strip().lower().rstrip(".")
    if value and value != MANAGED_DNS_ZONE:
        raise ValueError("AutoIP разрешена только DNS-зона vetka.rest")
    return value


def managed_record(value):
    value = value.strip().lower().rstrip(".")
    if value and (
        len(value) > 253
        or not _HOST.fullmatch(value)
        or not value.endswith("." + MANAGED_DNS_ZONE)
    ):
        raise ValueError(
            "AutoIP разрешены только поддомены vetka.rest; корневая запись запрещена"
        )
    return value
