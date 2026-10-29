"""Public Atlas probe discovery; coverage is observed, never assumed."""

import math

import httpx

COUNTRIES = {"DE": "Германия", "NL": "Нидерланды", "FI": "Финляндия"}
PROVIDERS = {31133: "Мегафон", 3216: "Билайн", 8359: "МТС", 12389: "Ростелеком"}
CITIES = {
    "Москва": (55.7558, 37.6173),
    "Санкт-Петербург": (59.9343, 30.3351),
    "Красноярск": (56.0153, 92.8932),
    "Хабаровск": (48.4802, 135.0719),
}
RADIUS_KM = 75


def distance_km(a, b):
    lat1, lon1, lat2, lon2 = map(math.radians, (*a, *b))
    v = (
        math.sin((lat2 - lat1) / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    )
    return 6371 * 2 * math.asin(math.sqrt(min(1, v)))


def select_probes(rows):
    """At most two per RU city/provider and three distinct ASNs per foreign country."""
    candidates = {}
    seen = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or row.get("status", {}).get("id") != 1
            or not row.get("is_public")
        ):
            continue
        tags = {t.get("slug") for t in row.get("tags", []) if isinstance(t, dict)}
        if "system-ipv4-works" not in tags:
            continue
        identifier, asn = row.get("id"), row.get("asn_v4")
        if type(identifier) is not int or type(asn) is not int:
            continue
        if identifier in seen:
            continue
        seen.add(identifier)
        country = row.get("country_code")
        info = {"id": identifier, "country": country, "asn": asn}
        if country == "RU" and asn in PROVIDERS:
            try:
                lon, lat = row["geometry"]["coordinates"]
                if not (-180 <= lon <= 180 and -90 <= lat <= 90):
                    continue
                city = min(CITIES, key=lambda c: distance_km((lat, lon), CITIES[c]))
                distance = distance_km((lat, lon), CITIES[city])
            except (KeyError, TypeError, ValueError):
                continue
            if distance > RADIUS_KM:
                continue
            info.update(
                city=city, provider=PROVIDERS[asn], distance_km=round(distance, 1)
            )
            candidates.setdefault((country, city, asn), []).append(info)
        elif country in COUNTRIES:
            candidates.setdefault((country,), []).append(info)
    probes, coverage = [], []
    for city in CITIES:
        for asn, provider in PROVIDERS.items():
            group = sorted(
                candidates.get(("RU", city, asn), []),
                key=lambda p: (p["distance_km"], p["id"]),
            )
            chosen = group[:2]
            probes.extend(chosen)
            coverage.append(
                {
                    "country": "RU",
                    "city": city,
                    "provider": provider,
                    "asn": asn,
                    "probes": len(chosen),
                }
            )
    for country in COUNTRIES:
        group = sorted(candidates.get((country,), []), key=lambda p: p["id"])
        chosen, asns = [], set()
        for probe in group:
            if probe["asn"] in asns:
                continue
            chosen.append(probe)
            asns.add(probe["asn"])
            if len(chosen) == 3:
                break
        probes.extend(chosen)
        coverage.append(
            {"country": country, "name": COUNTRIES[country], "probes": len(chosen)}
        )
    return {
        "probes": probes,
        "coverage": coverage,
        "radius_km": RADIUS_KM,
        "geolocation_approximate": True,
        "countries": COUNTRIES,
        "missing_groups": [g for g in coverage if not g["probes"]],
        "measurement_submitted": False,
        "note": "Город определяется приблизительно по координатам RIPE Atlas. ASN не подтверждает мобильный доступ. Отсутствие зонда не означает недоступность прокси.",
    }


async def discover_probes():
    rows = []
    async with httpx.AsyncClient(
        base_url="https://atlas.ripe.net/api/v2/", timeout=25, follow_redirects=False
    ) as client:
        for country in ("RU", *COUNTRIES):
            page = 1
            while True:
                response = await client.get(
                    "probes/",
                    params={
                        "country_code": country,
                        "status": 1,
                        "is_public": "true",
                        "page_size": 500,
                        "page": page,
                    },
                )
                response.raise_for_status()
                data = response.json()
                if not isinstance(data.get("results"), list):
                    raise ValueError("Unknown probe response")
                rows.extend(data["results"])
                if not data.get("next"):
                    break
                page += 1
                if page > 10:
                    raise ValueError("Probe inventory exceeds safe pagination limit")
    return select_probes(rows)
