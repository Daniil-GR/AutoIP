"""SSH filtering for new VPSs; it never substitutes for MTProto readiness."""

from datetime import datetime, timedelta

from .monitor import CheckHost
from .nodehost import known_blocked, public_ip
from .security import aware

FOREIGN_COUNTRIES = ("DE", "NL", "FR")


def outcome(report, address):
    if (
        report.get("source") != "check-host"
        or report.get("status") != "observed"
        or report.get("target") != address
        or report.get("port") != 22
    ):
        return "UNKNOWN"
    observations = report.get("observations", [])
    foreign = {
        o.get("country")
        for o in observations
        if o.get("state") == "reachable" and o.get("protocol") == "tcp"
    }
    if not set(FOREIGN_COUNTRIES) <= foreign:
        return "UNKNOWN"
    ru = [
        o
        for o in observations
        if o.get("country") == "RU" and o.get("protocol") == "tcp"
    ]
    good = {o.get("asn") for o in ru if o.get("state") == "reachable" and o.get("asn")}
    if len(good) >= 2:
        return "PASS"
    missing = set()
    for observation in ru:
        raw = observation.get("raw")
        item = raw[0] if isinstance(raw, list) and raw else None
        error = str(item.get("error", "")).lower() if isinstance(item, dict) else ""
        if (
            observation.get("state") == "unknown"
            and "timed out" in error
            and observation.get("asn")
        ):
            missing.add(observation["asn"])
    return "RU_SUSPECTED" if len(missing) >= 2 and not good else "UNKNOWN"


def assess(db, address, created_at, rounds, now):
    address = public_ip(address)
    if known_blocked(db, address):
        return {"status": "REJECT_HISTORY", "install_allowed": False}
    if now < aware(created_at) + timedelta(minutes=4):
        return {
            "status": "BOOT_WAIT",
            "install_allowed": False,
            "retry_at": (aware(created_at) + timedelta(minutes=4)).isoformat(),
        }
    valid = []
    for round_ in rounds:
        try:
            checked = datetime.fromisoformat(round_["checked_at"])
            if (
                checked.tzinfo is None
                or checked > now
                or now - checked > timedelta(minutes=10)
            ):
                continue
            if checked < aware(created_at) + timedelta(minutes=4):
                continue
        except (ValueError, KeyError, TypeError):
            continue
        valid.append((checked, outcome(round_["report"], address)))
    valid.sort()
    if valid and valid[-1][1] == "PASS" and now - valid[-1][0] <= timedelta(minutes=2):
        return {
            "status": "SSH_READY",
            "install_allowed": True,
            "mtproto_verified": False,
        }
    last = valid[-3:]
    if (
        len(last) == 3
        and all(v == "RU_SUSPECTED" for _, v in last)
        and all(last[i + 1][0] - last[i][0] >= timedelta(minutes=1) for i in range(2))
    ):
        return {"status": "REJECT_RU_FILTER", "install_allowed": False}
    return {"status": "RECHECK", "install_allowed": False}


async def check(address):
    return await CheckHost().check(
        public_ip(address), 22, foreign_countries=FOREIGN_COUNTRIES
    )
