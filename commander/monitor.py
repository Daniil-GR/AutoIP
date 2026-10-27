"""Conservative external check: failure != confirmed censorship."""
import asyncio
import re

import httpx

PUBLIC_HOST = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


async def checkhost_tcp(host: str, port: int) -> dict:
    if not PUBLIC_HOST.fullmatch(host) or not 1 <= port <= 65535:
        return {"status": "unknown", "error": "Invalid public host/port"}
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            nodes_resp = await client.get("https://check-host.net/nodes/hosts", headers={"Accept": "application/json"})
            nodes_resp.raise_for_status()
            nodes = nodes_resp.json().get("hosts", {})
            ru = [name for name, info in nodes.items() if isinstance(info, dict) and info.get("country") == "RU"][:5]
            if not ru:
                return {"status": "unknown", "error": "No available RU check nodes"}
            args = [("host", host + ":" + str(port))] + [("node", n) for n in ru]
            resp = await client.get("https://check-host.net/check-tcp", params=args, headers={"Accept": "application/json"})
            resp.raise_for_status()
            request_id = resp.json().get("request_id")
            if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", request_id):
                return {"status": "unknown", "error": "Missing request ID"}
            results = {}
            for _ in range(4):
                await asyncio.sleep(2)
                r = await client.get("https://check-host.net/check-result/" + request_id)
                r.raise_for_status()
                results = r.json()
                if all(results.get(node) is not None for node in ru):
                    break
            details = {node: results.get(node) for node in ru}
            # Site can change response shapes; do not infer censorship.
            return {"status": "observed", "results": details, "source": "check-host", "note": "Raw observations only; no automated block verdict"}
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return {"status": "unknown", "error": str(exc)[:250], "source": "check-host"}
