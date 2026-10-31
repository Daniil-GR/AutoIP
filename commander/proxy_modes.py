"""Protocol choices for new installations; legacy nodes keep their mode."""

from typing import Literal

ProxyMode = Literal["web_mtproto", "mtproto_faketls"]
DEFAULT_MODE = "web_mtproto"
FAKETLS_MODE = "mtproto_faketls"
FAKETLS_SNI = "www.booking.com"


def mode_settings(mode):
    if mode == DEFAULT_MODE:
        return {"proxy_mode": mode, "port": 9443, "secret_format": "dd", "web": True}
    if mode == FAKETLS_MODE:
        return {
            "proxy_mode": mode,
            "port": 443,
            "secret_format": "ee",
            "sni": FAKETLS_SNI,
            "web": False,
        }
    raise ValueError("Неизвестный режим прокси")
