import hashlib
import secrets
from datetime import timedelta, timezone
from pathlib import Path

import pyotp
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .config import settings
from .database import AdminSession, Audit, LoginAttempt, get_db, utcnow

basic = HTTPBasic(auto_error=False)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def audit(db, actor, action, target="", **details):
    db.add(Audit(actor=actor, action=action, target=target, details=details))


def valid_password(username, password):
    return secrets.compare_digest(
        username.encode(), settings.admin_user.encode()
    ) & secrets.compare_digest(password.encode(), settings.admin_password.encode())


def throttle(db, request):
    # Trust the direct peer only. Reverse proxy must also rate-limit /api/session.
    address = request.client.host if request.client else "local"
    cutoff = utcnow() - timedelta(minutes=15)
    db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < cutoff))
    count = db.scalar(
        select(func.count())
        .select_from(LoginAttempt)
        .where(LoginAttempt.address == address)
    )
    if count >= 10:
        raise HTTPException(
            429, "Слишком много попыток входа. Повторите через 15 минут"
        )
    return address


def failed_login(db, address):
    db.add(LoginAttempt(address=address))
    audit(db, "anonymous", "login_failed")
    db.commit()


def admin(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(basic),
    db: Session = Depends(get_db),
):
    token = request.cookies.get("autoip_session")
    session = db.get(AdminSession, digest(token)) if token else None
    if session and aware(session.expires_at) > utcnow():
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if not secrets.compare_digest(
                request.headers.get("x-csrf-token", ""), session.csrf
            ):
                raise HTTPException(403, "Неверный CSRF-токен")
        return settings.admin_user
    if credentials and not settings.totp_secret_file:
        address = throttle(db, request)
        if valid_password(credentials.username, credentials.password):
            return credentials.username
        failed_login(db, address)
    raise HTTPException(401, "Требуется вход администратора")


def login(db, request, username, password, otp):
    address = throttle(db, request)
    valid = valid_password(username, password)
    if settings.totp_secret_file:
        try:
            valid &= pyotp.TOTP(
                Path(settings.totp_secret_file).read_text().strip()
            ).verify(otp, valid_window=0)
        except (OSError, ValueError):
            valid = False
    if not valid:
        failed_login(db, address)
        raise HTTPException(401, "Неверные данные входа")
    token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    db.add(
        AdminSession(
            token_hash=digest(token),
            csrf=csrf,
            expires_at=utcnow() + timedelta(hours=settings.session_hours),
        )
    )
    audit(db, username, "login")
    db.commit()
    return token, csrf


def display_time(value):
    from zoneinfo import ZoneInfo

    return (
        aware(value)
        .astimezone(ZoneInfo(settings.display_timezone))
        .strftime("%d.%m.%Y %H:%M %Z")
    )
