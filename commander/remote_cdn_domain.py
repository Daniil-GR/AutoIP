#!/usr/bin/env python3
"""Add a CDN hostname to an existing standard deploy.sh installation.

Python 3.11+, standard library only. Default is a read-only plan. No DNS/CDN API,
certificate issuance, package installation, secret rotation, or binary upgrade.
"""

import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import tomllib
import urllib.request


class Refused(RuntimeError):
    pass


def domain(value):
    value = value.lower().rstrip(".")
    if (
        len(value) > 253
        or "." not in value
        or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
            for p in value.split(".")
        )
    ):
        raise Refused("Некорректное имя домена")
    return value


def prepare(config, nginx, old, new):
    old, new = domain(old), domain(new)
    if old == new:
        raise Refused("Укажите разные имена")
    parsed = tomllib.loads(config)
    vhosts = parsed.get("web", {}).get("vhosts", [])
    sources = [v for v in vhosts if v.get("host") == old]
    if len(sources) != 1 or not sources[0].get("profiles"):
        raise Refused(
            "Не найден единственный WEB-vhost с профилями для исходного имени"
        )
    source = sources[0]
    if source.get("hosts"):
        raise Refused("Групповые hosts требуют отдельной проверки; файл не изменён")
    aliases = [v for v in vhosts if v.get("host") == new or new in v.get("hosts", [])]
    desired = {**copy.deepcopy(source), "host": new}
    if aliases and (len(aliases) != 1 or aliases[0] != desired):
        raise Refused("Новое имя уже настроено иначе; перезапись запрещена")
    output = config
    if not aliases:
        # Clone the entire vhost subtree, retaining profiles/limits/decoy and
        # comments. Refuse unfamiliar TOML spelling rather than reserialize keys.
        starts = list(
            re.finditer(r"(?m)^[ \t]*\[\[web\.vhosts\]\][ \t]*(?:#.*)?$", config)
        )
        if len(starts) != len(vhosts):
            raise Refused("Нестандартная запись TOML; автоматическая правка запрещена")
        start = starts[vhosts.index(source)].start()
        end = len(config)
        for header in re.finditer(
            r"(?m)^[ \t]*\[([^\n]+)\][ \t]*(?:#.*)?$",
            config[starts[vhosts.index(source)].end() :],
        ):
            name = header.group(1).strip("[] ")
            if not name.startswith("web.vhosts."):
                end = starts[vhosts.index(source)].end() + header.start()
                break
        block = config[start:end]
        block, count = re.subn(
            r'(?m)^([ \t]*)host[ \t]*=[ \t]*["\'][^"\'\n]+["\'][ \t]*(?:#.*)?$',
            lambda m: m[1] + "host = " + json.dumps(new),
            block,
        )
        if count != 1:
            raise Refused("Неоднозначная строка host; файл не изменён")
        output = config[:end] + "\n" + block.rstrip() + "\n\n" + config[end:]
        check = tomllib.loads(output)
        expected = copy.deepcopy(parsed)
        expected["web"]["vhosts"].insert(vhosts.index(source) + 1, desired)
        if check != expected:
            raise Refused("Проверка сохранности TOML не пройдена")
    lines = list(re.finditer(r"(?m)^([ \t]*)server_name[ \t]+([^;\n]+);[ \t]*$", nginx))
    matches = [m for m in lines if old in m[2].split()]
    known = {v.get("host") for v in vhosts} | {old, new}
    if len(matches) != 1 or set(matches[0][2].split()) - known:
        raise Refused(
            "Nginx отличается от стандартного отдельного WEB-сайта; правка запрещена"
        )
    if len(re.findall(r"(?m)^\s*proxy_set_header\s+Host\s+\$host\s*;\s*$", nginx)) != 1:
        raise Refused("Nginx должен передавать исходный Host $host")
    if "proxy_pass http://telemt_web;" not in nginx:
        raise Refused("Не найден стандартный upstream Telemt")
    m = matches[0]
    names = m[2].split()
    if new not in names:
        names.append(new)
    nginx_output = (
        nginx[: m.start()]
        + m[1]
        + "server_name "
        + " ".join(names)
        + ";"
        + nginx[m.end() :]
    )
    return output, nginx_output


def run(*args):
    try:
        result = subprocess.run(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45
        )
    except subprocess.TimeoutExpired:
        raise Refused("Истекло время операции: " + args[0]) from None
    if result.returncode:
        raise Refused("Не выполнена проверка/операция: " + args[0] + " " + args[1])


def atomic(path, content, metadata):
    fd, tmp = tempfile.mkstemp(prefix=".telemtproxy-", dir=path.parent)
    try:
        os.fchown(fd, metadata.st_uid, metadata.st_gid)
        os.fchmod(fd, metadata.st_mode & 0o777)
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def ready(host):
    # Only the private loopback listener is contacted; this is site readiness,
    # not a claim of authenticated Telegram traffic through the CDN.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(30):
        try:
            request = urllib.request.Request(
                "http://127.0.0.1:18080/",
                headers={"Host": host, "X-Forwarded-For": "127.0.0.1"},
            )
            with opener.open(request, timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(1)
    raise Refused("WEB-listener не подтвердил готовность")


def apply(
    config_path, nginx_path, outputs, backup_root=Path("/var/backups/telemtproxy")
):
    paths = [config_path, nginx_path]
    originals = [p.read_text() for p in paths]
    metadata = [p.stat() for p in paths]
    if originals == list(outputs):
        print("Оба имени уже настроены. Перезапуск не нужен.")
        return
    run("nginx", "-t")
    run("systemctl", "is-active", "--quiet", "telemt")
    run("systemctl", "is-active", "--quiet", "nginx")
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder = Path(
        tempfile.mkdtemp(prefix=time.strftime("cdn-%Y%m%dT%H%M%S-"), dir=backup_root)
    )
    os.chmod(folder, 0o700)
    for i, original in enumerate(originals):
        target = folder / ("telemt.toml" if i == 0 else "nginx.conf")
        target.write_text(original)
        target.chmod(0o600)
    manifest = folder / "operation.json"

    def journal(stage):
        manifest.write_text(
            json.dumps({"stage": stage, "files": [str(p) for p in paths]}, indent=2)
        )
        manifest.chmod(0o600)
        with manifest.open() as f:
            os.fsync(f.fileno())

    journal("PREPARED")
    try:
        for path, content, stat in zip(paths, outputs, metadata):
            atomic(path, content, stat)
        journal("FILES_WRITTEN")
        run("nginx", "-t")
        run("systemctl", "restart", "telemt")
        for vhost in tomllib.loads(outputs[0])["web"]["vhosts"]:
            if vhost.get("host"):
                ready(vhost["host"])
        run("systemctl", "reload", "nginx")
        journal("APPLIED")
    except BaseException:
        for path, content, stat in zip(paths, originals, metadata):
            atomic(path, content, stat)
        try:
            run("nginx", "-t")
            run("systemctl", "restart", "telemt")
            run("systemctl", "reload", "nginx")
            journal("ROLLED_BACK")
        except BaseException:
            journal("ROLLBACK_FAILED")
            raise Refused(
                "Откат требует вмешательства. Закрытая копия: " + str(folder)
            ) from None
        raise Refused(
            "Изменения отменены, исходные файлы восстановлены. Копия: " + str(folder)
        ) from None
    print("Применено. Закрытая резервная копия: " + str(folder))
    print("Проверьте реальную передачу данных через новую ссылку в Telegram.")


def main():
    parser = argparse.ArgumentParser(
        description="Добавить CDN-имя в Telemt и Nginx. Без --apply — только проверка."
    )
    parser.add_argument("source", help="существующее имя WEB-прокси")
    parser.add_argument(
        "alias", help="новое CDN-имя с уже выпущенным сертификатом на CDN"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="применить и перезапустить Telemt: возможен краткий перерыв",
    )
    args = parser.parse_args()
    old, new = domain(args.source), domain(args.alias)
    if os.geteuid() != 0:
        raise Refused("Запустите от root; конфигурация содержит закрытые данные")
    config = Path("/etc/telemt/telemt.toml")
    nginx = Path("/etc/nginx/sites-available/default")
    enabled = Path("/etc/nginx/sites-enabled/default")
    if config.is_symlink() or nginx.is_symlink() or enabled.resolve() != nginx:
        raise Refused("Нестандартные пути конфигурации; требуется отдельная проверка")
    lock_path = Path("/run/lock/telemtproxy-cdn-domain.lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    lock_stat = os.fstat(descriptor)
    if (
        lock_stat.st_uid != 0
        or not stat.S_ISREG(lock_stat.st_mode)
        or lock_stat.st_nlink != 1
    ):
        os.close(descriptor)
        raise Refused("Небезопасный файл блокировки")
    with os.fdopen(descriptor, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        outputs = prepare(config.read_text(), nginx.read_text(), old, new)
        print("План: сохранить " + old + ", добавить " + new + " в Telemt и Nginx.")
        print("Секреты, ad_tag, IP, сертификаты и DNS не меняются.")
        print("В Gcore необходим Forward Host header; origin SNI оставьте " + old + ".")
        print("Применение перезапустит Telemt; возможен краткий перерыв.")
        if args.apply:
            apply(config, nginx, outputs)
        else:
            print("Проверка завершена. Для применения повторите команду с --apply.")


if __name__ == "__main__":
    try:
        main()
    except (Refused, OSError, ValueError) as error:
        # Never emit configuration, secrets, command stderr, or full tracebacks.
        print(
            "Ошибка: "
            + (str(error) if isinstance(error, Refused) else type(error).__name__)
        )
        raise SystemExit(1)
