#!/usr/bin/env python3
"""Menu-driven Mr Patchy Compose authoring. Never starts or changes containers."""

import argparse
from copy import deepcopy
from dataclasses import dataclass, replace
import ipaddress
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Config:
    apps: int = 1
    workers: int = 1
    project: str = "mrpatchy-custom"
    runtime: str = "build"
    image: str = ""
    external_data_volume: str = ""
    database: str = "sqlite"
    http_port: int = 80
    https_port: int = 443
    bind_ip: str = "0.0.0.0"
    control_subnet: str = "172.30.254.0/24"
    jobs: int = 2
    polls: int = 8
    ai: int = 4
    worker_prefix: str = ""
    app_memory: str = "2g"
    worker_memory: str = "4g"


def validate(config):
    for field in ("apps", "workers"):
        value = getattr(config, field)
        if type(value) is not int or not 0 <= value <= 16:
            raise ValueError(f"{field} must be between 0 and 16")
    if config.apps + config.workers == 0:
        raise ValueError("Choose at least one app or worker")
    if not config.apps and not config.external_data_volume:
        raise ValueError("Worker-only mode requires an existing controller data volume")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", config.project):
        raise ValueError("Project name must use lowercase letters, digits, hyphens or underscores")
    if config.external_data_volume and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", config.external_data_volume):
        raise ValueError("Enter a Docker volume name, not a path or environment expression")
    if config.runtime not in ("build", "gcp", "image"):
        raise ValueError("Runtime must be build, gcp or image")
    if config.runtime == "image" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_:@-]{0,255}", config.image):
        raise ValueError("Enter an image name/tag or digest without whitespace or environment expressions")
    if config.database not in ("sqlite", "mysql"):
        raise ValueError("Database must be sqlite or mysql")
    for field in ("http_port", "https_port"):
        value = getattr(config, field)
        if type(value) is not int or not 1 <= value <= 65535:
            raise ValueError(f"{field} must be between 1 and 65535")
    if config.http_port == config.https_port:
        raise ValueError("HTTP and HTTPS need different host ports")
    ipaddress.ip_address(config.bind_ip)
    subnet = ipaddress.ip_network(config.control_subnet)
    if subnet.version != 4 or subnet.prefixlen > 27:
        raise ValueError("Control network needs an IPv4 subnet with at least 32 addresses")
    for field in ("jobs", "polls", "ai"):
        value = getattr(config, field)
        if type(value) is not int or not 1 <= value <= 64:
            raise ValueError(f"{field} concurrency must be between 1 and 64")
    if config.worker_prefix and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,47}", config.worker_prefix):
        raise ValueError("Worker ID prefix must be 1-48 letters, digits, dots, hyphens or underscores")
    for field in ("app_memory", "worker_memory"):
        if not re.fullmatch(r"[1-9][0-9]{0,5}[mg]", getattr(config, field)):
            raise ValueError(f"{field} must be a positive whole number followed by m or g")


def yaml_module():
    try:
        import yaml
    except ImportError:
        raise ValueError("Install the YAML dependency: python -m pip install -r requirements-configure.txt") from None
    return yaml


def service_name(role, index):
    return role if index == 1 else f"{role}-{index}"


def build_document(config, output, root=ROOT):
    """Clone maintained templates instead of duplicating their security settings."""
    validate(config)
    yaml = yaml_module()
    base = yaml.safe_load((root / "compose.yaml").read_text(encoding="utf-8"))
    gcp = yaml.safe_load((root / "compose.gcp.yaml").read_text(encoding="utf-8")) if config.runtime == "gcp" else None
    try:
        context = Path(os.path.relpath(root, Path(output).absolute().parent)).as_posix()
    except ValueError:  # Windows paths on different drives cannot be relative.
        context = root.as_posix()
    # A checkout name can itself contain '$'; Compose must treat that literally.
    context = context.replace("$", "$$")
    document = {"name": config.project, "services": {}, "volumes": {"app-data": {}}, "networks": {"management": {}}}
    services = document["services"]
    if config.external_data_volume:
        document["volumes"]["app-data"] = {"external": True, "name": config.external_data_volume}
    database = ("${DATABASE_URL:?Set DATABASE_URL to the existing MySQL database}"
                if config.database == "mysql" else "${DATABASE_URL:-sqlite:////data/mrpatchy.db}")
    caddy_ip = str(ipaddress.ip_network(config.control_subnet).network_address + 2)
    worker_ids = [f"{config.worker_prefix}-{i}" for i in range(1, config.workers + 1)] if config.worker_prefix else []

    def runtime_service(role):
        service = deepcopy(base["services"][role])
        if config.runtime == "image":
            service.pop("build", None)
            service["image"] = config.image
        elif gcp:
            override = deepcopy(gcp["services"][role])
            service["environment"].update(override.pop("environment", {}))
            service.update(override)
            service["build"]["context"] = context
        else:
            service["build"] = {"context": context}
        service["environment"]["DATABASE_URL"] = database
        return service

    previous = None
    for index in range(1, config.apps + 1):
        name = service_name("app", index)
        service = runtime_service("app")
        # All app instances share Caddy's existing app:8000 DNS endpoint. No
        # repeated fixed IP and no new trusted hop or public app port is needed.
        service["networks"]["control"] = {"aliases": ["app"]} if index > 1 else {}
        env = service["environment"]
        env.update(FORWARDED_ALLOW_IPS=caddy_ip, HTTPS_PORT=str(config.https_port))
        public_url = "https://localhost" + (f":{config.https_port}" if config.https_port != 443 else "")
        env["PUBLIC_URL"] = "${PUBLIC_URL:-" + public_url + "}"
        if worker_ids:
            env["MRPATCHY_EXPECTED_WORKER_IDS"] = ",".join(worker_ids)
        service["mem_limit"] = config.app_memory
        if previous:
            service["depends_on"] = {previous: {"condition": "service_healthy"}}
        services[name] = service
        previous = name

    for index in range(1, config.workers + 1):
        name = service_name("worker", index)
        service = runtime_service("worker")
        service.pop("depends_on", None)
        if previous:
            service["depends_on"] = {previous: {"condition": "service_healthy"}}
        service["environment"].update(
            MRPATCHY_WORKER_ID=worker_ids[index - 1] if worker_ids else "",
            MRPATCHY_JOB_CONCURRENCY=str(config.jobs),
            MRPATCHY_POLL_CONCURRENCY=str(config.polls),
            MRPATCHY_AI_CONCURRENCY=str(config.ai),
        )
        service["mem_limit"] = config.worker_memory
        services[name] = service

    if config.apps:
        caddy = deepcopy(base["services"]["caddy"])
        caddy["depends_on"] = {previous: {"condition": "service_healthy"}}
        caddy["networks"]["control"]["ipv4_address"] = caddy_ip
        caddy["environment"].update(HTTPS_PORT=str(config.https_port), PUBLIC_URL=services["app"]["environment"]["PUBLIC_URL"])
        for port in caddy["ports"]:
            port["published"] = str(config.http_port if port["target"] == 80 else config.https_port)
            port["host_ip"] = config.bind_ip
        services["caddy"] = caddy
        document["volumes"].update({name: {} for name in ("tls-config", "caddy-data", "caddy-config")})
        document["networks"].update(control={"internal": True, "ipam": {"config": [{"subnet": config.control_subnet}]}}, edge={})
    return document


def render(config, output, root=ROOT):
    document = build_document(config, output, root)
    return ("# Generated by tools/configure_compose.py; use this as a standalone -f file.\n"
            "# See docs/COMPOSE_CONFIGURATION.md for state and multi-app limitations.\n"
            + yaml_module().safe_dump(document, sort_keys=False, width=1000))


def save(text, output, overwrite=False, root=ROOT):
    """New files are exclusive; explicit replacement keeps an exclusive .bak."""
    output = Path(output).absolute()
    if output.suffix.lower() not in (".yaml", ".yml"):
        raise ValueError("Output filename must end in .yaml or .yml")
    if output.resolve() in ((root / "compose.yaml").resolve(), (root / "compose.gcp.yaml").resolve()):
        raise ValueError("Choose a custom filename; the maintained Compose templates are protected")
    if output.is_symlink():
        raise ValueError("Refusing to replace a symbolic link")
    if not overwrite:
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        return
    if not output.exists():
        return save(text, output, root=root)
    backup = output.with_name(output.name + ".bak")
    with backup.open("xb") as stream:
        stream.write(output.read_bytes())
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=output.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
        os.replace(temporary, output)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def prompt(label, default, convert=str):
    while True:
        value = input(f"{label} [{default}]: ").strip()
        try:
            return convert(value) if value else default
        except ValueError:
            print("Enter a valid value.")


def notices(config):
    if not config.apps:
        print("Worker-only: use the existing controller's data volume on this Docker host, matching version and database.")
    if not config.workers:
        print("App-only: background jobs require workers connected to the same controller state.")
    if config.apps > 1:
        print("Multiple apps share local state and a DNS endpoint. This is NOT a validated HA deployment.\n"
              "Initial startup is ordered; upgrades and TLS changes require one controller owner. See the guide.")


def menu(config, output):
    while True:
        print(f"\nMr Patchy Compose configuration: {config.apps} app(s), {config.workers} worker(s)\n"
              f"Project: {config.project} | Runtime: {config.runtime} | Output: {output}\n"
              "1. Container layout\n2. Build / GCP / existing image\n3. Project, database and shared data\n"
              "4. Ports and network\n5. Worker concurrency, IDs and memory\n6. Preview YAML\n7. Save YAML\n0. Quit")
        choice = input("Choice: ").strip()
        try:
            candidate = config
            if choice == "0":
                return 0
            if choice == "1":
                print("1. Apps + workers\n2. Apps only\n3. Workers only")
                layout = input("Layout: ").strip()
                if layout not in ("1", "2", "3"):
                    raise ValueError("Choose layout 1, 2 or 3")
                apps = 0 if layout == "3" else prompt("App count (1-16)", max(1, config.apps), int)
                workers = 0 if layout == "2" else prompt("Worker count (1-16)", max(1, config.workers), int)
                if (layout != "3" and apps == 0) or (layout != "2" and workers == 0):
                    raise ValueError("Selected roles need at least one container")
                volume = prompt("Existing controller data volume", config.external_data_volume) if layout == "3" else config.external_data_volume
                candidate = replace(config, apps=apps, workers=workers, external_data_volume=volume)
            elif choice == "2":
                runtime = prompt("Runtime (build/gcp/image)", config.runtime)
                image = prompt("Image name/tag or digest", config.image) if runtime == "image" else ""
                candidate = replace(config, runtime=runtime, image=image)
            elif choice == "3":
                candidate = replace(config, project=prompt("Compose project name", config.project),
                                    database=prompt("Database (sqlite/mysql)", config.database))
                volume = prompt("Existing data volume (use - for a new project volume)", config.external_data_volume or "-")
                candidate = replace(candidate, external_data_volume="" if volume == "-" else volume)
            elif choice == "4":
                candidate = replace(config, http_port=prompt("HTTP host port", config.http_port, int),
                                    https_port=prompt("HTTPS host port", config.https_port, int),
                                    bind_ip=prompt("Bind IP", config.bind_ip), control_subnet=prompt("Unused control subnet", config.control_subnet))
            elif choice == "5":
                prefix = prompt("Unique worker ID prefix (- for automatic boot IDs)", config.worker_prefix or "-")
                candidate = replace(config, worker_prefix="" if prefix == "-" else prefix,
                                    jobs=prompt("Jobs per worker", config.jobs, int), polls=prompt("Polls per worker", config.polls, int),
                                    ai=prompt("AI tasks per worker", config.ai, int), app_memory=prompt("Memory per app", config.app_memory),
                                    worker_memory=prompt("Memory per worker", config.worker_memory))
            elif choice == "6":
                notices(config)
                print(render(config, output))
            elif choice == "7":
                output = Path(prompt("Output YAML path", str(output))).expanduser().absolute()
                content = render(config, output)
                notices(config)
                print(content)
                if input("Save this configuration? [y/N]: ").strip().lower() != "y":
                    continue
                overwrite = False
                if output.exists():
                    overwrite = input("File exists. Back up to .bak and replace? Type REPLACE: ").strip() == "REPLACE"
                    if not overwrite:
                        continue
                save(content, output, overwrite)
                print(f"Saved {output}")
                print(f'docker compose --env-file .env -f "{output}" config --quiet')
                print(f'docker compose --env-file .env -f "{output}" up --build -d --wait')
                return 0
            else:
                raise ValueError("Choose an option from 0 to 7")
            validate(candidate)
            config = candidate
        except (ValueError, OSError) as error:
            print(f"Configuration not saved: {error}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "compose.custom.yaml")
    parser.add_argument("--non-interactive", action="store_true", help="Generate using flags instead of the menu")
    parser.add_argument("--print", dest="preview", action="store_true", help="Print YAML without saving (non-interactive)")
    parser.add_argument("--overwrite", action="store_true", help="Back up an existing output to .bak before replacement")
    for name, field in Config.__dataclass_fields__.items():
        parser.add_argument("--" + name.replace("_", "-"), type=field.type, default=field.default)
    args = parser.parse_args(argv)
    config = Config(**{name: getattr(args, name) for name in Config.__dataclass_fields__})
    try:
        validate(config)
        if args.non_interactive or args.preview:
            content = render(config, args.output)
            if args.preview:
                print(content, end="")
            else:
                save(content, args.output, args.overwrite)
                print(f"Saved {args.output.absolute()}")
            return 0
        return menu(config, args.output)
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled; no configuration saved.", file=sys.stderr)
        return 130
    except (ValueError, OSError) as error:
        print(f"Configuration not saved: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
