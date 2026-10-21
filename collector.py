#!/usr/bin/env python3
"""Collect filtered security events from the local systemd journal."""

import argparse
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

LOCK_PATH = Path("/run/lock/cdt-log-harvester.lock")


def load_config(path):
    with path.open(encoding="utf-8") as file:
        config = json.load(file)

    if not isinstance(config.get("rules"), dict):
        raise ValueError("'rules' must be a JSON object")

    rules = {}
    for category, phrases in config["rules"].items():
        if not isinstance(phrases, list) or not all(
            isinstance(p, str) and p for p in phrases
        ):
            raise ValueError(
                f"Rule '{category}' must contain non-empty strings"
            )
        if phrases:
            rules[category] = re.compile(
                "|".join(re.escape(p) for p in phrases),
                re.IGNORECASE,
            )

    return config, rules


def classify(message, rules):
    return [
        category
        for category, pattern in rules.items()
        if pattern.search(message)
    ]


def load_written_cursors(output_path):
    cursors = set()
    if output_path.exists():
        with output_path.open(encoding="utf-8") as file:
            for line in file:
                try:
                    cursor = json.loads(line).get("journal_cursor")
                    if cursor:
                        cursors.add(cursor)
                except json.JSONDecodeError:
                    continue
    return cursors


def save_checkpoint(path, cursor):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=".cursor-", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(cursor + "\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def main():
    parser = argparse.ArgumentParser(
        description="Collect filtered local security journal events."
    )
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    try:
        lock_file = LOCK_PATH.open("a")
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("Another collector instance is already running.",
              file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Could not acquire collector lock: {error}",
              file=sys.stderr)
        return 1

    try:
        config, rules = load_config(Path(args.config).expanduser())
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 1

    output_path = Path(
        config.get("output", "output/security-events.jsonl")
    ).expanduser()
    checkpoint_path = output_path.with_suffix(".cursor")

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output = output_path.open("a", encoding="utf-8")
        written_cursors = load_written_cursors(output_path)
        last_cursor = (
            checkpoint_path.read_text(encoding="utf-8").strip()
            if checkpoint_path.exists()
            else ""
        )
    except OSError as error:
        print(f"Output/checkpoint error: {error}", file=sys.stderr)
        return 1

    command = [
        "journalctl", "--follow", "--output=json", "--no-pager"
    ]
    if last_cursor:
        command.append(f"--after-cursor={last_cursor}")
    else:
        command.append("--since=now")

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )
    except OSError as error:
        output.close()
        print(f"Could not start journalctl: {error}", file=sys.stderr)
        return 1

    print(f"Collector started; config: {args.config}", flush=True)
    print(f"Writing events to: {output_path}", flush=True)
    print(f"Checkpoint file: {checkpoint_path}", flush=True)

    try:
        with output:
            for line in process.stdout:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                cursor = event.get("__CURSOR")
                if not cursor:
                    continue

                # Ignore this service's own journal output to prevent
                # recursive collection of its diagnostic messages.
                if event.get("_SYSTEMD_UNIT") == "cdt-log-harvester.service":
                    save_checkpoint(checkpoint_path, cursor)
                    continue

                message = str(event.get("MESSAGE", ""))
                categories = classify(message, rules)

                if categories and cursor not in written_cursors:
                    record = {
                        "collected_at": datetime.now(
                            timezone.utc
                        ).isoformat(),
                        "host": event.get("_HOSTNAME", "unknown"),
                        "source": event.get("SYSLOG_IDENTIFIER", "unknown"),
                        "unit": event.get("_SYSTEMD_UNIT", ""),
                        "pid": event.get("_PID", ""),
                        "priority": event.get("PRIORITY", ""),
                        "categories": categories,
                        "message": message,
                        "journal_cursor": cursor,
                    }
                    output.write(json.dumps(record) + "\n")
                    output.flush()
                    os.fsync(output.fileno())
                    written_cursors.add(cursor)
                    print(
                        f"[{','.join(categories)}] "
                        f"{record['source']}: {message}",
                        flush=True,
                    )

                # Save progress only after any matching event is durable.
                save_checkpoint(checkpoint_path, cursor)

    except KeyboardInterrupt:
        print("\nCollector stopped.", flush=True)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if process.stdout:
            process.stdout.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())