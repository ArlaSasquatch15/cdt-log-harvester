# cdt-log-harvester
log harvester initial implementation code

# CDT Security Log Harvester

A Python-based defensive security log collector that monitors Linux system journal events, classifies messages using configurable rules, and records matching events as JSON Lines (JSONL).

## Features

- Collects events from the systemd journal.
- Classifies events using configurable, case-insensitive rules.
- Supports custom matching rules.
- Records structured event metadata, including timestamps, host, source, severity, categories, and journal cursor.
- Uses checkpoints to resume collection.
- Includes systemd service management and automatic restart after failures.
- Supports Ansible-based deployment.
- Validates Python syntax and JSON configuration before deployment.

## Project structure

```text
cdt-log-harvester/
├── collector.py
├── config.json
├── cdt-log-harvester.service
├── deploy.yml
├── inventory.example.ini
├── README.md
└── .gitignore
```

## Requirements

- Linux system using systemd and the systemd journal.
- Python 3.
- Ansible on the deployment machine.
- Appropriate privileges to read required journal entries and install the service.
- Authorized access to any remote machines being managed.

## Configuration

Rules are defined in config.json.

The default categories include: authentication_failure, privilege_activity, service_failure, custom_test

Each category contains message patterns used to classify matching journal events. Add or modify patterns to suit your monitoring requirements.

The configured output path is: output/security-events.jsonl

Each matching event is written as a JSON object on its own line.

## Local validation

Validate the Python source:

```python3 -m py_compile collector.py```

Validate the configuration:

```python3 -m json.tool config.json```

Validate the Ansible playbook:

```ansible-playbook -i inventory.example.ini deploy.yml --syntax-check```

## Deployment

The example inventory targets localhost for development and testing.

Deploy locally with:

```ansible-playbook -i inventory.example.ini deploy.yml```

The playbook installs the collector under /opt/cdt-log-harvester, configures the systemd service, and enables and starts the service.

For remote deployment, create a private inventory.ini containing authorized target hosts and the appropriate SSH connection settings. Verify connectivity and privileges before deployment.

Do not commit private inventory files, credentials, collected logs, or runtime checkpoints.

## Service management

Check service status:

```systemctl status cdt-log-harvester.service```

Check recent service messages:

```journalctl -u cdt-log-harvester.service -n 50 --no-pager```

Restart the service:

```sudo systemctl restart cdt-log-harvester.service```

Check whether it is active:

```systemctl is-active cdt-log-harvester.service```

## Output and runtime state

The collector maintains JSONL output and checkpoint state in its configured working directory. Preserve these files when continuity of collection matters.

Plan and configure log rotation, retention, and disk-space monitoring before production use.

## Security considerations

- Deploy only to systems you are authorized to administer.
- Protect logs because they may contain sensitive operational information.
- Restrict access to configuration, logs, and checkpoint files.
- Use authenticated SSH for remote deployment.
- Monitor service failures and unexpected configuration changes.
- Test recovery behavior in a controlled environment.
- Review privilege requirements before deploying beyond a lab environment.
- Do not treat automatic service restart as protection against tampering or deliberate removal.

## Limitations

This project currently provides local journal collection and Ansible-based installation. Centralized log forwarding, remote health monitoring, log rotation, and centralized tamper detection require additional configuration or implementation.

## Project status

Core collection, rule matching, checkpointing, and local service deployment have been tested in a Linux lab environment. Validate the deployment and security requirements of each target environment before operational use.
