# ClawLab Audit

Lightweight execution auditing for Python applications and AI agents.

## Features

- Unique operation identifiers.
- UTC timestamps.
- Success and error recording.
- Execution duration.
- Local SHA-256 hash-chained journal.
- Journal integrity verification.
- Synchronous and asynchronous functions.

## Installation

After publication on PyPI:

    pip install clawlab-audit

For now, install the local package:

    python -m pip install ~/clawlab-distribution/dist/clawlab_audit-0.1.0-py3-none-any.whl

## Usage

    from clawlab import auditer, rapport

    @auditer
    def calculer():
        return 25 * 4

    print("Result:", calculer())
    rapport()

## Storage

The journal is stored locally at:

    ~/.config/clawlab/sdk_audit.json

No network transmission is performed by the module.

## Security limitations

The journal uses SHA-256 hash chaining to detect modifications.
It is not tamper-proof against an attacker able to rewrite the journal
and recompute its hashes. It is not a certified security product.

## Version

0.1.0 - Independent prototype.
