# ClawLab Audit

Lightweight execution auditing for Python applications and AI agents.

ClawLab Audit records function executions in a local JSON journal, tracks execution metadata and provides tools for integrity verification, filtering, statistics, anomaly detection and report generation.

## Features

- Unique operation identifiers.
- UTC timestamps.
- Success and error recording.
- Execution duration measurement.
- Support for synchronous and asynchronous functions.
- Optional agent, model and tool metadata.
- Local JSON journal with SHA-256 hash chaining.
- Journal integrity verification.
- Operation search and detailed inspection.
- Filtering by agent, model, tool, result and date.
- JSON and CSV exports.
- HTML report generation.
- Execution statistics.
- Basic anomaly detection.
- Local journal backup and recovery.

## Installation

Install from PyPI:

```bash
pip install clawlab-audit
```

Or install the local development version:

```bash
git clone https://github.com/jibee950/clawlab-audit.git
cd clawlab-audit
python -m pip install -e .
```

## Quick start

```python
from clawlab import auditer, rapport

@auditer
def calculate():
    return 25 * 4

result = calculate()

print("Result:", result)
rapport()
```

Each execution is recorded automatically, including its status (success or error), execution duration and optional metadata. The function's return value is passed back to the caller but is not stored in the journal.

## Auditing AI agents and tools

You can attach metadata to audited functions:

```python
from clawlab import auditer

@auditer(
    agent="assistant",
    model="gpt-model",
    tool="calculator"
)
def calculate():
    return 25 * 4

calculate()
```

The metadata is stored alongside the execution record.

## Asynchronous functions

ClawLab also supports asynchronous functions:

```python
import asyncio
from clawlab import auditer

@auditer(agent="async-agent")
async def process():
    await asyncio.sleep(1)
    return "completed"

asyncio.run(process())
```

## Integrity verification

Verify the local journal:

```python
from clawlab import verifier_integrite

verifier_integrite()
```

The journal uses a SHA-256 hash chain to detect modifications to recorded entries.

## Search and inspect operations

```python
from clawlab import rechercher_operation, details_operation

operation = rechercher_operation("OPERATION_ID")
details = details_operation("OPERATION_ID")
```

Replace `OPERATION_ID` with an actual operation identifier.

## Filtering operations

```python
from clawlab import filtrer_operations

filtrer_operations(
    agent="assistant",
    resultat="error"
)
```

Available filters:

- `agent`
- `model`
- `tool`
- `resultat`
- `date_debut`
- `date_fin`
- `export`

## Statistics and anomaly detection

Display execution statistics:

```python
from clawlab import statistiques

statistiques()
```

Analyze recent operations:

```python
from clawlab import analyser_anomalies

result = analyser_anomalies(
    fenetre=50,
    facteur_lenteur=3
)

print(result)
```

The anomaly analyzer uses simple heuristics:

- Failure-rate increases are detected by comparing recent operations with the preceding window.
- Slow operations are identified by comparing recent execution times with the median duration across the available history.
- Repeated tool failures are counted across the entire journal; an alert is raised after at least three failures for the same tool.

The analysis is marked as sufficient when at least two complete windows are available (2 × `fenetre` operations). Other checks may still produce alerts with a shorter history. Results are indicative and should not be treated as statistical guarantees.

## Exporting data

Export the journal to JSON:

```python
from clawlab import exporter_json

exporter_json()
```

Export to CSV:

```python
from clawlab import exporter_csv

exporter_csv()
```

Generate an HTML report:

```python
from clawlab import exporter_html

exporter_html()
```

You can also specify a destination:

```python
from pathlib import Path

Path("reports").mkdir(parents=True, exist_ok=True)
exporter_html("reports/audit.html")
```

## Storage

The journal is stored locally at:

```text
~/.config/clawlab/sdk_audit.json
```

ClawLab does not transmit journal data over the network.

## Security limitations

ClawLab uses a local SHA-256 hash chain to detect modifications to journal entries.

This mechanism is not tamper-proof. An attacker with sufficient access can rewrite the journal and recompute its hashes.

The project does not provide cryptographic signatures, external timestamping, remote backups or certified security guarantees.

ClawLab Audit is an execution-auditing utility, not a certified security product.

## Development and tests

Run the test suite from the project directory:

```bash
python -m unittest discover -s tests -v
```

## License

ClawLab Audit is distributed under the MIT License.
See the `LICENSE` file for details.

## Project

GitHub: https://github.com/jibee950/clawlab-audit

Package: https://pypi.org/project/clawlab-audit/

## Version

0.1.0 - Independent development version.
