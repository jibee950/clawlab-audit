# ClawLab Audit

**Lightweight execution auditing for Python applications and AI agents.**

ClawLab Audit helps developers understand what their Python functions and AI agent tools are doing.

It records executions in a local JSON journal, tracks success and failure, measures execution time and provides tools to inspect operations, detect basic anomalies and generate reports.

No external logging service. No remote data transmission. Your journal stays local.

## Why ClawLab Audit?

When a Python application or AI agent executes multiple functions and tools, it can become difficult to understand what happened when something fails.

ClawLab Audit provides a simple execution history to help developers:

- Identify failed function executions.
- Measure execution duration.
- Track agent, model and tool metadata.
- Inspect individual operations.
- Detect basic execution anomalies.
- Verify journal integrity.
- Export execution data for further analysis.

It is designed to be lightweight and easy to integrate into existing Python projects.

## Features

- Unique operation identifiers.
- UTC timestamps.
- Success and error recording.
- Execution duration measurement.
- Synchronous and asynchronous function support.
- Optional agent, model and tool metadata.
- Local JSON journal.
- SHA-256 hash-chain integrity verification.
- Operation search and detailed inspection.
- Filtering by agent, model, tool, result and date.
- JSON and CSV exports.
- HTML report generation.
- Execution statistics.
- Basic anomaly detection.
- Local journal backup and recovery.

## Installation

Install the published package from PyPI:

```bash
pip install clawlab-audit
```

Or install the development version from GitHub:

```bash
git clone https://github.com/jibee950/clawlab-audit.git
cd clawlab-audit
python -m pip install -e .
```

## Quick start

Import the decorator and apply it to a function:

```python
from clawlab import auditer, rapport

@auditer
def calculate():
    return 25 * 4

result = calculate()

print("Result:", result)
rapport()
```

Each execution is recorded with its status, duration and metadata.

The function's return value is passed back to the caller but is not stored in the journal.

Exceptions are recorded and re-raised.

## Auditing AI agents and tools

Attach metadata to functions to identify which agent, model or tool performed an operation:

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

This metadata is stored alongside the execution record and can be used for filtering and analysis.

## Asynchronous functions

ClawLab Audit also supports asynchronous functions:

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

The journal uses a SHA-256 hash chain to help detect modifications to recorded entries.

## Search and inspect operations

Find an operation by its identifier:

```python
from clawlab import rechercher_operation, details_operation

operation = rechercher_operation("OPERATION_ID")
details = details_operation("OPERATION_ID")
```

Replace `OPERATION_ID` with an actual operation identifier.

## Filtering operations

Filter recorded operations:

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
- Slow operations are identified by comparing execution times with the median duration across the available history.
- Repeated tool failures are counted across the entire journal. An alert is raised after at least three failures for the same tool.

The analysis is marked as sufficient when at least two complete windows are available (2 × `fenetre` operations).

Other checks may still produce alerts with a shorter history. Results are indicative and are not statistical guarantees.

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

## Storage and privacy

The journal is stored locally at:

```text
~/.config/clawlab/sdk_audit.json
```

ClawLab Audit does not transmit journal data over the network.

Your execution records remain on your machine unless you choose to export or share them.

## Data integrity and privacy

ClawLab Audit is designed with local-first data storage.

- **Local storage:** execution records remain on your machine.
- **Integrity checks:** SHA-256 hash chaining helps identify changes to recorded entries.
- **Privacy:** no journal data is transmitted to external services.
- **Recovery:** local backups help protect against accidental data loss.

The integrity mechanism is designed to detect modifications, not to provide tamper-proof or certified security. An attacker with direct access to the journal could rewrite it and recompute its hashes.

## Built for developers

ClawLab Audit is a lightweight Python tool designed to fit into existing projects.

- Simple decorator-based integration.
- Support for synchronous and asynchronous functions.
- No external logging infrastructure required.
- JSON, CSV and HTML reporting.
- Automated test suite.

Run the tests locally:

```bash
python -m unittest discover -s tests -v
```

Contributions, feedback and ideas for improvement are welcome.

## License

ClawLab Audit is distributed under the MIT License.

See the `LICENSE` file for details.

## Project links

- GitHub: https://github.com/jibee950/clawlab-audit
- PyPI: https://pypi.org/project/clawlab-audit/

## Version

Current release version: **0.2.0**

This release includes expanded auditing, reporting and anomaly detection features.
