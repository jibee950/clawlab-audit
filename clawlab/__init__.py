import functools
import hashlib
import inspect
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

JOURNAL = Path.home() / ".config" / "clawlab" / "sdk_audit.json"


def _empreinte(data):
    contenu = json.dumps(
        data, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(contenu).hexdigest()


def _enregistrer(action, resultat, duree, erreur=None):
    JOURNAL.parent.mkdir(parents=True, exist_ok=True)

    operations = []
    if JOURNAL.exists():
        operations = json.loads(JOURNAL.read_text(encoding="utf-8"))

    precedent = operations[-1]["hash"] if operations else "GENESIS"

    operation = {
        "id": str(uuid.uuid4()),
        "date": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "resultat": resultat,
        "duree_ms": round(duree, 2),
        "erreur": erreur,
        "previous_hash": precedent
    }

    operation["hash"] = _empreinte(operation)
    operations.append(operation)

    JOURNAL.write_text(
        json.dumps(operations, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def auditer(fonction=None, *, nom=None):
    def decorateur(func):
        action = nom or f"{func.__module__}.{func.__qualname__}"

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                debut = time.perf_counter()
                try:
                    resultat = await func(*args, **kwargs)
                except Exception as erreur:
                    _enregistrer(
                        action, "error",
                        (time.perf_counter() - debut) * 1000,
                        type(erreur).__name__
                    )
                    raise

                _enregistrer(
                    action, "success",
                    (time.perf_counter() - debut) * 1000
                )
                return resultat

            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            debut = time.perf_counter()
            try:
                resultat = func(*args, **kwargs)
            except Exception as erreur:
                _enregistrer(
                    action, "error",
                    (time.perf_counter() - debut) * 1000,
                    type(erreur).__name__
                )
                raise

            _enregistrer(
                action, "success",
                (time.perf_counter() - debut) * 1000
            )
            return resultat

        return wrapper

    return decorateur(fonction) if fonction else decorateur


def rapport():
    if not JOURNAL.exists():
        print("Aucune opération enregistrée.")
        return

    operations = json.loads(JOURNAL.read_text(encoding="utf-8"))
    succes = sum(o["resultat"] == "success" for o in operations)
    echecs = sum(o["resultat"] == "error" for o in operations)

    precedent = "GENESIS"
    valide = True

    for operation in operations:
        empreinte_stockee = operation["hash"]
        contenu = {k: v for k, v in operation.items() if k != "hash"}

        if operation["previous_hash"] != precedent:
            valide = False
            break

        if _empreinte(contenu) != empreinte_stockee:
            valide = False
            break

        precedent = empreinte_stockee

    print("===== RAPPORT CLAWLAB SDK =====")
    print("Opérations :", len(operations))
    print("Succès :", succes)
    print("Échecs :", echecs)
    print("Intégrité :", "VALIDÉE" if valide else "ÉCHEC")
