import base64
import errno
import functools
import math
import os

if os.name == "nt":
    import msvcrt
else:
    import fcntl
import hashlib
import inspect
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

JOURNAL = Path.home() / ".config" / "clawlab" / "sdk_audit.json"
SIGNING_KEY = Path.home() / ".config" / "clawlab" / "audit_signing_key.pem"


def _verrouiller(lock):
    if os.name == "nt":
        # Le fichier est créé par open("a+"). Ne pas lire l'octet ici :
        # sous Windows, un autre thread qui détient déjà le verrou peut
        # rendre cette lecture elle-même fautive avec PermissionError.
        while True:
            lock.seek(0)
            try:
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError as erreur:
                if erreur.errno not in (errno.EACCES, errno.EDEADLK):
                    raise
                # LK_LOCK abandonne après dix tentatives; réessayer le verrou
                # non bloquant évite de perdre un producteur lors d'une écriture lente.
                time.sleep(0.01)
    else:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)


def _deverrouiller(lock):
    if os.name == "nt":
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)



def _empreinte(data):
    contenu = json.dumps(
        data, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(contenu).hexdigest()




def _synchroniser_repertoire(chemin):
    """Synchronise le répertoire après un remplacement atomique."""
    if os.name == "nt":
        return

    descripteur = os.open(str(chemin.parent), os.O_RDONLY)
    try:
        os.fsync(descripteur)
    finally:
        os.close(descripteur)


def _chemin_checkpoint():
    return JOURNAL.with_name(JOURNAL.name + ".checkpoint")


def _chemin_checkpoint_backup():
    return JOURNAL.with_name(JOURNAL.name + ".bak.checkpoint")


def _charger_cle_signature():
    """Charge ou crée la clé Ed25519 locale, séparée des fichiers du journal."""
    SIGNING_KEY.parent.mkdir(parents=True, exist_ok=True)
    try:
        cle = serialization.load_pem_private_key(
            SIGNING_KEY.read_bytes(), password=None
        )
        if not isinstance(cle, Ed25519PrivateKey):
            raise ValueError("La clé locale n'est pas une clé Ed25519.")
        return cle
    except FileNotFoundError:
        cle = Ed25519PrivateKey.generate()
        contenu = cle.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        temporaire = SIGNING_KEY.with_name(
            "." + SIGNING_KEY.name + "." + uuid.uuid4().hex + ".tmp"
        )
        try:
            with temporaire.open("xb") as fichier:
                os.chmod(temporaire, 0o600)
                fichier.write(contenu)
                fichier.flush()
                os.fsync(fichier.fileno())
            try:
                # Lien exclusif : deux premiers démarrages concurrents ne
                # peuvent pas remplacer la clé l'un de l'autre.
                os.link(temporaire, SIGNING_KEY)
            except FileExistsError:
                cle_existante = serialization.load_pem_private_key(
                    SIGNING_KEY.read_bytes(), password=None
                )
                if not isinstance(cle_existante, Ed25519PrivateKey):
                    raise ValueError("La clé locale n'est pas une clé Ed25519.")
                return cle_existante
            _synchroniser_repertoire(SIGNING_KEY)
            return cle
        finally:
            temporaire.unlink(missing_ok=True)


def _instantane_checkpoint(operations):
    return {
        "version": 1,
        "count": len(operations),
        "last_id": operations[-1]["id"] if operations else None,
        "last_hash": operations[-1]["hash"] if operations else "GENESIS",
    }


def _checkpoint_signe(operations):
    instantane = _instantane_checkpoint(operations)
    cle = _charger_cle_signature()
    signature = cle.sign(
        json.dumps(
            instantane, sort_keys=True, ensure_ascii=False
        ).encode("utf-8")
    )
    return {
        "version": 2,
        "snapshot": instantane,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def _verifier_checkpoint_signe(checkpoint):
    if not isinstance(checkpoint, dict) or checkpoint.get("version") != 2:
        return False
    try:
        instantane = checkpoint["snapshot"]
        signature = base64.b64decode(checkpoint["signature"], validate=True)
        cle = _charger_cle_signature()
        cle.public_key().verify(
            signature,
            json.dumps(
                instantane, sort_keys=True, ensure_ascii=False
            ).encode("utf-8"),
        )
        return True
    except (KeyError, TypeError, ValueError, InvalidSignature):
        return False


def _ecrire_checkpoint(operations, chemin=None):
    chemin = chemin or _chemin_checkpoint()
    chemin.parent.mkdir(parents=True, exist_ok=True)
    temporaire = chemin.with_name(
        "." + chemin.name + "." + uuid.uuid4().hex + ".tmp"
    )
    try:
        with temporaire.open("x", encoding="utf-8") as f:
            os.chmod(temporaire, 0o600)
            json.dump(_checkpoint_signe(operations), f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporaire, chemin)
        _synchroniser_repertoire(chemin)
    finally:
        if temporaire.exists():
            temporaire.unlink()


def _verifier_checkpoint(operations, chemin=None):
    chemin = chemin or _chemin_checkpoint()
    try:
        checkpoint = json.loads(chemin.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as erreur:
        raise ValueError("Checkpoint absent ou illisible.") from erreur

    if isinstance(checkpoint, dict) and checkpoint.get("version") == 2:
        if not _verifier_checkpoint_signe(checkpoint):
            raise ValueError("Signature du checkpoint invalide.")
        instantane = checkpoint.get("snapshot")
    else:
        # Migration transparente des checkpoints historiques non signés.
        instantane = checkpoint

    if instantane != _instantane_checkpoint(operations):
        raise ValueError(
            "Checkpoint incohérent : suppression ou modification du journal détectée."
        )
    if not (isinstance(checkpoint, dict) and checkpoint.get("version") == 2):
        _ecrire_checkpoint(operations, chemin)



def _ecrire_sauvegarde_atomique(operations):
    chemin = JOURNAL.with_name(JOURNAL.name + ".bak")
    temporaire = chemin.with_name(
        "." + chemin.name + "." + uuid.uuid4().hex + ".tmp"
    )
    donnees = {
        "version": 2,
        "operations": operations,
        "checkpoint": _checkpoint_signe(operations),
    }
    try:
        with temporaire.open("x", encoding="utf-8") as f:
            os.chmod(temporaire, 0o600)
            json.dump(donnees, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporaire, chemin)
        _synchroniser_repertoire(chemin)
    finally:
        if temporaire.exists():
            temporaire.unlink()


def _charger_sauvegarde(chemin=None):
    chemin = chemin or JOURNAL.with_name(JOURNAL.name + ".bak")
    try:
        donnees = json.loads(chemin.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as erreur:
        raise ValueError("Sauvegarde illisible.") from erreur

    if isinstance(donnees, dict):
        version = donnees.get("version")
        if version not in (1, 2):
            raise ValueError("Version de sauvegarde inconnue.")
        operations = donnees.get("operations")
        checkpoint = donnees.get("checkpoint")
        if not isinstance(operations, list):
            raise ValueError("Format de sauvegarde invalide.")
        if not _verifier_liste_operations(operations):
            raise ValueError("Intégrité de la sauvegarde invalide.")
        if version == 2:
            if (
                not _verifier_checkpoint_signe(checkpoint)
                or checkpoint.get("snapshot") != _instantane_checkpoint(operations)
            ):
                raise ValueError("Checkpoint signé intégré à la sauvegarde invalide.")
        elif checkpoint != _instantane_checkpoint(operations):
            raise ValueError("Checkpoint intégré à la sauvegarde invalide.")

    elif isinstance(donnees, list):
        # Compatibilité avec les anciennes sauvegardes.
        operations = donnees
        if not _verifier_liste_operations(operations):
            raise ValueError("Intégrité de la sauvegarde invalide.")

        ancien_checkpoint = _chemin_checkpoint_backup()
        if ancien_checkpoint.exists():
            _verifier_checkpoint(operations, ancien_checkpoint)
        elif _chemin_checkpoint().exists():
            raise ValueError("Checkpoint de l'ancienne sauvegarde absent.")

    else:
        raise ValueError("Format de sauvegarde invalide.")

    return operations


def _charger_operations():
    checkpoint = _chemin_checkpoint()

    if not JOURNAL.exists():
        if checkpoint.exists():
            raise ValueError("Journal absent alors qu'un checkpoint existe.")
        return []

    try:
        contenu = JOURNAL.read_text(encoding="utf-8")
        operations = json.loads(contenu)
    except (json.JSONDecodeError, UnicodeDecodeError) as erreur:
        raise ValueError("Journal JSON illisible.") from erreur

    if not isinstance(operations, list):
        raise ValueError("Format du journal invalide.")

    if not _verifier_liste_operations(operations):
        raise ValueError("Intégrité du journal invalide.")

    if checkpoint.exists():
        _verifier_checkpoint(operations)
    else:
        if _chemin_checkpoint_backup().exists():
            raise ValueError("Checkpoint principal absent : vérification refusée.")
        sauvegarde = JOURNAL.with_name(JOURNAL.name + ".bak")
        if sauvegarde.exists():
            try:
                donnees_sauvegarde = json.loads(
                    sauvegarde.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError, UnicodeDecodeError) as erreur:
                raise ValueError(
                    "Checkpoint principal absent : sauvegarde illisible."
                ) from erreur

            if not isinstance(donnees_sauvegarde, list):
                raise ValueError(
                    "Checkpoint principal absent : migration refusée."
                )

        # Migration d'un journal historique valide.
        _ecrire_checkpoint(operations)

    return operations



def _remplacer_octets_atomiquement(chemin, contenu):
    temp = chemin.with_name("." + chemin.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temp.open("xb") as fichier:
            os.chmod(temp, 0o600)
            fichier.write(contenu)
            fichier.flush()
            os.fsync(fichier.fileno())
        os.replace(temp, chemin)
        _synchroniser_repertoire(chemin)
    finally:
        if temp.exists():
            temp.unlink()


def _enregistrer(
    action, resultat, duree, erreur=None,
    agent=None, model=None, tool=None
):
    JOURNAL.parent.mkdir(parents=True, exist_ok=True)

    verrou = JOURNAL.with_name(JOURNAL.name + ".lock")
    temporaire = None

    with verrou.open("a+") as lock:
        os.chmod(verrou, 0o600)
        _verrouiller(lock)

        try:
            operations = _charger_operations()
            checkpoint = _chemin_checkpoint()
            ancien_journal = JOURNAL.read_bytes() if JOURNAL.exists() else None
            ancien_checkpoint = checkpoint.read_bytes() if checkpoint.exists() else None
            precedent = operations[-1]["hash"] if operations else "GENESIS"

            operation = {
                "id": str(uuid.uuid4()),
                "date": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "resultat": resultat,
                "duree_ms": round(duree, 2),
                "erreur": erreur,
                "agent": agent,
                "model": model,
                "tool": tool,
                "previous_hash": precedent
            }

            operation["hash"] = _empreinte(operation)
            operations.append(operation)

            temporaire = JOURNAL.with_name(
                "." + JOURNAL.name + "." + uuid.uuid4().hex + ".tmp"
            )

            with temporaire.open("x", encoding="utf-8") as f:
                os.chmod(temporaire, 0o600)
                json.dump(operations, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # Sauvegarde atomique du journal précédent.
            if JOURNAL.exists():
                _ecrire_sauvegarde_atomique(operations[:-1])

            os.replace(temporaire, JOURNAL)
            _synchroniser_repertoire(JOURNAL)
            temporaire = None
            try:
                _ecrire_checkpoint(operations)
            except Exception as erreur_checkpoint:
                erreurs_retour = []

                try:
                    if ancien_checkpoint is None:
                        checkpoint.unlink(missing_ok=True)
                    else:
                        _remplacer_octets_atomiquement(checkpoint, ancien_checkpoint)
                except Exception as retour:
                    erreurs_retour.append("checkpoint : " + str(retour))

                try:
                    if ancien_journal is None:
                        JOURNAL.unlink(missing_ok=True)
                    else:
                        _remplacer_octets_atomiquement(JOURNAL, ancien_journal)
                except Exception as retour:
                    erreurs_retour.append("journal : " + str(retour))

                if erreurs_retour:
                    raise RuntimeError(
                        "Échec du checkpoint et du retour arrière : "
                        + "; ".join(erreurs_retour)
                    ) from erreur_checkpoint
                raise

        finally:
            if temporaire is not None and temporaire.exists():
                temporaire.unlink()

            _deverrouiller(lock)



def auditer(
    fonction=None, *, nom=None, agent=None, model=None, tool=None
):
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
                        type(erreur).__name__,
                        agent, model, tool
                    )
                    raise

                _enregistrer(
                    action, "success",
                    (time.perf_counter() - debut) * 1000,
                    agent=agent, model=model, tool=tool
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
                    type(erreur).__name__,
                    agent, model, tool
                )
                raise

            _enregistrer(
                action, "success",
                (time.perf_counter() - debut) * 1000,
                agent=agent, model=model, tool=tool
            )
            return resultat

        return wrapper

    return decorateur(fonction) if fonction else decorateur


def verifier_integrite():
    operations = _charger_operations()
    precedent = "GENESIS"

    for operation in operations:
        empreinte_stockee = operation.get("hash")
        contenu = {
            k: v for k, v in operation.items() if k != "hash"
        }

        if operation.get("previous_hash") != precedent:
            print("Intégrité : ÉCHEC")
            return False

        if _empreinte(contenu) != empreinte_stockee:
            print("Intégrité : ÉCHEC")
            return False

        precedent = empreinte_stockee

    print("Intégrité :", "VALIDÉE")
    return True


def rapport():
    operations = _charger_operations()

    if not operations:
        print("Aucune opération enregistrée.")
        return

    succes = sum(o["resultat"] == "success" for o in operations)
    echecs = sum(o["resultat"] == "error" for o in operations)

    print("===== RAPPORT CLAWLAB SDK =====")
    print("Opérations :", len(operations))
    print("Succès :", succes)
    print("Échecs :", echecs)
    verifier_integrite()


def rechercher_operation(operation_id):
    for operation in _charger_operations():
        if operation.get("id") == operation_id:
            print(json.dumps(operation, ensure_ascii=False, indent=2))
            return operation

    print("Aucune opération trouvée.")
    return None


def details_operation(operation_id):
    operation = rechercher_operation(operation_id)
    if operation is not None:
        print("Action :", operation["action"])
        print("Résultat :", operation["resultat"])
        print("Date :", operation["date"])
        print("Durée :", operation["duree_ms"], "ms")
    return operation


def exporter_json(destination="clawlab_export.json"):
    if not JOURNAL.exists():
        print("Aucune opération à exporter.")
        return

    operations = _charger_operations()
    fichier = Path(destination).expanduser()
    fichier.parent.mkdir(parents=True, exist_ok=True)
    fichier.write_text(
        json.dumps(operations, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    print(f"Export terminé : {fichier.resolve()}")
    print(f"Opérations exportées : {len(operations)}")
    return fichier


def exporter_html(destination="clawlab_report.html"):
    from html import escape

    operations = _charger_operations()

    if not operations:
        print("Aucune opération à exporter.")
        return None

    precedent = "GENESIS"
    integrite = True

    for operation in operations:
        contenu = {
            k: v for k, v in operation.items() if k != "hash"
        }
        if (
            operation.get("previous_hash") != precedent
            or _empreinte(contenu) != operation.get("hash")
        ):
            integrite = False
            break
        precedent = operation.get("hash")

    succes = sum(o.get("resultat") == "success" for o in operations)
    echecs = sum(o.get("resultat") == "error" for o in operations)
    total = len(operations)
    taux = round(succes / total * 100, 1) if total else 0

    from contextlib import redirect_stdout
    from io import StringIO

    with redirect_stdout(StringIO()):
        analyse = analyser_anomalies()

    alertes = analyse.get("alertes", [])
    analyse_suffisante = analyse.get("analyse_suffisante", False)

    if analyse_suffisante:
        titre_analyse = "Analyse des anomalies"
        statut_analyse = "Historique suffisant"
    else:
        titre_analyse = "Analyse indicative"
        statut_analyse = (
            "Historique insuffisant pour une comparaison fiable"
        )

    alertes_normales = []
    alertes_critiques = []

    for alerte in alertes:
        texte = str(alerte)
        if texte.startswith("Échecs répétés :"):
            alertes_critiques.append(texte)
        else:
            alertes_normales.append(texte)

    alertes_html = "".join(
        f"<li>{escape(alerte)}</li>"
        for alerte in alertes_normales
    )

    alertes_critiques_html = "".join(
        f'<div class="critical-alert">'
        f'<strong>ALERTE OUTIL</strong>'
        f'<p>{escape(alerte)}</p>'
        f'</div>'
        for alerte in alertes_critiques
    )

    taux_recent = analyse.get("taux_echec_recent")
    taux_html = (
        f"<p>Taux d'échec récent : <strong>{taux_recent}%</strong></p>"
        if taux_recent is not None else ""
    )

    anomalies_html = (
        '<section class="card anomalies">'
        f"<h2>{titre_analyse}</h2>"
        f"<p>{escape(statut_analyse)}</p>"
        f"{taux_html}"
        f"{alertes_critiques_html}"
        f"<ul>{alertes_html}</ul>"
        "</section>"
    )


    from collections import Counter

    durees = []
    for op in operations:
        try:
            durees.append(float(op.get("duree_ms", 0)))
        except (TypeError, ValueError):
            pass

    moyenne = round(sum(durees) / len(durees), 2) if durees else 0
    maximum = round(max(durees), 2) if durees else 0

    plus_lente = max(
        operations,
        key=lambda o: float(o.get("duree_ms") or 0)
    )

    def bloc_repartition(champ, titre):
        compteurs = Counter(
            str(op.get(champ) or "Non renseigné")
            for op in operations
        )
        elements = "".join(
            f"<li>{escape(nom)} : <strong>{nombre}</strong></li>"
            for nom, nombre in compteurs.most_common()
        )
        return (
            f'<section class="card"><h3>{titre}</h3>'
            f'<ul>{elements}</ul></section>'
        )

    stats_html = (
        '<div class="cards">'
        f'<div class="card">Durée moyenne<div class="number">{moyenne} ms</div></div>'
        f'<div class="card">Durée maximale<div class="number">{maximum} ms</div></div>'
        f'<div class="card">Fonction la plus lente<div>{escape(str(plus_lente.get("action", "—")))}</div></div>'
        '</div>'
        '<h2>Répartition des opérations</h2>'
        '<div class="cards">'
        + bloc_repartition("agent", "Agents")
        + bloc_repartition("model", "Modèles")
        + bloc_repartition("tool", "Outils")
        + '</div>'
    )

    lignes = []
    for op in reversed(operations):
        resultat = str(op.get("resultat", "inconnu"))
        classe = "success" if resultat == "success" else "error"
        lignes.append(
            "<tr>"
            f'<td data-label="Date">{escape(str(op.get("date", "")))}</td>'
            f'<td data-label="Action">{escape(str(op.get("action", "")))}</td>'
            f'<td data-label="Résultat"><span class="badge {classe}">{escape(resultat)}</span></td>'
            f'<td data-label="Durée">{escape(str(op.get("duree_ms", "")))} ms</td>'
            f'<td data-label="Erreur">{escape(str(op.get("erreur") or "—"))}</td>'
            f'<td data-label="Agent">{escape(str(op.get("agent") or "—"))}</td>'
            f'<td data-label="Modèle">{escape(str(op.get("model") or "—"))}</td>'
            f'<td data-label="Outil">{escape(str(op.get("tool") or "—"))}</td>'
            f'<td data-label="ID">{escape(str(op.get("id", "")))}</td>'
            "</tr>"
        )

    statut = "VALIDÉE" if integrite else "ÉCHEC"
    couleur = "success" if integrite else "error"

    page = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClawLab Audit</title>
<style>
body {{font-family:Arial,sans-serif;background:#f3f4f6;color:#20242c;
margin:0;padding:20px}}
main {{max-width:1100px;margin:auto}}
h1 {{margin-bottom:5px}}
.subtitle {{color:#667085}}
.cards {{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
gap:12px;margin:25px 0}}
.card {{background:white;padding:18px;border-radius:12px}}
.number {{font-size:27px;font-weight:bold;margin-top:8px}}
table {{width:100%;border-collapse:collapse;background:white}}
th,td {{padding:12px;text-align:left;border-bottom:1px solid #eee;
font-size:13px;overflow-wrap:anywhere}}
th {{background:#e9edf3}}
.badge {{padding:5px 8px;border-radius:6px;font-weight:bold}}
.success {{color:#087443;background:#dcfce7}}
.error {{color:#b42318;background:#fee4e2}}
.status {{font-weight:bold}}
.anomalies {{margin-top:20px}}
.anomalies li {{margin:8px 0}}
.critical-alert {{
    background:#fee4e2;
    color:#b42318;
    border-left:5px solid #b42318;
    padding:12px;
    margin:12px 0;
    border-radius:8px;
}}
.critical-alert p {{margin-bottom:0}}


.table-wrap {{overflow-x:auto;border-radius:12px}}
footer {{margin-top:20px;color:#667085;font-size:12px}}

@media (max-width: 600px) {{
    body {{ padding: 12px; }}
    h1 {{ font-size: 24px; }}
    h2 {{ font-size: 19px; }}
    .cards {{ grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }}
    .card {{ padding: 13px; min-width: 0; }}
    .number {{ font-size: 23px; }}
    .table-wrap {{ overflow: visible; }}
    table, tbody {{ display: block; width: 100%; }}
    thead {{ display: none; }}
    tr {{
        display: block;
        background: white;
        border-radius: 12px;
        padding: 8px 12px;
        margin-bottom: 12px;
    }}
    td {{
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 10px;
        padding: 9px 2px;
        font-size: 12px;
        overflow-wrap: anywhere;
        text-align: right;
    }}
    td::before {{
        content: attr(data-label);
        font-weight: bold;
        color: #667085;
        flex: 0 0 75px;
        text-align: left;
    }}
}}

</style>
</head>
<body>
<main>
<h1>ClawLab Audit</h1>
<p class="subtitle">Rapport local des opérations enregistrées</p>
<div class="cards">
<div class="card">Opérations<div class="number">{total}</div></div>
<div class="card">Succès<div class="number">{succes}</div></div>
<div class="card">Échecs<div class="number">{echecs}</div></div>
<div class="card">Taux de succès<div class="number">{taux}%</div></div>
</div>
<div class="card">
<strong>Contrôle de la chaîne de hachage :</strong>
<span class="status {couleur}">{statut}</span>
</div>
{stats_html}\n{anomalies_html}\n<h2>Historique des opérations</h2>
<div class="table-wrap">
<table>
<thead><tr>
<th>Date</th><th>Action</th><th>Résultat</th>
<th>Durée</th><th>Erreur</th>
<th>Agent</th><th>Modèle</th><th>Outil</th><th>ID</th>
</tr></thead>
<tbody>{''.join(lignes)}</tbody>
</table>
</div>
<footer>ClawLab Audit — rapport généré localement.
La validation de la chaîne ne garantit pas à elle seule l'inaltérabilité du journal.</footer>
</main>
</body>
</html>"""

    fichier = Path(destination).expanduser()
    fichier.parent.mkdir(parents=True, exist_ok=True)
    fichier.write_text(page, encoding="utf-8")

    print(f"Rapport HTML créé : {fichier.resolve()}")
    return fichier


def statistiques():
    from collections import Counter

    operations = _charger_operations()

    if not operations:
        print("Aucune opération à analyser.")
        return None

    succes = sum(o.get("resultat") == "success" for o in operations)
    echecs = sum(o.get("resultat") == "error" for o in operations)

    durees = []
    for op in operations:
        try:
            durees.append(float(op.get("duree_ms", 0)))
        except (TypeError, ValueError):
            pass

    def compter(champ):
        return dict(Counter(
            str(o.get(champ) or "Non renseigné")
            for o in operations
        ))

    plus_lente = max(
        operations,
        key=lambda o: float(o.get("duree_ms") or 0)
    )

    resultat = {
        "operations": len(operations),
        "succes": succes,
        "echecs": echecs,
        "taux_succes": round(succes / len(operations) * 100, 2),
        "duree_moyenne_ms": round(sum(durees) / len(durees), 2) if durees else 0,
        "duree_max_ms": max(durees) if durees else 0,
        "operation_plus_lente": plus_lente.get("action"),
        "agents": compter("agent"),
        "modeles": compter("model"),
        "outils": compter("tool")
    }

    print("===== STATISTIQUES CLAWLAB =====")
    print("Opérations :", resultat["operations"])
    print("Succès :", succes)
    print("Échecs :", echecs)
    print("Taux de réussite :", resultat["taux_succes"], "%")
    print("Durée moyenne :", resultat["duree_moyenne_ms"], "ms")
    print("Durée maximale :", resultat["duree_max_ms"], "ms")
    print("Opération la plus lente :", resultat["operation_plus_lente"])

    for champ in ("agents", "modeles", "outils"):
        print("\n" + champ.upper())
        for nom, nombre in resultat[champ].items():
            print(f"  {nom} : {nombre}")

    return resultat


def exporter_csv(destination="clawlab_export.csv"):
    import csv

    operations = _charger_operations()

    if not operations:
        print("Aucune opération à exporter.")
        return None

    fichier = Path(destination).expanduser()
    fichier.parent.mkdir(parents=True, exist_ok=True)

    champs = [
        "id",
        "date",
        "action",
        "agent",
        "model",
        "tool",
        "resultat",
        "duree_ms",
        "erreur",
        "previous_hash",
        "hash"
    ]

    with fichier.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=champs,
            extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(operations)

    print("Export CSV terminé :", fichier.resolve())
    print("Opérations exportées :", len(operations))
    return fichier



def filtrer_operations(
    agent=None,
    model=None,
    tool=None,
    resultat=None,
    date_debut=None,
    date_fin=None,
    export=None
):
    operations = _charger_operations()

    def correspond(valeur, filtre):
        if filtre is None:
            return True
        return filtre.lower() in str(valeur or "").lower()

    filtres = []

    for op in operations:
        if not correspond(op.get("agent"), agent):
            continue
        if not correspond(op.get("model"), model):
            continue
        if not correspond(op.get("tool"), tool):
            continue
        if not correspond(op.get("resultat"), resultat):
            continue

        date = op.get("date", "")[:10]

        if date_debut and date < date_debut:
            continue
        if date_fin and date > date_fin:
            continue

        filtres.append(op)

    print("===== RECHERCHE CLAWLAB =====")
    print("Résultats :", len(filtres))

    for op in filtres:
        print(
            op.get("date", ""),
            "|", op.get("action", ""),
            "|", op.get("resultat", ""),
            "| Agent :", op.get("agent") or "Non renseigné"
        )

    if export and filtres:
        import csv

        destination = Path(export).expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)

        champs = [
            "id", "date", "action", "agent", "model",
            "tool", "resultat", "duree_ms", "erreur",
            "previous_hash", "hash"
        ]

        with destination.open(
            "w", encoding="utf-8-sig", newline=""
        ) as f:
            writer = csv.DictWriter(f, fieldnames=champs)
            writer.writeheader()
            writer.writerows(filtres)

        print("Export filtré :", destination.resolve())
        print("Opérations exportées :", len(filtres))

    elif export:
        print("Aucune opération à exporter.")

    return filtres


def _verifier_liste_operations(operations):
    if not isinstance(operations, list):
        return False

    precedent = "GENESIS"

    anciens_champs = {
        "id", "date", "action", "resultat",
        "duree_ms", "erreur", "previous_hash", "hash"
    }

    nouveaux_champs = anciens_champs | {
        "agent", "model", "tool"
    }

    try:
        for operation in operations:
            if not isinstance(operation, dict):
                return False

            champs = set(operation.keys())

            if champs not in (anciens_champs, nouveaux_champs):
                return False

            for champ in ("id", "date", "action", "resultat"):
                valeur = operation[champ]
                if not isinstance(valeur, str) or not valeur.strip():
                    return False

            for champ in ("erreur", "agent", "model", "tool"):
                if champ in operation:
                    valeur = operation[champ]
                    if valeur is not None and not isinstance(valeur, str):
                        return False

            duree = operation["duree_ms"]
            if (
                isinstance(duree, bool)
                or not isinstance(duree, (int, float))
                or not math.isfinite(duree)
                or duree < 0
            ):
                return False

            datetime.fromisoformat(operation["date"])

            if operation["previous_hash"] != precedent:
                return False

            contenu = {
                k: v for k, v in operation.items()
                if k != "hash"
            }

            if not isinstance(operation["hash"], str):
                return False

            if _empreinte(contenu) != operation["hash"]:
                return False

            precedent = operation["hash"]

        return True

    except Exception:
        return False


def restaurer_sauvegarde():
    JOURNAL.parent.mkdir(parents=True, exist_ok=True)

    backup = JOURNAL.with_name(JOURNAL.name + ".bak")
    checkpoint = _chemin_checkpoint()
    verrou = JOURNAL.with_name(JOURNAL.name + ".lock")
    temporaire = None

    def remplacer_octets(chemin, contenu):
        temp = chemin.with_name(
            "." + chemin.name + "." + uuid.uuid4().hex + ".tmp"
        )
        try:
            with temp.open("xb") as f:
                os.chmod(temp, 0o600)
                f.write(contenu)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, chemin)
            _synchroniser_repertoire(chemin)
        finally:
            if temp.exists():
                temp.unlink()

    with verrou.open("a+") as lock:
        os.chmod(verrou, 0o600)
        _verrouiller(lock)

        try:
            if JOURNAL.exists():
                try:
                    _charger_operations()
                    print("Journal actuel valide. Restauration inutile.")
                    return False
                except (ValueError, OSError):
                    pass

            try:
                operations = _charger_sauvegarde(backup)
            except (ValueError, OSError) as erreur:
                print("Sauvegarde invalide :", erreur)
                return False

            ancien_journal = (
                JOURNAL.read_bytes() if JOURNAL.exists() else None
            )
            ancien_checkpoint = (
                checkpoint.read_bytes() if checkpoint.exists() else None
            )

            if ancien_journal is not None:
                corrompu = JOURNAL.with_name(
                    JOURNAL.name + ".corrompu-" + uuid.uuid4().hex
                )
                remplacer_octets(corrompu, ancien_journal)
                print("Ancien journal préservé :", corrompu)

            contenu = json.dumps(
                operations, ensure_ascii=False, indent=2
            ).encode("utf-8")

            temporaire = JOURNAL.with_name(
                "." + JOURNAL.name + "." + uuid.uuid4().hex + ".tmp"
            )

            with temporaire.open("xb") as f:
                os.chmod(temporaire, 0o600)
                f.write(contenu)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temporaire, JOURNAL)
            _synchroniser_repertoire(JOURNAL)
            temporaire = None

            try:
                _ecrire_checkpoint(operations)
            except Exception as erreur:
                erreurs_retour = []

                try:
                    if ancien_checkpoint is None:
                        checkpoint.unlink(missing_ok=True)
                    else:
                        remplacer_octets(checkpoint, ancien_checkpoint)
                except Exception as retour:
                    erreurs_retour.append("checkpoint : " + str(retour))

                try:
                    if ancien_journal is None:
                        JOURNAL.unlink(missing_ok=True)
                    else:
                        remplacer_octets(JOURNAL, ancien_journal)
                except Exception as retour:
                    erreurs_retour.append("journal : " + str(retour))

                if erreurs_retour:
                    raise RuntimeError(
                        "Échec du checkpoint et du retour arrière : "
                        + "; ".join(erreurs_retour)
                    ) from erreur

                raise

            print("Restauration effectuée.")
            print("Opérations restaurées :", len(operations))
            return True

        finally:
            if temporaire is not None and temporaire.exists():
                temporaire.unlink()
            _deverrouiller(lock)


def analyser_anomalies(fenetre=50, facteur_lenteur=3):
    """Analyse les opérations récentes et signale les anomalies."""
    if not isinstance(fenetre, int) or isinstance(fenetre, bool) or fenetre < 2:
        raise ValueError("fenetre doit être un entier supérieur ou égal à 2")

    if not isinstance(facteur_lenteur, (int, float)) or isinstance(facteur_lenteur, bool) or facteur_lenteur <= 1:
        raise ValueError("facteur_lenteur doit être supérieur à 1")

    from collections import Counter
    from statistics import median

    operations = _charger_operations()

    resultat = {
        "operations_analysees": len(operations),
        "alertes": [],
        "analyse_suffisante": len(operations) >= fenetre * 2,
    }

    if not operations:
        resultat["alertes"].append("Aucune opération à analyser.")
        return resultat

    recentes = operations[-fenetre:]
    precedentes = operations[-2 * fenetre:-fenetre]

    echecs_recents = sum(o.get("resultat") == "error" for o in recentes)
    taux_recent = echecs_recents / len(recentes) * 100

    resultat["taux_echec_recent"] = round(taux_recent, 2)

    if precedentes:
        echecs_precedents = sum(
            o.get("resultat") == "error" for o in precedentes
        )
        taux_precedent = echecs_precedents / len(precedentes) * 100
        resultat["taux_echec_precedent"] = round(taux_precedent, 2)

        if len(recentes) == fenetre and taux_recent - taux_precedent >= 20:
            resultat["alertes"].append(
                "Hausse du taux d'échec : "
                f"{taux_precedent:.1f}% à {taux_recent:.1f}%."
            )

    durees = [
        float(o["duree_ms"])
        for o in operations
        if isinstance(o.get("duree_ms"), (int, float))
        and not isinstance(o.get("duree_ms"), bool)
        and o["duree_ms"] >= 0
    ]

    if len(durees) >= 3:
        duree_mediane = median(durees)
        resultat["duree_mediane_ms"] = round(duree_mediane, 2)

        if duree_mediane > 0:
            lentes = [
                {
                    "action": o.get("action"),
                    "duree_ms": o.get("duree_ms"),
                    "tool": o.get("tool"),
                }
                for o in recentes
                if float(o.get("duree_ms", 0)) >
                duree_mediane * facteur_lenteur
            ]

            resultat["operations_lentes"] = lentes

            if lentes:
                resultat["alertes"].append(
                    f"{len(lentes)} opération(s) anormalement lente(s)."
                )

    outils_en_echec = Counter(
        o["tool"].strip()
        for o in operations
        if o.get("resultat") == "error"
        and isinstance(o.get("tool"), str)
        and o["tool"].strip()
    )

    echecs_sans_outil = sum(
        o.get("resultat") == "error"
        and not (
            isinstance(o.get("tool"), str)
            and o["tool"].strip()
        )
        for o in operations
    )

    resultat["outils_en_echec"] = dict(outils_en_echec.most_common())
    resultat["echecs_sans_outil"] = echecs_sans_outil

    if outils_en_echec:
        outil, nombre = outils_en_echec.most_common(1)[0]
        resultat["outil_le_plus_en_echec"] = {
            "outil": outil,
            "echecs": nombre,
        }

    for outil, nombre in outils_en_echec.items():
        if nombre >= 3:
            resultat["alertes"].append(
                f"Échecs répétés : l'outil {outil} a échoué "
                f"{nombre} fois."
            )

    if not resultat["alertes"]:
        resultat["alertes"].append("Aucune anomalie détectée.")

    print("===== ANALYSE DES ANOMALIES CLAWLAB =====")
    print("Opérations analysées :", len(operations))
    print("Analyse suffisante :", resultat["analyse_suffisante"])

    for alerte in resultat["alertes"]:
        print("-", alerte)

    return resultat
