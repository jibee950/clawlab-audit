import asyncio
import contextlib
import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import clawlab


class ClawLabTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        self.ancienne_cle = clawlab.SIGNING_KEY
        clawlab.SIGNING_KEY = Path(self.tempdir.name) / "audit_signing_key.pem"
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        clawlab.SIGNING_KEY = self.ancienne_cle
        self.tempdir.cleanup()

    def test_empreinte_deterministe(self):
        donnees = {"action": "test", "resultat": "success"}
        self.assertEqual(
            clawlab._empreinte(donnees),
            clawlab._empreinte(donnees)
        )

    def test_enregistrement_et_integrite(self):
        clawlab._enregistrer("test", "success", 12.5)

        operations = clawlab._charger_operations()

        self.assertEqual(len(operations), 1)
        self.assertTrue(
            clawlab._verifier_liste_operations(operations)
        )

    def test_detection_modification(self):
        clawlab._enregistrer("test", "success", 10)

        operations = clawlab._charger_operations()
        operations[0]["action"] = "modification"

        self.assertFalse(
            clawlab._verifier_liste_operations(operations)
        )

    def test_decorateur_succes(self):
        @clawlab.auditer(agent="test-agent", model="test-model")
        def calculer():
            return 100

        resultat = calculer()
        operations = clawlab._charger_operations()

        self.assertEqual(resultat, 100)
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]["resultat"], "success")
        self.assertEqual(operations[0]["agent"], "test-agent")

    def test_decorateur_erreur(self):
        @clawlab.auditer
        def echouer():
            raise ValueError("Erreur de test")

        with self.assertRaises(ValueError):
            echouer()

        operations = clawlab._charger_operations()

        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]["resultat"], "error")
        self.assertEqual(operations[0]["erreur"], "ValueError")

    def test_decorateur_asynchrone(self):
        @clawlab.auditer(agent="async-agent")
        async def operation():
            return "ok"

        resultat = asyncio.run(operation())
        operations = clawlab._charger_operations()

        self.assertEqual(resultat, "ok")
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]["resultat"], "success")

    def test_filtrage_et_export_csv(self):
        clawlab._enregistrer(
            "operation_a", "success", 10, agent="alpha"
        )
        clawlab._enregistrer(
            "operation_b", "error", 20, agent="beta"
        )

        destination = Path(self.tempdir.name) / "filtre.csv"

        with contextlib.redirect_stdout(io.StringIO()):
            resultats = clawlab.filtrer_operations(
                agent="alpha",
                export=str(destination)
            )

        self.assertEqual(len(resultats), 1)
        self.assertTrue(destination.exists())

        with destination.open(
            encoding="utf-8-sig", newline=""
        ) as fichier:
            lignes = list(csv.DictReader(fichier))

        self.assertEqual(len(lignes), 1)
        self.assertEqual(lignes[0]["agent"], "alpha")

    def test_exports_json_et_csv(self):
        clawlab._enregistrer("export_test", "success", 5)

        json_path = Path(self.tempdir.name) / "export.json"
        csv_path = Path(self.tempdir.name) / "export.csv"

        with contextlib.redirect_stdout(io.StringIO()):
            clawlab.exporter_json(str(json_path))
            clawlab.exporter_csv(str(csv_path))

        self.assertTrue(json_path.exists())
        self.assertTrue(csv_path.exists())

        donnees = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(len(donnees), 1)

    def test_restaurer_sauvegarde(self):
        clawlab._enregistrer("premiere", "success", 1)
        clawlab._enregistrer("deuxieme", "success", 2)

        backup = clawlab.JOURNAL.with_name(
            clawlab.JOURNAL.name + ".bak"
        )

        self.assertTrue(backup.exists())

        clawlab.JOURNAL.write_text(
            "JOURNAL CORROMPU",
            encoding="utf-8"
        )

        with contextlib.redirect_stdout(io.StringIO()):
            resultat = clawlab.restaurer_sauvegarde()

        operations = clawlab._charger_operations()

        self.assertTrue(resultat)
        self.assertEqual(len(operations), 1)
        self.assertTrue(
            clawlab._verifier_liste_operations(operations)
        )

        copies = list(
            Path(self.tempdir.name).glob("*.corrompu-*")
        )
        self.assertEqual(len(copies), 1)

    def test_ecritures_simultanees(self):
        def enregistrer(numero):
            clawlab._enregistrer(
                f"operation_{numero}", "success", 1
            )

        attendues = {f"operation_{numero}" for numero in range(50)}
        with ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(enregistrer, range(50)))

        operations = clawlab._charger_operations()

        self.assertEqual(len(operations), len(attendues))
        self.assertEqual(
            {operation["action"] for operation in operations}, attendues
        )
        self.assertEqual(
            len({operation["id"] for operation in operations}),
            len(attendues)
        )
        self.assertTrue(
            clawlab._verifier_liste_operations(operations)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)


class ClawLabAdvancedTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        self.ancienne_cle = clawlab.SIGNING_KEY
        clawlab.SIGNING_KEY = Path(self.tempdir.name) / "audit_signing_key.pem"
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        clawlab.SIGNING_KEY = self.ancienne_cle
        self.tempdir.cleanup()


    def test_verification_integrite(self):
        clawlab._enregistrer("test", "success", 10)

        sortie = io.StringIO()
        with contextlib.redirect_stdout(sortie):
            resultat = clawlab.verifier_integrite()

        self.assertTrue(resultat)
        self.assertIn("VALIDÉE", sortie.getvalue())

    def test_recherche_operation(self):
        clawlab._enregistrer("recherche", "success", 10)
        operation = clawlab._charger_operations()[0]

        with contextlib.redirect_stdout(io.StringIO()):
            resultat = clawlab.rechercher_operation(operation["id"])

        self.assertEqual(resultat["action"], "recherche")

    def test_details_operation(self):
        clawlab._enregistrer("details", "success", 15)
        operation = clawlab._charger_operations()[0]

        sortie = io.StringIO()
        with contextlib.redirect_stdout(sortie):
            resultat = clawlab.details_operation(operation["id"])

        self.assertEqual(resultat["action"], "details")
        self.assertIn("Action :", sortie.getvalue())

    def test_statistiques(self):
        clawlab._enregistrer(
            "calcul", "success", 10,
            agent="agent-a", model="modele-a", tool="outil-a"
        )
        clawlab._enregistrer(
            "calcul", "error", 30,
            erreur="ValueError",
            agent="agent-a", model="modele-a", tool="outil-a"
        )

        with contextlib.redirect_stdout(io.StringIO()):
            resultat = clawlab.statistiques()

        self.assertEqual(resultat["operations"], 2)
        self.assertEqual(resultat["succes"], 1)
        self.assertEqual(resultat["echecs"], 1)
        self.assertEqual(resultat["taux_succes"], 50.0)
        self.assertEqual(resultat["duree_moyenne_ms"], 20.0)
        self.assertEqual(resultat["duree_max_ms"], 30.0)
        self.assertEqual(resultat["agents"]["agent-a"], 2)

    def test_export_html(self):
        clawlab._enregistrer("rapport_test", "success", 10)

        destination = Path(self.tempdir.name) / "rapport.html"

        with contextlib.redirect_stdout(io.StringIO()):
            resultat = clawlab.exporter_html(str(destination))

        self.assertEqual(resultat, destination)
        self.assertTrue(destination.exists())

        contenu = destination.read_text(encoding="utf-8")
        self.assertIn("rapport_test", contenu)

    def test_refus_restaurer_journal_valide(self):
        clawlab._enregistrer("journal_valide", "success", 10)
        clawlab._enregistrer("deuxieme", "success", 20)

        avant = clawlab.JOURNAL.read_bytes()

        with contextlib.redirect_stdout(io.StringIO()):
            resultat = clawlab.restaurer_sauvegarde()

        apres = clawlab.JOURNAL.read_bytes()

        self.assertFalse(resultat)
        self.assertEqual(avant, apres)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class ClawLabRobustnessTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        self.ancienne_cle = clawlab.SIGNING_KEY
        clawlab.SIGNING_KEY = Path(self.tempdir.name) / "audit_signing_key.pem"
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        clawlab.SIGNING_KEY = self.ancienne_cle
        self.tempdir.cleanup()

    def test_json_illisible(self):
        clawlab.JOURNAL.write_text("{json invalide", encoding="utf-8")

        with self.assertRaises(ValueError):
            clawlab._charger_operations()

    def test_format_json_invalide(self):
        clawlab.JOURNAL.write_text(
            '{"action": "test"}', encoding="utf-8"
        )

        with self.assertRaises(ValueError):
            clawlab._charger_operations()

    def test_empreinte_falsifiee(self):
        clawlab._enregistrer("test", "success", 10)

        operations = clawlab._charger_operations()
        operations[0]["action"] = "falsification"

        clawlab.JOURNAL.write_text(
            json.dumps(operations), encoding="utf-8"
        )

        with self.assertRaises(ValueError):
            clawlab._charger_operations()

    def test_refus_ecriture_journal_altere(self):
        clawlab._enregistrer("operation_valide", "success", 10)

        clawlab.JOURNAL.write_text(
            "journal corrompu", encoding="utf-8"
        )
        avant = clawlab.JOURNAL.read_bytes()

        with self.assertRaises(ValueError):
            clawlab._enregistrer("nouvelle_operation", "success", 5)

        apres = clawlab.JOURNAL.read_bytes()

        self.assertEqual(avant, apres)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class ClawLabSchemaTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        self.ancienne_cle = clawlab.SIGNING_KEY
        clawlab.SIGNING_KEY = Path(self.tempdir.name) / "audit_signing_key.pem"
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        clawlab.SIGNING_KEY = self.ancienne_cle
        self.tempdir.cleanup()

    def creer_operation(self):
        clawlab._enregistrer("test", "success", 10)
        return clawlab._charger_operations()

    def verifier_rejet(self, modification):
        operations = self.creer_operation()
        modification(operations[0])

        self.assertFalse(
            clawlab._verifier_liste_operations(operations)
        )

    def test_identifiant_manquant(self):
        self.verifier_rejet(lambda op: op.pop("id"))

    def test_duree_negative(self):
        self.verifier_rejet(lambda op: op.update(duree_ms=-1))

    def test_duree_non_finie(self):
        for valeur in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(duree=valeur):
                operations = self.creer_operation()
                operations[0]["duree_ms"] = valeur
                contenu = {
                    k: v for k, v in operations[0].items()
                    if k != "hash"
                }
                operations[0]["hash"] = clawlab._empreinte(contenu)

                self.assertFalse(
                    clawlab._verifier_liste_operations(operations)
                )

    def test_date_invalide(self):
        self.verifier_rejet(lambda op: op.update(date="date-invalide"))

    def test_type_action_invalide(self):
        self.verifier_rejet(lambda op: op.update(action=123))


class ClawLabCrashTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        self.ancienne_cle = clawlab.SIGNING_KEY
        clawlab.SIGNING_KEY = Path(self.tempdir.name) / "audit_signing_key.pem"
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        clawlab.SIGNING_KEY = self.ancienne_cle
        self.tempdir.cleanup()

    def test_echec_ecriture_preserve_journal(self):
        clawlab._enregistrer("operation_initiale", "success", 10)

        avant = clawlab.JOURNAL.read_bytes()

        original_dump = clawlab.json.dump

        def echec_dump(*args, **kwargs):
            raise OSError("Interruption simulee")

        clawlab.json.dump = echec_dump

        try:
            with self.assertRaises(OSError):
                clawlab._enregistrer("operation_interrompue", "success", 5)
        finally:
            clawlab.json.dump = original_dump

        apres = clawlab.JOURNAL.read_bytes()

        self.assertEqual(avant, apres)
        self.assertTrue(clawlab.verifier_integrite())

    def test_crash_apres_remplacement_journal_restaure_evenement_commis(self):
        script = """
import os
from pathlib import Path
import clawlab

clawlab.JOURNAL = Path(os.environ["CLAWLAB_TEST_JOURNAL"])
clawlab.SIGNING_KEY = Path(os.environ["CLAWLAB_TEST_SIGNING_KEY"])
ecriture_checkpoint_originale = clawlab._ecrire_checkpoint
nombre_appels_checkpoint = 0

def interrompre_apres_remplacement(operations, chemin=None):
    global nombre_appels_checkpoint
    if chemin is None:
        nombre_appels_checkpoint += 1
        if nombre_appels_checkpoint == 2:
            os._exit(73)
    return ecriture_checkpoint_originale(operations, chemin)

clawlab._ecrire_checkpoint = interrompre_apres_remplacement
clawlab._enregistrer("operation_commise", "success", 10)
clawlab._enregistrer("operation_interrompue", "success", 20)
"""
        environnement = os.environ.copy()
        environnement["CLAWLAB_TEST_JOURNAL"] = str(clawlab.JOURNAL)
        environnement["CLAWLAB_TEST_SIGNING_KEY"] = str(clawlab.SIGNING_KEY)
        racine_projet = Path(__file__).resolve().parents[1]

        processus = subprocess.run(
            [sys.executable, "-c", script],
            cwd=racine_projet,
            env=environnement,
            capture_output=True,
            timeout=30,
        )

        self.assertEqual(processus.returncode, 73)
        journal_interrompu = clawlab.JOURNAL.read_bytes()
        with self.assertRaises(ValueError):
            clawlab._charger_operations()

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(clawlab.restaurer_sauvegarde())

        operations = clawlab._charger_operations()
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]["action"], "operation_commise")

        copies = list(
            clawlab.JOURNAL.parent.glob(
                clawlab.JOURNAL.name + ".corrompu-*"
            )
        )
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].read_bytes(), journal_interrompu)


class ClawLabRecoveryTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        self.ancienne_cle = clawlab.SIGNING_KEY
        clawlab.SIGNING_KEY = Path(self.tempdir.name) / "audit_signing_key.pem"
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        clawlab.SIGNING_KEY = self.ancienne_cle
        self.tempdir.cleanup()

    def test_restauration_apres_corruption(self):
        clawlab._enregistrer("operation_1", "success", 10)
        clawlab._enregistrer("operation_2", "success", 20)

        backup = clawlab.JOURNAL.with_name(
            clawlab.JOURNAL.name + ".bak"
        )
        donnees_backup = json.loads(
            backup.read_text(encoding="utf-8")
        )
        operations_backup = donnees_backup["operations"]

        clawlab.JOURNAL.write_text(
            "journal corrompu", encoding="utf-8"
        )

        resultat = clawlab.restaurer_sauvegarde()

        self.assertTrue(resultat)
        self.assertTrue(clawlab.verifier_integrite())

        restaurees = clawlab._charger_operations()
        self.assertEqual(len(restaurees), len(operations_backup))

        copies = list(
            clawlab.JOURNAL.parent.glob(
                "sdk_audit.json.corrompu-*"
            )
        )
        self.assertEqual(len(copies), 1)
        self.assertEqual(
            copies[0].read_text(encoding="utf-8"),
            "journal corrompu"
        )


class ClawLabAnomalyTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        self.ancienne_cle = clawlab.SIGNING_KEY
        clawlab.SIGNING_KEY = Path(self.tempdir.name) / "audit_signing_key.pem"
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        clawlab.SIGNING_KEY = self.ancienne_cle
        self.tempdir.cleanup()

    def test_journal_vide(self):
        resultat = clawlab.analyser_anomalies()
        self.assertEqual(resultat["operations_analysees"], 0)
        self.assertFalse(resultat["analyse_suffisante"])

    def test_hausse_taux_echec(self):
        for i in range(50):
            clawlab._enregistrer("ancienne", "success", 10)

        for i in range(50):
            clawlab._enregistrer(
                "recente",
                "error" if i < 15 else "success",
                10
            )

        resultat = clawlab.analyser_anomalies()
        self.assertTrue(
            any("Hausse du taux d'échec" in a
                for a in resultat["alertes"])
        )

    def test_operation_anormalement_lente(self):
        for i in range(10):
            clawlab._enregistrer("normale", "success", 10)

        clawlab._enregistrer("lente", "success", 1000)

        resultat = clawlab.analyser_anomalies()
        self.assertEqual(len(resultat["operations_lentes"]), 1)
        self.assertEqual(
            resultat["operations_lentes"][0]["action"],
            "lente"
        )

    def test_outil_avec_echec(self):
        clawlab._enregistrer(
            "appel outil",
            "error",
            10,
            agent="agent-test",
            model="modele-test",
            tool="outil-test"
        )

        resultat = clawlab.analyser_anomalies()
        self.assertEqual(
            resultat["outil_le_plus_en_echec"]["outil"],
            "outil-test"
        )


class ClawLabRepeatedToolTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        self.ancienne_cle = clawlab.SIGNING_KEY
        clawlab.SIGNING_KEY = Path(self.tempdir.name) / "audit_signing_key.pem"
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        clawlab.SIGNING_KEY = self.ancienne_cle
        self.tempdir.cleanup()

    def test_alerte_apres_trois_echecs(self):
        for _ in range(3):
            clawlab._enregistrer(
                "appel API",
                "error",
                10,
                tool="outil-test"
            )

        resultat = clawlab.analyser_anomalies()

        self.assertTrue(
            any(
                "outil-test" in alerte and "3 fois" in alerte
                for alerte in resultat["alertes"]
            )
        )

    def test_pas_alerte_avant_trois_echecs(self):
        for _ in range(2):
            clawlab._enregistrer(
                "appel API",
                "error",
                10,
                tool="outil-test"
            )

        resultat = clawlab.analyser_anomalies()

        self.assertFalse(
            any("Échecs répétés" in alerte for alerte in resultat["alertes"])
        )


class ClawLabHtmlAlertTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        self.ancienne_cle = clawlab.SIGNING_KEY
        clawlab.SIGNING_KEY = Path(self.tempdir.name) / "audit_signing_key.pem"
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        clawlab.SIGNING_KEY = self.ancienne_cle
        self.tempdir.cleanup()

    def test_alerte_critique_dans_rapport_html(self):
        for _ in range(3):
            clawlab._enregistrer(
                "appel API",
                "error",
                10,
                tool="outil-test"
            )

        destination = Path(self.tempdir.name) / "rapport.html"
        clawlab.exporter_html(str(destination))

        self.assertTrue(destination.exists())

        contenu = destination.read_text(encoding="utf-8")

        self.assertIn("ALERTE OUTIL", contenu)
        self.assertIn("outil-test", contenu)
        self.assertIn("critical-alert", contenu)


class ClawLabIntegrityAttackTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        self.ancienne_cle = clawlab.SIGNING_KEY
        clawlab.SIGNING_KEY = Path(self.tempdir.name) / "audit_signing_key.pem"
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

        for numero in range(3):
            clawlab._enregistrer(
                f"operation_{numero}", "success", 10
            )

        self.operations = clawlab._charger_operations()

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        clawlab.SIGNING_KEY = self.ancienne_cle
        self.tempdir.cleanup()

    def test_refuse_modification_sans_recalcul(self):
        operations = [dict(o) for o in self.operations]
        operations[1]["action"] = "action_falsifiee"

        self.assertFalse(
            clawlab._verifier_liste_operations(operations)
        )

    def test_refuse_suppression_dune_operation_intermediaire(self):
        operations = [dict(o) for o in self.operations]
        del operations[1]

        self.assertFalse(
            clawlab._verifier_liste_operations(operations)
        )

    def test_refuse_insertion_non_recalculee(self):
        operations = [dict(o) for o in self.operations]
        operations.insert(1, dict(operations[0]))

        self.assertFalse(
            clawlab._verifier_liste_operations(operations)
        )

    def test_refuse_reordonnancement(self):
        operations = [dict(o) for o in self.operations]
        operations[0], operations[1] = operations[1], operations[0]

        self.assertFalse(
            clawlab._verifier_liste_operations(operations)
        )

    def test_limite_suppression_derniere_operation(self):
        operations = [dict(o) for o in self.operations]
        del operations[-1]

        # Sans point de contrôle externe, la suppression de la fin
        # de la chaîne n'est pas détectable.
        self.assertTrue(
            clawlab._verifier_liste_operations(operations)
        )

    def test_limite_recalcul_complet_de_la_chaine(self):
        operations = [dict(o) for o in self.operations]
        operations[0]["action"] = "historique_reconstruit"

        precedent = "GENESIS"
        for operation in operations:
            operation["previous_hash"] = precedent
            contenu = {
                k: v for k, v in operation.items() if k != "hash"
            }
            operation["hash"] = clawlab._empreinte(contenu)
            precedent = operation["hash"]

        # Une chaîne entièrement recalculée est valide :
        # le hash local ne prouve pas l'authenticité historique.
        self.assertTrue(
            clawlab._verifier_liste_operations(operations)
        )


class ClawLabCheckpointTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        self.ancienne_cle = clawlab.SIGNING_KEY
        clawlab.SIGNING_KEY = Path(self.tempdir.name) / "audit_signing_key.pem"
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        clawlab.SIGNING_KEY = self.ancienne_cle
        self.tempdir.cleanup()

    def test_echec_checkpoint_sauvegarde_preserve_journal(self):
        clawlab._enregistrer("operation_1", "success", 10)

        original = clawlab._ecrire_sauvegarde_atomique

        def simuler_interruption(operations):
            raise OSError("Echec sauvegarde atomique")

        clawlab._ecrire_sauvegarde_atomique = simuler_interruption
        try:
            with self.assertRaisesRegex(OSError, "Echec sauvegarde atomique"):
                clawlab._enregistrer("operation_2", "success", 20)
        finally:
            clawlab._ecrire_sauvegarde_atomique = original

        operations = clawlab._charger_operations()
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]["action"], "operation_1")

        clawlab._enregistrer("operation_2", "success", 20)
        operations = clawlab._charger_operations()
        self.assertEqual(len(operations), 2)

    def test_echec_remplacement_sauvegarde_preserve_ancienne(self):
        clawlab._enregistrer("operation_1", "success", 10)
        clawlab._enregistrer("operation_2", "success", 20)

        backup = clawlab.JOURNAL.with_name(
            clawlab.JOURNAL.name + ".bak"
        )
        sauvegarde_initiale = backup.read_bytes()

        remplacement_original = clawlab.os.replace

        def simuler_echec(source, destination):
            if Path(destination) == backup:
                raise OSError("Echec remplacement atomique")
            return remplacement_original(source, destination)

        clawlab.os.replace = simuler_echec
        try:
            with self.assertRaisesRegex(
                OSError, "Echec remplacement atomique"
            ):
                clawlab._enregistrer("operation_3", "success", 30)
        finally:
            clawlab.os.replace = remplacement_original

        self.assertEqual(backup.read_bytes(), sauvegarde_initiale)

        operations = clawlab._charger_operations()
        self.assertEqual(len(operations), 2)
        self.assertEqual(operations[-1]["action"], "operation_2")
        self.assertTrue(clawlab._verifier_liste_operations(operations))

        temporaires = list(
            backup.parent.glob("." + backup.name + ".*.tmp")
        )
        self.assertEqual(temporaires, [])

    def test_echec_checkpoint_enregistrement_retour_arriere(self):
        clawlab._enregistrer("operation_1", "success", 10)

        journal = clawlab.JOURNAL
        checkpoint = clawlab._chemin_checkpoint()
        journal_initial = journal.read_bytes()
        checkpoint_initial = checkpoint.read_bytes()

        original = clawlab._ecrire_checkpoint

        def simuler_echec(operations, chemin=None):
            if chemin is None:
                raise OSError("Echec checkpoint enregistrement")
            return original(operations, chemin)

        clawlab._ecrire_checkpoint = simuler_echec
        try:
            with self.assertRaisesRegex(
                OSError, "Echec checkpoint enregistrement"
            ):
                clawlab._enregistrer("operation_2", "success", 20)
        finally:
            clawlab._ecrire_checkpoint = original

        self.assertEqual(journal.read_bytes(), journal_initial)
        self.assertEqual(checkpoint.read_bytes(), checkpoint_initial)

        operations = clawlab._charger_operations()
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]["action"], "operation_1")

    def test_echec_checkpoint_restauration_retour_arriere(self):
        clawlab._enregistrer("operation_1", "success", 10)
        clawlab._enregistrer("operation_2", "success", 20)

        journal = clawlab.JOURNAL
        checkpoint = clawlab._chemin_checkpoint()

        journal_corrompu = b"JOURNAL CORROMPU POUR TEST"
        journal.write_bytes(journal_corrompu)
        checkpoint_initial = checkpoint.read_bytes()

        ecriture_originale = clawlab._ecrire_checkpoint

        def simuler_echec(operations, chemin=None):
            if chemin is None:
                raise OSError("Echec checkpoint restauration")
            return ecriture_originale(operations, chemin)

        clawlab._ecrire_checkpoint = simuler_echec
        try:
            with self.assertRaisesRegex(
                OSError, "Echec checkpoint restauration"
            ):
                clawlab.restaurer_sauvegarde()
        finally:
            clawlab._ecrire_checkpoint = ecriture_originale

        self.assertEqual(journal.read_bytes(), journal_corrompu)
        self.assertEqual(checkpoint.read_bytes(), checkpoint_initial)

        copies = list(
            journal.parent.glob(journal.name + ".corrompu-*")
        )
        self.assertTrue(copies)
        self.assertEqual(copies[-1].read_bytes(), journal_corrompu)

    def test_sauvegarde_operations_mal_formees_rejetee(self):
        backup = clawlab.JOURNAL.with_name(
            clawlab.JOURNAL.name + ".bak"
        )
        backup.write_text(
            '{"version":1,"operations":["operation_invalide"],"checkpoint":{}}',
            encoding="utf-8"
        )

        with self.assertRaisesRegex(
            ValueError, "Intégrité de la sauvegarde invalide"
        ):
            clawlab._charger_sauvegarde(backup)

    def test_checkpoint_cree(self):
        clawlab._enregistrer("operation_1", "success", 10)

        checkpoint = clawlab.JOURNAL.with_name(
            clawlab.JOURNAL.name + ".checkpoint"
        )
        self.assertTrue(checkpoint.exists())
        donnees = json.loads(checkpoint.read_text(encoding="utf-8"))
        self.assertEqual(donnees["version"], 2)
        self.assertTrue(clawlab._verifier_checkpoint_signe(donnees))

    def test_checkpoint_signe_refuse_reecriture_sans_cle_privee(self):
        clawlab._enregistrer("operation_1", "success", 10)
        operations = clawlab._charger_operations()
        operations[0]["action"] = "historique_falsifie"
        operations[0]["previous_hash"] = "GENESIS"
        contenu = {k: v for k, v in operations[0].items() if k != "hash"}
        operations[0]["hash"] = clawlab._empreinte(contenu)
        clawlab.JOURNAL.write_text(json.dumps(operations), encoding="utf-8")

        checkpoint = clawlab._chemin_checkpoint()
        donnees = json.loads(checkpoint.read_text(encoding="utf-8"))
        donnees["snapshot"] = clawlab._instantane_checkpoint(operations)
        checkpoint.write_text(json.dumps(donnees), encoding="utf-8")

        self.assertTrue(clawlab._verifier_liste_operations(operations))
        with self.assertRaisesRegex(ValueError, "Signature du checkpoint"):
            clawlab._charger_operations()

    def test_checkpoint_historique_est_migre_vers_signature(self):
        clawlab._enregistrer("operation_1", "success", 10)
        checkpoint = clawlab._chemin_checkpoint()
        checkpoint.write_text(
            json.dumps(clawlab._instantane_checkpoint(clawlab._charger_operations())),
            encoding="utf-8",
        )

        clawlab._charger_operations()

        migre = json.loads(checkpoint.read_text(encoding="utf-8"))
        self.assertTrue(clawlab._verifier_checkpoint_signe(migre))

    def test_signature_sauvegarde_corrompue_est_refusee(self):
        clawlab._enregistrer("operation_1", "success", 10)
        clawlab._enregistrer("operation_2", "success", 20)
        backup = clawlab.JOURNAL.with_name(clawlab.JOURNAL.name + ".bak")
        donnees = json.loads(backup.read_text(encoding="utf-8"))
        donnees["checkpoint"]["signature"] = "A" * len(
            donnees["checkpoint"]["signature"]
        )
        backup.write_text(json.dumps(donnees), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "Checkpoint signé"):
            clawlab._charger_sauvegarde(backup)

    def test_suppression_derniere_operation_detectee(self):
        clawlab._enregistrer("operation_1", "success", 10)
        clawlab._enregistrer("operation_2", "success", 20)

        operations = json.loads(
            clawlab.JOURNAL.read_text(encoding="utf-8")
        )
        operations.pop()

        clawlab.JOURNAL.write_text(
            json.dumps(operations), encoding="utf-8"
        )

        with self.assertRaises(ValueError):
            clawlab._charger_operations()

    def test_evenement_orphelin_avec_chaine_recalculee_refuse(self):
        clawlab._enregistrer("operation_1", "success", 10)
        clawlab._enregistrer("operation_2", "success", 20)

        operations = clawlab._charger_operations()
        orpheline = dict(operations[-1])
        orpheline["id"] = "evenement-orphelin"
        orpheline["action"] = "evenement_fabrique"
        orpheline["previous_hash"] = operations[-1]["hash"]
        contenu = {k: v for k, v in orpheline.items() if k != "hash"}
        orpheline["hash"] = clawlab._empreinte(contenu)
        operations.append(orpheline)

        self.assertTrue(clawlab._verifier_liste_operations(operations))
        clawlab.JOURNAL.write_text(
            json.dumps(operations), encoding="utf-8"
        )

        with self.assertRaises(ValueError):
            clawlab._charger_operations()

    def test_checkpoint_manquant_est_detecte_apres_sauvegarde_versionnee(self):
        clawlab._enregistrer("operation_1", "success", 10)
        clawlab._enregistrer("operation_2", "success", 20)

        checkpoint = clawlab._chemin_checkpoint()
        checkpoint.unlink()

        with self.assertRaisesRegex(
            ValueError, "Checkpoint principal absent"
        ):
            clawlab._charger_operations()

    def test_recuperation_apres_interruption_checkpoint(self):
        clawlab._enregistrer("operation_1", "success", 10)

        original = clawlab._ecrire_checkpoint

        def simuler_interruption(operations, chemin=None):
            if chemin is None:
                raise OSError("Interruption simulee")
            return original(operations, chemin)

        clawlab._ecrire_checkpoint = simuler_interruption
        try:
            with self.assertRaisesRegex(OSError, "Interruption simulee"):
                clawlab._enregistrer("operation_2", "success", 20)
        finally:
            clawlab._ecrire_checkpoint = original

        operations = clawlab._charger_operations()
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]["action"], "operation_1")
        self.assertTrue(clawlab._verifier_liste_operations(operations))
        self.assertFalse(clawlab.restaurer_sauvegarde())

    def test_checkpoint_sauvegarde_associe(self):
        clawlab._enregistrer("operation_1", "success", 10)
        clawlab._enregistrer("operation_2", "success", 20)

        backup = clawlab.JOURNAL.with_name(
            clawlab.JOURNAL.name + ".bak"
        )
        donnees = json.loads(backup.read_text(encoding="utf-8"))
        self.assertEqual(donnees["version"], 2)
        self.assertEqual(
            donnees["checkpoint"]["snapshot"],
            clawlab._instantane_checkpoint(donnees["operations"])
        )
        self.assertTrue(
            clawlab._verifier_liste_operations(donnees["operations"])
        )
