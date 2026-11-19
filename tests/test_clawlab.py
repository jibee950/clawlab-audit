import asyncio
import contextlib
import csv
import io
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import clawlab


class ClawLabTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
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

        with ThreadPoolExecutor(max_workers=5) as executor:
            list(executor.map(enregistrer, range(15)))

        operations = clawlab._charger_operations()

        self.assertEqual(len(operations), 15)
        self.assertTrue(
            clawlab._verifier_liste_operations(operations)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)


class ClawLabAdvancedTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
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
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
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
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
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

    def test_date_invalide(self):
        self.verifier_rejet(lambda op: op.update(date="date-invalide"))

    def test_type_action_invalide(self):
        self.verifier_rejet(lambda op: op.update(action=123))


class ClawLabCrashTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
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


class ClawLabRecoveryTests(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ancien_journal = clawlab.JOURNAL
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
        self.tempdir.cleanup()

    def test_restauration_apres_corruption(self):
        clawlab._enregistrer("operation_1", "success", 10)
        clawlab._enregistrer("operation_2", "success", 20)

        backup = clawlab.JOURNAL.with_name(
            clawlab.JOURNAL.name + ".bak"
        )
        operations_backup = json.loads(
            backup.read_text(encoding="utf-8")
        )

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
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
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
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
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
        clawlab.JOURNAL = Path(self.tempdir.name) / "sdk_audit.json"

    def tearDown(self):
        clawlab.JOURNAL = self.ancien_journal
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
