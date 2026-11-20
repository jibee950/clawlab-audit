# ClawLab Audit â€” retours bÃªta et preuves Ã  produire

DerniÃ¨re mise Ã  jour : 20 novembre 2026

Cette fiche synthÃ©tise les retours reÃ§us sur Moltbook. Elle sÃ©pare les constats dÃ©jÃ  couverts par le pÃ©rimÃ¨tre local de ClawLab des propositions qui demanderaient une intÃ©gration ou une architecture distincte. Les suggestions de tiers ne sont pas des validations techniques.

Sources : [fil Â« What should an agent audit actually prove? Â»](https://www.moltbook.com/post/eadb460a-31a2-4aa1-8b57-413531fd8c66) et [fil Â« Looking for beta testers Â»](https://www.moltbook.com/post/9e9faf35-869d-4405-b7bd-165f81c96132).

## Retours retenus

| Sujet | Retour | Lecture pour ClawLab | Suite proposÃ©e |
|---|---|---|---|
| Provenance | Une chaÃ®ne de hashes vÃ©rifie la cohÃ©rence interne, mais ne prouve pas que lâ€™Ã©vÃ©nement vient dâ€™un appel dâ€™outil rÃ©el plutÃ´t que dâ€™un rÃ©cit rÃ©digÃ© aprÃ¨s coup. | Limite rÃ©elle. Le dÃ©corateur observe uniquement le code qui passe par son wrapper. | Garder les claims du README explicites. Pour une intÃ©gration future, capturer au point dâ€™appel de lâ€™outil et conserver lâ€™identifiant/hash de la source externe lorsque disponible. |
| Attaquant local | Un processus sous le mÃªme compte peut modifier le journal et le checkpoint. | La signature Ed25519 du checkpoint empÃªche sa rÃ©Ã©criture sans la clÃ© privÃ©e locale. Un attaquant pouvant remplacer cette clÃ© ou contrÃ´ler le processus peut encore forger l'historique. | Garder une copie protÃ©gÃ©e de la clÃ© et, pour une garantie contre l'administrateur local, Ã©pingler une rÃ©fÃ©rence publique ou un checkpoint signÃ© hors machine. |
| Omission dâ€™Ã©vÃ©nement | Un Ã©chec qui nâ€™atteint jamais le collecteur laisse un trou que la vÃ©rification interne ne peut pas forcÃ©ment dÃ©couvrir. | Un vÃ©rificateur ne peut conclure Ã  lâ€™absence dâ€™actions sans source indÃ©pendante ou sÃ©quence attendue Ã  comparer. | Pour chaque adaptateur, comparer les appels vus par lâ€™outil et les Ã©vÃ©nements ClawLab; exposer les Ã©carts comme Â« non rÃ©conciliÃ©s Â», pas comme preuve dâ€™absence. |
| RÃ©sultat mÃ©tier | Une exÃ©cution peut rÃ©ussir techniquement tout en produisant un effet mÃ©tier erronÃ©, comme facturer le mauvais compte. | Hors du pÃ©rimÃ¨tre du journal dâ€™exÃ©cution gÃ©nÃ©rique. | Documenter que le succÃ¨s de fonction nâ€™est pas une validation mÃ©tier. Une application peut ajouter son propre Ã©vÃ©nement de vÃ©rification aprÃ¨s lecture indÃ©pendante de lâ€™Ã©tat final. |
| Lecture indÃ©pendante | Un lecteur devrait pouvoir vÃ©rifier le rapport depuis une surface que lâ€™Ã©metteur ne contrÃ´le pas. | Les checkpoints sont signÃ©s avec une clÃ© Ed25519 locale; l'export portable et l'Ã©pinglage du public hors machine restent Ã  concevoir. | Ã€ lâ€™avenir, dÃ©finir un format dâ€™export et un vÃ©rificateur en lecture seule avec une clÃ© publique de confiance transmise sÃ©parÃ©ment. |
| Performance | Mesurer les latences de queue sous charge et pression mÃ©moire plutÃ´t que seulement la durÃ©e moyenne. | Les appels systÃ¨me et profils de noyau proposÃ©s sont trop spÃ©cifiques pour le cÅ“ur portable. | Lors dâ€™un prototype de backend, mesurer au minimum p50/p95/p99 sous charges documentÃ©es, et sÃ©parer latence dâ€™exÃ©cution mÃ©tier et temps dâ€™Ã©criture dâ€™audit. |
| Limites visibles | Publier aussi les cas oÃ¹ le rapport Ã©choue ou ne sait pas conclure. | TrÃ¨s utile pour Ã©viter que Â« intÃ©gritÃ© Â» soit interprÃ©tÃ© comme Â« vÃ©ritÃ© de lâ€™action Â». | Tenir les rÃ©sultats adversariaux ci-dessous Ã  jour avec le rÃ©sultat observÃ©, la version et la limite. |

## Cas de vÃ©rification Ã  suivre

| ID | ScÃ©nario | Ce que le test peut Ã©tablir | Ã‰tat |
|---|---|---|---|
| FB-01 | Modifier un champ dâ€™une opÃ©ration sans recalculer son hash. | La vÃ©rification dÃ©tecte cette altÃ©ration simple. | Test prÃ©sent; inclus dans la suite complÃ¨te 0.3.0 (55 tests OK sous Windows). |
| FB-02 | Recalculer toute la chaÃ®ne aprÃ¨s avoir falsifiÃ© une opÃ©ration. | Une chaÃ®ne locale recalculÃ©e peut rester cohÃ©rente; sans ancre indÃ©pendante, ce test doit montrer la limite, pas prÃ©tendre la rÃ©soudre. | Test de limite prÃ©sent; inclus dans la suite complÃ¨te 0.3.0. |
| FB-03 | Supprimer la derniÃ¨re opÃ©ration en laissant le checkpoint prÃ©cÃ©dent intact. | Le couple journal/checkpoint dÃ©tecte une troncature si le checkpoint reste fiable. | Test prÃ©sent; inclus dans la suite complÃ¨te 0.3.0. |
| FB-04 | Modifier le journal et recalculer aussi le checkpoint local. | La signature empÃªche de falsifier un checkpoint en l'absence de la clÃ© privÃ©e. Un acteur ayant aussi accÃ¨s Ã  cette clÃ© reste hors de la garantie. | Test ajoutÃ© : la recomposition du journal et du contenu du checkpoint en conservant la signature est rejetÃ©e. La compromission de la clÃ© reste une limite documentÃ©e. |
| FB-05 | Simuler un appel dâ€™outil rÃ©ellement exÃ©cutÃ©, mais omis avant lâ€™entrÃ©e du dÃ©corateur. | Le cÅ“ur gÃ©nÃ©rique ne peut pas dÃ©tecter un Ã©vÃ©nement quâ€™il nâ€™a jamais reÃ§u. Un adaptateur instrumentÃ© peut comparer deux sources. | Ã€ tester au niveau dâ€™un adaptateur, lorsquâ€™il existe. |
| FB-06 | Retourner un succÃ¨s technique tout en vÃ©rifiant un mauvais effet mÃ©tier. | Le journal dÃ©crit lâ€™exÃ©cution enregistrÃ©e; il ne valide pas la rÃ¨gle mÃ©tier sans assertion fournie par lâ€™application. | Cas de documentation; pas un dÃ©faut du vÃ©rificateur dâ€™intÃ©gritÃ©. |
| FB-07 | AprÃ¨s plusieurs Ã©critures, supprimer le checkpoint principal tout en gardant une sauvegarde versionnÃ©e. | Le chargement doit refuser de reconstruire une rÃ©fÃ©rence de confiance Ã  partir du seul journal actif. | Test de rÃ©gression ajoutÃ©; inclus dans la suite complÃ¨te 0.3.0 (55 tests OK sous Windows). |
| FB-08 | ArrÃªter le processus aprÃ¨s remplacement du journal, avant remplacement du checkpoint. | Le dÃ©marrage dÃ©tecte le dÃ©saccord; la restauration remet la derniÃ¨re sauvegarde cohÃ©rente et prÃ©serve le journal interrompu. | Test subprocess ajoutÃ©; inclus dans la suite complÃ¨te 0.3.0. |

## Pistes non retenues pour le cÅ“ur actuel

- Attestation matÃ©rielle ou distante : nÃ©cessite un modÃ¨le de dÃ©ploiement et une racine de confiance indÃ©pendante, hors bibliothÃ¨que locale actuelle.
- RÃ©vocation de sessions et blocage dâ€™accÃ¨s Ã  une passerelle : contrÃ´le dâ€™accÃ¨s rÃ©seau, distinct de lâ€™audit local.
- Buffer circulaire dâ€™horodatages dâ€™appels systÃ¨me : mesure spÃ©cifique Ã  lâ€™OS, Ã  considÃ©rer seulement si un besoin mesurÃ© le justifie.
- Capture complÃ¨te des prompts, entrÃ©es et sorties : augmente fortement le risque de conserver des secrets; reste dÃ©sactivÃ©e par dÃ©faut selon le RFC.
