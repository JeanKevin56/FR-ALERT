# FR-ALERT — Analyse des avis et alertes ANSSI avec enrichissement des CVE

Outil d'extraction, d'enrichissement et d'analyse des bulletins de sécurité du
CERT-FR (ANSSI). Il récupère les avis et alertes, identifie les CVE associées,
les enrichit via les API MITRE (CVSS, CWE) et FIRST (EPSS), consolide le tout
dans un fichier CSV, puis génère des alertes email pour les vulnérabilités
critiques.

## Structure du projet

Le code Python fonctionnel est découpé en quatre modules, correspondant aux
quatre étapes du livrable :

| Fichier | Étape | Rôle |
|---|---|---|
| `extraction_anssi.py`   | (a) Extraction      | Récupère les bulletins ANSSI (RSS ou fichiers locaux) et identifie les CVE. |
| `enrichissement_api.py` | (b) Enrichissement  | Interroge les API MITRE et FIRST pour chaque CVE, avec cache disque. |
| `consolidation.py`      | (c) Consolidation   | Aplatit les données en un DataFrame Pandas et exporte le CSV. |
| `alertes_email.py`      | (d) Alertes         | Sélectionne les CVE critiques, compose et envoie le mail d'alerte. |
| `main.py`               | Orchestration       | Exécute le pipeline complet (a → b → c → d). |

Le notebook `fonctions_extractions.ipynb` reprend ces étapes et ajoute
l'analyse, les visualisations (partie 5) et les modèles de Machine Learning
(partie 6).

## Installation

Python 3.11 recommandé. Installer les dépendances :

```bash
pip install feedparser requests pandas matplotlib seaborn scikit-learn
```

## Utilisation

Lancer le pipeline complet :

```bash
python main.py
```

Le script produit le fichier `donnees_enrichies.csv` et affiche le mail
d'alerte généré (sans l'envoyer par défaut).

### Choix de la source des données

Dans `main.py`, la variable `MODE` contrôle la source :

- `MODE = "remote"` : interroge les flux RSS et les API en ligne de l'ANSSI.
- `MODE = "local"`  : lit les fichiers JSON pré-téléchargés placés dans
  les dossiers `./alertes/` et `./avis/`.

### Cache des appels API

Pour respecter les serveurs externes, on applique une pause de 2 secondes entre chaque requête.
Un cache disque (`cache_cve.json`) mémoriseles CVE déjà interrogés : les exécutions suivantes
ne refont aucun appel réseau pour un CVE connu, y compris entre deux session 
(si l'application est fermée par ex)

## Enrichissement : les scores utilisés

- **CVSS** (0–10) : gravité de la vulnérabilité (0–3 faible, 4–6 moyenne,
  7–8 élevée, 9–10 critique).
- **CWE** : catégorie de la faiblesse (ex. CWE-79 = injection de script).
- **EPSS** (0–1) : probabilité d'exploitation réelle estimée par FIRST.

## Génération d'alertes (envoi optionnel)

Le module `alertes_email.py` sélectionne les CVE dont le CVSS ≥ 9 ou l'EPSS ≥ 0.5
(seuils ajustables), compose un sujet et un corps de mail, et peut l'envoyer
par SMTP.

Pour tester l'envoi sans aucune donnée
personnelle, créer un compte jetable sur https://ethereal.email/create (les
mails sont capturés, jamais délivrés), puis renseigner les identifiants via des
variables d'environnement :

```bash
export EMAIL_FROM="xxxx@ethereal.email"
export EMAIL_PASSWORD="xxxxxxxx"
```

Aucun identifiant n'est écrit en dur dans le code.

## Fichiers générés

- `donnees_enrichies.csv` : données consolidées (1 ligne = bulletin × CVE × produit).
- `cache_cve.json` : cache des réponses API (régénéré automatiquement).
