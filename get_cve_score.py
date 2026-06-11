import requests
import time


def get_cve_scores(cve_id):
    """
    Récupère les scores CVSS, CWE (MITRE) et EPSS (FIRST) pour un CVE donné.
    Retourne un dictionnaire compatible avec le module de consolidation.
    """
    print(f"    -> [API MITRE] Interrogation pour {cve_id}...")
    time.sleep(2)  # Pause obligatoire de 2s pour soulager l'API

    url_mitre = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url_mitre)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"      [ERREUR] MITRE API pour {cve_id} : {e}")
        return None

    # 1. Extraction Description
    try:
        description = data["containers"]["cna"]["descriptions"][0]["value"]
    except (KeyError, IndexError):
        description = "Non disponible"

    # 2. Extraction CVSS et Sévérité
    cvss_score = None
    base_severity = "Non renseigné"
    try:
        metrics = data["containers"]["cna"]["metrics"][0]
        if "cvssV3_1" in metrics:
            cvss_score = metrics["cvssV3_1"]["baseScore"]
            base_severity = metrics["cvssV3_1"].get("baseSeverity", "Non renseigné")
        elif "cvssV3_0" in metrics:
            cvss_score = metrics["cvssV3_0"]["baseScore"]
            base_severity = metrics["cvssV3_0"].get("baseSeverity", "Non renseigné")
    except (KeyError, IndexError):
        pass

    # 3. Extraction CWE
    cwe = "Non disponible"
    cwe_desc = "Non disponible"
    problemtype = data["containers"]["cna"].get("problemTypes", [{}])
    if problemtype and "descriptions" in problemtype[0]:
        try:
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")
        except (KeyError, IndexError):
            pass

    # 4. Extraction des produits (Correction de la boucle)
    produits_affectes_liste = []
    try:
        affected = data["containers"]["cna"]["affected"]
        for product in affected:
            vendor = product.get("vendor", "Non disponible")
            product_name = product.get("product", "Non disponible")
            versions = [v.get("version", "?") for v in product.get("versions", []) if v.get("status") == "affected"]

            produits_affectes_liste.append({
                "vendor": vendor,
                "produit": product_name,
                "versions": ", ".join(versions)
            })
    except KeyError:
        pass

    # 5. Extraction EPSS (FIRST)
    print(f"    -> [API FIRST] Interrogation EPSS pour {cve_id}...")
    time.sleep(2)  # Pause de 2s
    url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    epss_score = None
    try:
        response_epss = requests.get(url_epss)
        response_epss.raise_for_status()
        data_epss = response_epss.json()
        epss_data = data_epss.get("data", [])
        if epss_data:
            epss_score = epss_data[0]["epss"]
    except Exception as e:
        print(f"      [ERREUR] FIRST API pour {cve_id} : {e}")

    # 6. Retour structuré pour le DataFrame
    return {
        "identifiant": cve_id,
        "score_cvss": cvss_score,
        "base_severity": base_severity,
        "type_cwe": cwe,
        "score_epss": epss_score,
        "description": description,
        "produits_affectes": produits_affectes_liste
    }