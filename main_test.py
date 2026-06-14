import pandas as pd
from cve_extraction import extraire_cves
from get_cve_score import get_cve_scores
from dataframe import consolider_en_dataframe
from get_bulletin import get_bulletin

FEED_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"
FEED_AVIS    = "https://www.cert.ssi.gouv.fr/avis/feed/"

def executer_pipeline():
    print("=== DÉMARRAGE DU PIPELINE ANSSI ===\n")

    bulletins_a_traiter = get_bulletin(FEED_ALERTES) + get_bulletin(FEED_AVIS)
    print(f"Nombre de bulletins à traiter : {len(bulletins_a_traiter)}")
    donnees_globales = []

    for b_info in bulletins_a_traiter:
        print(f"[*] TRAITEMENT : {b_info['id']} ({b_info['type'].upper()})")

        bulletin_complet = {
            "id": b_info["id"],
            "titre": b_info["titre"],
            "type": b_info["type"],
            "date_publication": b_info["date_publication"],
            "lien": b_info["lien"],
            "cves_enrichis": []
        }

        param_entree = b_info["id"] if b_info["mode"] == "local" else b_info["lien"]
        liste_cves = extraire_cves(param_entree, mode=b_info["mode"], type_bulletin=b_info["dossier"])

        print(f"  -> {len(liste_cves)} CVE(s) extrait(s) : {liste_cves}")

        for cve_id in liste_cves:
            infos_cve = get_cve_scores(cve_id)

            if infos_cve:
                bulletin_complet["cves_enrichis"].append(infos_cve)

        donnees_globales.append(bulletin_complet)
        print("-" * 50)

    print("\n=== GÉNÉRATION DU DATAFRAME ET EXPORT CSV ===")
    df_final = consolider_en_dataframe(donnees_globales, nom_fichier_csv="donnees_enrichies.csv")

    if not df_final.empty:
        print(f"SUCCÈS ! Fichier 'donnees_enrichies.csv' généré.")
        print(f"Dimensions : {df_final.shape[0]} lignes générées à partir des combinaisons.")
    else:
        print("ÉCHEC : Le DataFrame est vide.")


if __name__ == "__main__":
    executer_pipeline()
