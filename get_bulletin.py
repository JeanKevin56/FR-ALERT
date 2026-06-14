import feedparser
from datetime import datetime


def get_bulletin(url, limit=10):
    """
    Renvoie une liste de tout les bulletins de l'ANSSI dans un format utilisable pour le DataFrame.
    """
    feed = feedparser.parse(url)
    bulletins = []
    for entry in feed.entries[:limit]:
        lien = entry.link

        if "alerte" in lien:
            type_b = "alerte"
            dossier = "alertes"
        else:
            type_b = "avis"
            dossier = "avis"
        
        date_str = str(entry.get("published", "")[:16])  # Format Mon, 01 Jan 2024 
        parsed_date = datetime.strptime(date_str, "%a, %d %b %Y")
        date = parsed_date.strftime("%Y-%m-%d")

        bulletins.append({
            "id": entry.id.split("/")[-2], #La fin de l'URL c'est l'ID
            "titre": entry.title,
            "type": type_b,
            "date_publication": date,
            "lien": lien,
            "mode": "remote",
            "dossier": dossier
        })
    return bulletins

# Pour utiliser : 
FEED_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"
FEED_AVIS    = "https://www.cert.ssi.gouv.fr/avis/feed/"
#bulletins_a_traiter = get_bulletin(FEED_ALERTES) + get_bulletin(FEED_AVIS)