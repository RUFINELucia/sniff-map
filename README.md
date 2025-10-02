# sniff-map
Capture les adresses IP visibles sur un réseau local, et génère une carte approximative des géolocalisations via une API publique (ip-api.com).

<p align="center">
  <img src="lucia-rufine-logo.jpg" alt="lucia-rufine" width="400"/>
</p>

## Description

`sniff-map` fournit un moyen simple d'inventorier les adresses IP visibles depuis une machine (ARP table / voisinage) et d'essayer d'obtenir une géolocalisation publique pour les adresses routables via l'API `ip-api.com`. Le script privilégie une approche **passive** (lecture des tables locales) pour éviter de générer du trafic réseau intrusif ; une option `--active` peut effectuer un balayage ICMP/ARP, mais elle est **délibérément optionnelle** et accompagnée d'avertissements.

Il produit :
- un fichier JSON (`results/ips_geo.json`) listant les IPs, MAC (si disponible) et données de géolocalisation,
- un CSV (`results/ips_geo.csv`) pour traitement externe,
- (optionnel) un petit fichier HTML/JS prêt à être ouvert dans un navigateur pour visualiser les points (option `--map`).

## Fonctionnalités

- Collecte passive des IPs visibles via la table ARP/voisinage (`arp -a`, `ip neigh`, etc.).
- Option `--active` : balayage ping/ARP (active — **utiliser avec autorisation**).
- Filtrage des adresses privées (option pour inclure/exclure).
- Requêtes vers `http://ip-api.com/json/<ip>` (avec pauses pour respecter les limites).
- Sorties JSON et CSV, et option de génération de carte HTML simple.

## Installation

```bash
git clone https://github.com/TON_COMPTE/sniff-map.git
cd sniff-map
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.\\.venv\\Scripts\\activate # Windows
pip install -r requirements.txt
```

## Usage

Collecte passive et géolocalisation (par défaut : passive) :

```bash
python sniff_map.py --output results/ --timeout 5
```

Inclure balayage actif (ping sweep) — nécessite autorisation :

```bash
python sniff_map.py --output results/ --active
```

Générer aussi une carte HTML :

```bash
python sniff_map.py --output results/ --map
```

Options importantes :

- --output : dossier de sortie (default results/)

- --active : active le balayage réseau (ping/ARP) — utilisation auditable

- --include-private : inclure adresses privées dans la géolocalisation (souvent infructueux)

- --map : génère un map.html léger montrant les points (Leaflet)

- --rate : délai en secondes entre requêtes vers ip-api (défaut 1.5s pour respecter quotas)

- --dry-run : simule l'exécution sans appeler ip-api ni écrire de fichiers

## Limites & avertissements techniques

- Beaucoup d'adresses locales (RFC1918) ne sont pas géolocalisables via IP publique ; le script évite par défaut de demander une géolocalisation pour ces IPs.

- ip-api.com a une limitation de requêtes pour la tranche gratuite (~45 req/minute) ; le script introduit un délai configurable entre requêtes.

- Les données de géolocalisation par IP sont approximatives et souvent erronées pour adresses dynamiques ou opérateurs mobiles.

- Pour cartographier précisément un réseau local (topologie, distances, etc.), il faut des outils et autorisations plus avancés.

## Avertissements légaux & éthiques

Ne scanne pas des réseaux tiers sans permission explicite. La fonction --active effectue des actions actives sur le réseau et peut être intrusive ; utilise-la seulement si tu as l'autorisation du propriétaire du réseau.

## License

MIT
