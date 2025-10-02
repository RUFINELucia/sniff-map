#!/usr/bin/env python3
"""
sniff_map.py

Collecte adresses IP visibles localement (passif) et tente une géolocalisation via ip-api.com.
Optionnellement peut faire un balayage actif (ping) si --active (UTILISATION RESPONSABLE).

Usage:
    python sniff_map.py --output results/
    python sniff_map.py --output results/ --active --map
"""
from pathlib import Path
import argparse
import subprocess
import json
import csv
import time
import re
import ipaddress
import sys

try:
    import requests
except Exception:
    print("Erreur: requests non installé. pip install requests")
    raise

# ------------------------------------------------------------
# Helpers: collecte passive (arp / ip neigh) -- cross-platform
# ------------------------------------------------------------
def parse_arp_a_output(text):
    """
    Parse typical `arp -a` output (Windows / *nix variations) and return set of IPs and optional MACs.
    """
    entries = []
    # patterns: Windows: ? (192.168.1.1) at 00-11-22-33-44-55 [ether] on ...
    # unix: ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
    ip_mac_re = re.compile(r"\(?([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)?(?:\s+at\s+([0-9a-fA-F:\-]{11,17}))?")
    for line in text.splitlines():
        m = ip_mac_re.search(line)
        if m:
            ip = m.group(1)
            mac = m.group(2) if m.group(2) else None
            entries.append((ip, mac))
    return entries

def get_arp_table():
    """
    Try common commands: 'arp -a' or 'ip neigh'. Return list of (ip, mac) tuples.
    """
    results = []
    # Try `ip neigh` (Linux)
    try:
        p = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=3)
        if p.returncode == 0 and p.stdout.strip():
            for line in p.stdout.splitlines():
                # format: "192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"
                parts = line.split()
                if len(parts) >= 1:
                    ip = parts[0]
                    mac = None
                    if "lladdr" in parts:
                        idx = parts.index("lladdr")
                        if idx + 1 < len(parts):
                            mac = parts[idx + 1]
                    results.append((ip, mac))
            if results:
                return results
    except Exception:
        pass

    # Fallback to arp -a
    try:
        p = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
        if p.returncode == 0 and p.stdout.strip():
            parsed = parse_arp_a_output(p.stdout)
            if parsed:
                return parsed
    except Exception:
        pass

    # If nothing found, return empty
    return results

# ------------------------------------------------------------
# Optional active scan: basic ping sweep (careful!)
# ------------------------------------------------------------
def ping_host(ip, timeout=1):
    """
    Ping an IP once. Cross-platform naive implementation.
    Returns True if alive, False otherwise.
    """
    try:
        # On Windows use '-n 1', on unix '-c 1'
        param = "-n" if sys.platform.startswith("win") else "-c"
        p = subprocess.run(["ping", param, "1", "-W", str(timeout), str(ip)],
                           capture_output=True)
        return p.returncode == 0
    except Exception:
        return False

def active_scan(subnet_cidr, max_hosts=100):
    """
    Very small active scan: iterate hosts in subnet (up to max_hosts) and ping them.
    WARNING: active network traffic is generated.
    """
    alive = []
    try:
        net = ipaddress.ip_network(subnet_cidr, strict=False)
    except Exception:
        return alive
    for i, host in enumerate(net.hosts()):
        if i >= max_hosts:
            break
        ip = str(host)
        if ping_host(ip):
            alive.append((ip, None))
    return alive

# ------------------------------------------------------------
# Geolocation using ip-api.com (with simple rate limiting)
# ------------------------------------------------------------
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,query,org,isp,message"

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def geolocate_ip(ip, session, rate=1.5, timeout=5):
    """
    Query ip-api.com for a single IP. Returns dict or None.
    Sleeps `rate` seconds AFTER each query to be polite with free API limits.
    """
    url = IP_API_URL.format(ip=ip)
    try:
        resp = session.get(url, timeout=timeout)
        data = resp.json()
    except Exception as e:
        data = {"status": "fail", "message": f"request_error: {e}", "query": ip}
    # respect rate limiting (simple)
    time.sleep(rate)
    return data

# ------------------------------------------------------------
# Main logic
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Collecte IPs locales et tente géolocalisation via ip-api.com (usage responsable).")
    parser.add_argument("--output", "-o", type=Path, default=Path("results/"), help="Dossier de sortie")
    parser.add_argument("--active", action="store_true", help="Activer balayage actif (ping). N'utilise que si tu as autorisation.")
    parser.add_argument("--subnet", help="Sous-réseau pour active scan (ex: 192.168.1.0/24) si --active")
    parser.add_argument("--include-private", action="store_true", help="Inclure les IP privées dans les requêtes de géolocalisation")
    parser.add_argument("--map", action="store_true", help="Générer un map.html simple (Leaflet) avec les points géolocalisés")
    parser.add_argument("--rate", type=float, default=1.5, help="Délai (s) entre requêtes vers ip-api (défaut 1.5s)")
    parser.add_argument("--dry-run", action="store_true", help="Simule l'exécution (pas d'appels ip-api, pas d'écriture)")
    parser.add_argument("--max-active-hosts", type=int, default=50, help="Max hosts pour active scan")
    args = parser.parse_args()

    outdir = args.output
    if not args.dry_run:
        outdir.mkdir(parents=True, exist_ok=True)

    print("=== sniff-map ===")
    print("Mode:", "ACTIVE scan" if args.active else "PASSIVE only")
    if args.active:
        print("!!! ATTENTION: Mode actif. Assure-toi d'avoir l'autorisation explicite avant de continuer.")
        # simple confirmation
        consent = input("Confirme que tu as l'autorisation (oui/non) : ").strip().lower()
        if consent not in ("oui", "o", "yes", "y"):
            print("Abandon (autorisation non confirmée).")
            return

    print("[*] Collecte passive (table ARP / voisinage)...")
    entries = get_arp_table()
    ips_set = {ip for ip, mac in entries}

    if args.active and args.subnet:
        print(f"[*] Lancement d'un petit active scan sur {args.subnet} (max {args.max_active_hosts} hôtes)...")
        active = active_scan(args.subnet, max_hosts=args.max_active_hosts)
        for ip, mac in active:
            ips_set.add(ip)

    if not ips_set:
        print("[!] Aucune IP trouvée en mode passif. Si tu es sur un réseau isolé, essaie --active avec subnet.")
    else:
        print(f"[*] IPs trouvées: {len(ips_set)}")

    session = requests.Session()
    session.headers.update({"User-Agent": "sniff-map/0.1 (+https://example.invalid)"})

    results = []
    for ip in sorted(ips_set):
        entry = {"ip": ip, "private": is_private(ip)}
        if entry["private"] and not args.include_private:
            entry["geo"] = {"status": "skipped", "message": "private_ip_not_queried"}
            print(f" - {ip} (private) -> skipped")
        else:
            if args.dry_run:
                # simuler une réponse
                entry["geo"] = {"status": "success", "country": "Simulated", "city": "Simulated", "lat": 0.0, "lon": 0.0, "query": ip}
                print(f" - {ip} -> simulated")
            else:
                print(f" - {ip} -> querying ip-api...")
                geo = geolocate_ip(ip, session, rate=args.rate)
                entry["geo"] = geo
        results.append(entry)

    report = {
        "meta": {
            "collected_count": len(results),
            "active_mode": args.active,
            "include_private": args.include_private,
            "dry_run": args.dry_run
        },
        "results": results
    }

    if not args.dry_run:
        json_path = outdir / "ips_geo.json"
        csv_path = outdir / "ips_geo.csv"
        with json_path.open("w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        # CSV simple
        with csv_path.open("w", encoding="utf-8", newline='') as f:
            w = csv.writer(f)
            w.writerow(["ip", "private", "status", "country", "region", "city", "lat", "lon", "query", "org", "isp", "message"])
            for r in results:
                geo = r.get("geo", {}) or {}
                w.writerow([
                    r["ip"],
                    r["private"],
                    geo.get("status"),
                    geo.get("country"),
                    geo.get("regionName"),
                    geo.get("city"),
                    geo.get("lat"),
                    geo.get("lon"),
                    geo.get("query"),
                    geo.get("org"),
                    geo.get("isp"),
                    geo.get("message")
                ])
        print(f"[OK] Résultats écrits: {json_path}, {csv_path}")

        if args.map:
            # génère un map.html simple en utilisant Leaflet et les coordonnées disponibles
            map_path = outdir / "map.html"
            points = []
            for r in results:
                geo = r.get("geo", {}) or {}
                if geo.get("status") == "success" and geo.get("lat") is not None and geo.get("lon") is not None:
                    points.append({"ip": r["ip"], "lat": geo.get("lat"), "lon": geo.get("lon"), "city": geo.get("city"), "country": geo.get("country")})
            # écrire HTML
            html = """<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>sniff-map results</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.3/dist/leaflet.css"/>
  <style>#map{height:90vh;width:100%;}</style>
</head>
<body>
  <h3>sniff-map results</h3>
  <div id="map"></div>
  <script src="https://unpkg.com/leaflet@1.9.3/dist/leaflet.js"></script>
  <script>
    const points = PLACEHOLDER_POINTS;
    const map = L.map('map').setView([20,0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom: 18}).addTo(map);
    points.forEach(p => {
      L.marker([p.lat, p.lon]).addTo(map).bindPopup(p.ip + ' — ' + (p.city||'') + ', ' + (p.country||''));
    });
  </script>
</body>
</html>
"""
            with map_path.open("w", encoding="utf-8") as f:
                f.write(html.replace("PLACEHOLDER_POINTS", json.dumps(points)))
            print(f"[OK] Carte HTML générée: {map_path}")

    else:
        print("[DRY-RUN] Aucun fichier écrit (--dry-run).")

if __name__ == "__main__":
    main()

