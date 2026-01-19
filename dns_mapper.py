#!/usr/bin/env python3
"""
DNS Mapper - Cartographie d'environnement DNS
Usage: python dns_mapper.py <domain>
"""

import dns.resolver
import dns.reversename
import sys
import dns.exception


class DNSMapper:
    """Classe pour cartographier l'environnement DNS d'un domaine"""

    def __init__(self, domain):
        """
        Initialise le mapper DNS

        Args:
            domain (str): Le nom de domaine à analyser
        """
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.results = {}

    def resolve_a(self):
        """
        Résout les enregistrements A (IPv4)

        Returns:
            list: Liste des adresses IP, ou liste vide si erreur
        """
        try:
            answers = self.resolver.resolve(self.domain, 'A')
            ips = [str(rdata) for rdata in answers]
            self.results['A'] = ips
            return ips
        except dns.resolver.NXDOMAIN:
            # Le domaine n'existe pas
            print(f"  [!] Domaine inexistant")
            return []
        except dns.resolver.NoAnswer:
            # Le domaine existe mais n'a pas d'enregistrement A
            print(f"  [!] Pas d'enregistrement A")
            return []
        except dns.resolver.Timeout:
            # Timeout de la requête DNS
            print(f"  [!] Timeout")
            return []
        except dns.exception.DNSException as e:
            # Autre erreur DNS
            print(f"  [!] Erreur DNS: {e}")
            return []

    def resolve_mx(self):
        """
        Résout les enregistrements MX (serveurs mail)

        Returns:
            list: Liste des serveurs mail, ou liste vide si erreur
        """
        try:
            answers = self.resolver.resolve(self.domain, 'MX')
            mx_servers = [str(rdata.exchange).rstrip('.') for rdata in answers]
            self.results['MX'] = mx_servers
            return mx_servers
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.Timeout:
            return []
        except dns.exception.DNSException:
            return []

    def resolve_ns(self):
        """
        Résout les enregistrements NS (nameservers)

        Returns:
            list: Liste des nameservers, ou liste vide si erreur
        """
        try:
            answers = self.resolver.resolve(self.domain, 'NS')
            nameservers = [str(rdata.target).rstrip('.') for rdata in answers]
            self.results['NS'] = nameservers
            return nameservers
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.Timeout:
            return []
        except dns.exception.DNSException:
            return []

    def resolve_txt(self):
        """
        Résout les enregistrements TXT

        Returns:
            list: Liste des enregistrements TXT, ou liste vide si erreur
        """
        try:  # ← CORRIGÉ : 4 espaces maintenant !
            answers = self.resolver.resolve(self.domain, 'TXT')
            txt_records = []
            for rdata in answers:
                # Decode bytes si nécessaire et joint toutes les strings
                txt = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                txt_records.append(txt)
            self.results['TXT'] = txt_records
            return txt_records
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.Timeout:
            return []
        except dns.exception.DNSException:
            return []

    def reverse_dns(self, ip):
        """
        Fait un reverse DNS (IP → domaine)

        Args:
            ip (str): Adresse IP à résoudre

        Returns:
            list: Liste des noms de domaine, ou liste vide si erreur
        """
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, 'PTR')
            return [str(rdata).rstrip('.') for rdata in answers]
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.Timeout:
            return []
        except dns.exception.DNSException:
            return []

    def scan(self):
        """Lance le scan complet du domaine"""
        print(f" Scanning {self.domain}...\n")
        print("=" * 60)

        # Records A
        print("\n Résolution des adresses IP (A Records)...")
        ips = self.resolve_a()
        if ips:
            print(f"✓ Trouvé {len(ips)} adresse(s) IP:")
            for ip in ips:
                print(f"  • {ip}")
                # Reverse DNS
                reverse = self.reverse_dns(ip)
                if reverse:
                    print(f"    ↳ PTR: {reverse[0]}")
        else:
            print("  ✗ Aucune adresse IP trouvée")

        # Records MX
        print("\n Résolution des serveurs mail (MX Records)...")
        mx_servers = self.resolve_mx()
        if mx_servers:
            print(f"✓ Trouvé {len(mx_servers)} serveur(s) mail:")
            for mx in mx_servers:
                print(f"  • {mx}")
        else:
            print("  ✗ Aucun serveur mail trouvé")

        # Records NS
        print("\n Résolution des nameservers (NS Records)...")
        nameservers = self.resolve_ns()
        if nameservers:
            print(f"✓ Trouvé {len(nameservers)} nameserver(s):")
            for ns in nameservers:
                print(f"  • {ns}")
        else:
            print("  ✗ Aucun nameserver trouvé")

        # Records TXT
        print("\n Résolution des enregistrements TXT...")
        txt_records = self.resolve_txt()
        if txt_records:
            print(f"✓ Trouvé {len(txt_records)} enregistrement(s) TXT:")
            for txt in txt_records:
                # Tronque à 80 caractères pour la lisibilité
                if len(txt) > 80:
                    print(f"  • {txt[:80]}...")
                else:
                    print(f"  • {txt}")
        else:
            print("  ✗ Aucun enregistrement TXT trouvé")

        print("\n" + "=" * 60)
        print(f" Scan terminé!\n")


def main():
    """Point d'entrée du programme"""
    # Vérification du nombre d'arguments
    if len(sys.argv) != 2:
        print("Erreur: nombre d'arguments incorrect")
        print("\nUsage: python dns_mapper.py <domain>")
        print("\nExemple:")
        print("  python dns_mapper.py google.com")
        sys.exit(1)

    # Récupération du domaine
    domain = sys.argv[1]

    # Création du mapper et lancement du scan
    mapper = DNSMapper(domain)
    mapper.scan()


if __name__ == '__main__':
    main()