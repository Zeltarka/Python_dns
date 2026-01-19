#!/usr/bin/env python3
"""
DNS Mapper - Cartographie d'environnement DNS avec rapport PDF automatique
Usage: python dns_mapper.py <domain>
"""

import dns.resolver
import dns.reversename
import sys
import dns.exception
import ipaddress
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT


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
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.exception.DNSException):
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
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.exception.DNSException):
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
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.exception.DNSException):
            return []

    def resolve_txt(self):
        """
        Résout les enregistrements TXT

        Returns:
            list: Liste des enregistrements TXT, ou liste vide si erreur
        """
        try:
            answers = self.resolver.resolve(self.domain, 'TXT')
            txt_records = []
            for rdata in answers:
                txt = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                txt_records.append(txt)
            self.results['TXT'] = txt_records
            return txt_records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.exception.DNSException):
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
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.exception.DNSException):
            return []

    def scan_ip_neighbors(self, ip, range_size=5):
        """
        Scan les adresses IP voisines et fait un reverse DNS

        Args:
            ip (str): Adresse IP de base
            range_size (int): Nombre d'IPs à scanner de chaque côté (défaut: 5)

        Returns:
            dict: Dictionnaire {ip: domaines}
        """
        neighbors = {}
        try:
            ip_obj = ipaddress.IPv4Address(ip)

            for offset in range(-range_size, range_size + 1):
                if offset == 0:
                    continue

                try:
                    neighbor_ip = str(ip_obj + offset)
                    reverse = self.reverse_dns(neighbor_ip)
                    if reverse:
                        neighbors[neighbor_ip] = reverse
                except (ipaddress.AddressValueError, ValueError):
                    continue

        except ipaddress.AddressValueError:
            pass

        return neighbors

    def enumerate_subdomains(self):
        """
        Énumère les sous-domaines courants

        Returns:
            dict: Dictionnaire {subdomain: ips}
        """
        common_subdomains = [
            'www', 'mail', 'webmail', 'smtp', 'pop', 'imap',
            'ftp', 'api', 'admin', 'blog', 'dev', 'test',
            'preprod', 'staging', 'prod', 'production',
            'extranet', 'intranet', 'intra', 'vpn',
            'remote', 'portal', 'crm', 'erp',
            'mobile', 'app', 'cdn', 'static',
            'shop', 'store', 'payment', 'secure'
        ]

        found_subdomains = {}

        for sub in common_subdomains:
            subdomain = f"{sub}.{self.domain}"
            try:
                answers = self.resolver.resolve(subdomain, 'A')
                ips = [str(rdata) for rdata in answers]
                found_subdomains[subdomain] = ips
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.Timeout, dns.exception.DNSException):
                continue

        return found_subdomains

    def generate_pdf(self, filename):
        """
        Génère un rapport PDF complet

        Args:
            filename (str): Nom du fichier PDF de sortie
        """
        doc = SimpleDocTemplate(filename, pagesize=A4,
                                rightMargin=50, leftMargin=50,
                                topMargin=50, bottomMargin=50)

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#1e3a8a'),
            spaceAfter=20,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        section_style = ParagraphStyle(
            'Section',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#1e40af'),
            spaceBefore=15,
            spaceAfter=10,
            fontName='Helvetica-Bold',
            borderWidth=1,
            borderColor=colors.HexColor('#60a5fa'),
            borderPadding=5,
            backColor=colors.HexColor('#eff6ff')
        )
        normal_style = styles['Normal']
        normal_style.fontSize = 9

        story = []

        # Titre
        story.append(Paragraph(f"Rapport DNS - {self.domain}", title_style))
        story.append(Paragraph(f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}",
                               ParagraphStyle('date', parent=normal_style, alignment=TA_CENTER, fontSize=10)))
        story.append(Spacer(1, 0.3 * inch))

        # Section A Records
        story.append(Paragraph("Adresses IP (A Records)", section_style))
        if 'A' in self.results and self.results['A']:
            data = [['Adresse IP', 'Reverse DNS (PTR)']]
            for ip in self.results['A']:
                reverse = self.reverse_dns(ip)
                ptr = Paragraph(reverse[0] if reverse else '-', normal_style)
                data.append([ip, ptr])

            t = Table(data, colWidths=[1.8 * inch, 4.5 * inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('TOPPADDING', (0, 1), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f9ff')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bfdbfe'))
            ]))
            story.append(t)
        else:
            story.append(Paragraph("✗ Aucune adresse IP trouvée", normal_style))
        story.append(Spacer(1, 0.15 * inch))

        # Section MX Records
        story.append(Paragraph(" Serveurs Mail (MX Records)", section_style))
        if 'MX' in self.results and self.results['MX']:
            data = [['Serveur Mail']]
            for mx in self.results['MX']:
                data.append([Paragraph(mx, normal_style)])

            t = Table(data, colWidths=[6.3 * inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('TOPPADDING', (0, 1), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f9ff')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bfdbfe'))
            ]))
            story.append(t)
        else:
            story.append(Paragraph("✗ Aucun serveur mail trouvé", normal_style))
        story.append(Spacer(1, 0.15 * inch))

        # Section NS Records
        story.append(Paragraph("Nameservers (NS Records)", section_style))
        if 'NS' in self.results and self.results['NS']:
            data = [['Nameserver']]
            for ns in self.results['NS']:
                data.append([Paragraph(ns, normal_style)])

            t = Table(data, colWidths=[6.3 * inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('TOPPADDING', (0, 1), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f9ff')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bfdbfe'))
            ]))
            story.append(t)
        else:
            story.append(Paragraph("✗ Aucun nameserver trouvé", normal_style))
        story.append(Spacer(1, 0.15 * inch))

        # Section TXT Records
        story.append(Paragraph(" Enregistrements TXT", section_style))
        if 'TXT' in self.results and self.results['TXT']:
            data = [['Enregistrement TXT']]
            for txt in self.results['TXT']:
                data.append([Paragraph(txt, normal_style)])

            t = Table(data, colWidths=[6.3 * inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('TOPPADDING', (0, 1), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f9ff')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bfdbfe'))
            ]))
            story.append(t)
        else:
            story.append(Paragraph("✗  Aucun enregistrement TXT trouvé", normal_style))
        story.append(Spacer(1, 0.15 * inch))

        # Section IP Neighbors
        story.append(Paragraph(" Adresses IP Voisines", section_style))
        if 'neighbors' in self.results and self.results['neighbors']:
            for base_ip, neighbors in self.results['neighbors'].items():
                story.append(Paragraph(f"<b>Voisins de {base_ip}:</b>",
                                       ParagraphStyle('sub', parent=normal_style, fontSize=10,
                                                      textColor=colors.HexColor('#1e40af'), spaceAfter=5)))
                if neighbors:
                    data = [['IP Voisine', 'Domaine']]
                    for neighbor_ip, domains in neighbors.items():
                        data.append([neighbor_ip, Paragraph(domains[0], normal_style)])

                    t = Table(data, colWidths=[1.8 * inch, 4.5 * inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                        ('TOPPADDING', (0, 1), (-1, -1), 5),
                        ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f9ff')]),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bfdbfe'))
                    ]))
                    story.append(t)
                    story.append(Spacer(1, 0.1 * inch))
                else:
                    story.append(Paragraph("✗ Aucun voisin avec PTR trouvé", normal_style))
                    story.append(Spacer(1, 0.1 * inch))
        else:
            story.append(Paragraph("✗ Aucune IP voisine analysée", normal_style))
        story.append(Spacer(1, 0.15 * inch))

        # Section Subdomains
        story.append(Paragraph("🔗 Sous-domaines", section_style))
        if 'subdomains' in self.results and self.results['subdomains']:
            data = [['Sous-domaine', 'Adresses IP']]
            for subdomain, ips in self.results['subdomains'].items():
                ip_text = Paragraph(', '.join(ips), normal_style)
                data.append([Paragraph(subdomain, normal_style), ip_text])

            t = Table(data, colWidths=[3 * inch, 3.3 * inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('TOPPADDING', (0, 1), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f9ff')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bfdbfe'))
            ]))
            story.append(t)
        else:
            story.append(Paragraph("✗ Aucun sous-domaine trouvé", normal_style))

        # Construction du PDF
        doc.build(story)
        print(f"✓ Rapport PDF généré: {filename}")

    def scan(self):
        """Lance le scan complet du domaine (tout activé par défaut)"""
        print(f"Scan DNS en cours pour {self.domain}...")

        # Tous les scans activés
        print("  → Résolution A, MX, NS, TXT...")
        self.resolve_a()
        self.resolve_mx()
        self.resolve_ns()
        self.resolve_txt()

        # Scan des voisins pour chaque IP
        if 'A' in self.results and self.results['A']:
            print(f"  → Scan des voisins pour {len(self.results['A'])} IP(s)...")
            self.results['neighbors'] = {}
            for ip in self.results['A']:
                neighbors = self.scan_ip_neighbors(ip, range_size=5)
                self.results['neighbors'][ip] = neighbors

        # Énumération des sous-domaines
        print("  → Énumération des sous-domaines (peut prendre quelques secondes)...")
        subdomains = self.enumerate_subdomains()
        self.results['subdomains'] = subdomains
        print(f"  → {len(subdomains)} sous-domaine(s) trouvé(s)")

        print("✓ Scan terminé!")


def main():
    """Point d'entrée du programme"""
    if len(sys.argv) < 2:
        print("Erreur: Veuillez spécifier un domaine")
        print("\nUsage: python dns_mapper.py <domain>")
        print("\nExemple: python dns_mapper.py google.com")
        print("\nLe rapport PDF sera généré automatiquement avec le nom: dns_report_<domain>_<date>.pdf")
        sys.exit(1)

    domain = sys.argv[1]

    # Nom du fichier PDF automatique
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    pdf_filename = f"dns_report_{domain}_{timestamp}.pdf"

    # Création du mapper et scan complet
    mapper = DNSMapper(domain)
    mapper.scan()

    # Génération automatique du PDF
    mapper.generate_pdf(pdf_filename)


if __name__ == '__main__':
    main()