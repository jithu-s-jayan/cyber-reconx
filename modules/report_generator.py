import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import time

def generate_pdf_report(scan_data, filename="recon_report.pdf"):
    # Output file setup
    doc = SimpleDocTemplate(filename, pagesize=letter,
                            rightMargin=54, leftMargin=54,
                            topMargin=54, bottomMargin=54)
    
    styles = getSampleStyleSheet()
    
    # Define custom cyber neon color scheme styles
    dark_primary = colors.HexColor("#08090c")
    cyber_cyan = colors.HexColor("#00f0ff")
    accent_purple = colors.HexColor("#bc00dd")
    text_white = colors.HexColor("#ffffff")
    text_gray = colors.HexColor("#8a93a6")
    risk_color = colors.HexColor("#ff3b30") if scan_data.get("threat_level") == "High" else colors.HexColor("#ff9500") if scan_data.get("threat_level") == "Medium" else colors.HexColor("#34c759")
    
    # Custom Paragraph Styles
    title_style = ParagraphStyle(
        'CyberTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=cyber_cyan,
        alignment=0,
        spaceAfter=15
    )
    
    header_style = ParagraphStyle(
        'CyberHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=accent_purple,
        spaceBefore=15,
        spaceAfter=10
    )
    
    body_style = ParagraphStyle(
        'CyberBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=text_gray,
        spaceAfter=8
    )
    
    body_white_style = ParagraphStyle(
        'CyberBodyWhite',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=text_white,
        spaceAfter=8
    )

    story = []
    
    # Header block
    story.append(Paragraph("CYBER RECONX - SECURITY INTELLIGENCE REPORT", title_style))
    story.append(Paragraph(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} (UTC)", body_style))
    story.append(Paragraph(f"<b>Recon Target:</b> {scan_data.get('target', 'N/A')}", body_white_style))
    story.append(Paragraph(f"<b>Scan Class:</b> {scan_data.get('scan_type', 'N/A')}", body_style))
    story.append(Spacer(1, 15))
    
    # Score Summary Table
    score_data = [
        [Paragraph("<b>METRIC</b>", body_white_style), Paragraph("<b>VALUE</b>", body_white_style)],
        [Paragraph("Threat Severity Level", body_style), Paragraph(f"<font color='{risk_color.hexval()}'><b>{scan_data.get('threat_level', 'Info')}</b></font>", body_style)],
        [Paragraph("Security/Threat Score", body_style), Paragraph(f"<b>{scan_data.get('threat_score', 0)} / 100</b>", body_style)],
        [Paragraph("Target Address/Details", body_style), Paragraph(scan_data.get('target', 'Unknown'), body_style)]
    ]
    
    t_summary = Table(score_data, colWidths=[2.5*inch, 3.5*inch])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f111a")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#1b1e2e")),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#08090c")),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 20))
    
    # Details section
    story.append(Paragraph("SECURITY FINDINGS & METRICS SUMMARY", header_style))
    story.append(Paragraph(scan_data.get('summary', 'No summary details compiled.'), body_style))
    story.append(Spacer(1, 15))
    
    # Recommendations
    story.append(Paragraph("CYBER DEFENSE & REMEDIATION STEPS", header_style))
    recs = get_recommendations(scan_data.get("threat_level", "Low"))
    for rec in recs:
        story.append(Paragraph(f"• {rec}", body_style))
        
    story.append(Spacer(1, 40))
    story.append(Paragraph("<i>CONFIDENTIAL DOCUMENT: Intended only for system owners and verified authorized security review presentation. No real target was subjected to unauthorized scanning during compilation.</i>", body_style))
    
    # Build Document
    doc.build(story)

def get_recommendations(level):
    if level == "High":
        return [
            "Disable outdated cleartext services (FTP, Telnet, POP3, IMAP) immediately.",
            "Deploy a robust Web Application Firewall (WAF) to filter malicious network scans.",
            "Ensure SSL certificates are up-to-date and restrict key access control pathways.",
            "Review dynamic access security headers; enforce modern Content-Security-Policy (CSP) protocols."
        ]
    elif level == "Medium":
        return [
            "Update open ports services banners and apply patch updates to web engine servers.",
            "Incorporate HTTP strict transport layers across internal DNS parameters.",
            "Keep server banners hidden to mitigate intelligence gatherers pinpointing potential CVE maps."
        ]
    else:
        return [
            "Continually monitor port configuration updates.",
            "Perform scheduled scans using Cyber ReconX to verify posture remains optimized."
        ]
