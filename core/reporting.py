
import os
from google import genai
from datetime import datetime
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import json

def generate_executive_pdf(report_data, output_path):
    """
    Generates a professional PDF forensic report using ReportLab.
    """
    doc = SimpleDocTemplate(output_path, pagesize=LETTER)
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        'ExecutiveTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a73e8'),
        spaceAfter=20,
        alignment=1 # Center
    )
    
    sub_title_style = ParagraphStyle(
        'SubTitle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.grey,
        spaceAfter=30,
        alignment=1
    )

    story = []

    # Header
    story.append(Paragraph("AdvancedIDS Forensic Executive Report", title_style))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Case ID: {report_data.get('case_id')}", sub_title_style))
    story.append(Spacer(1, 12))

    # Summary Table
    data = [
        ['Metric', 'Value'],
        ['Primary Adversary', report_data.get('source_ip')],
        ['Classification', report_data.get('classification')],
        ['Confidence Score', report_data.get('confidence')],
        ['Risk Level', 'CRITICAL' if float(report_data.get('confidence', '0').strip('%')) > 90 else 'HIGH'],
        ['Timestamp', report_data.get('timestamp')],
        ['Target Node', report_data.get('destination_ip', '10.0.0.1')]
    ]
    
    table = Table(data, colWidths=[150, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a73e8')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(table)
    story.append(Spacer(1, 24))

    # AI Incident Narrative
    story.append(Paragraph("A.I. Strategic Narrative & Root Cause Analysis", styles['Heading2']))
    story.append(Spacer(1, 12))
    
    # Process the narrative from Gemini
    narrative = report_data.get('narrative', 'Neural synthesis offline.')
    for p in narrative.split('\n\n'):
        story.append(Paragraph(p.replace('\n', '<br/>'), styles['BodyText']))
        story.append(Spacer(1, 12))

    # Technical Footprint
    story.append(Spacer(1, 12))
    story.append(Paragraph("Technical Forensic Attribution", styles['Heading2']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Root Cause:</b> {report_data.get('reasoning', 'No deep DPI signature available.')}", styles['BodyText']))
    
    # Footer
    story.append(Spacer(1, 48))
    story.append(Paragraph("--- END OF REPORT | PROPRIETARY ADVANCED-IDS SOC CLASSIFIED ---", styles['Italic']))

    doc.build(story)
    return output_path

def get_ai_narrative(log_data, api_key=None):
    """
    Uses Gemini to synthesize a high-level incident narrative for the PDF.
    """
    if not api_key:
        api_key = os.getenv("GEMINI_API_KEY")
        
    if not api_key:
        return "Gemini API key is not configured. Neural narrative disabled."

    try:
        client = genai.Client(api_key=api_key)
        
        prompt = f"""
        You are a Senior Security Director. Summarize the following cyber-intelligence incident for an executive briefing:

        [INCIDENT TELEMETRY]
        IP: {log_data.get('source_ip')}
        Target: {log_data.get('destination_ip')}
        Classification: {log_data.get('label')}
        Confidence: {log_data.get('confidence')}
        Forensic Reasoning: {log_data.get('reasoning')}
        Historical Label: {log_data.get('historical_label')}
        
        [REQUIREMENTS]
        Write a professional 3-paragraph narrative:
        1. Overview: What happened and the significance of the threat.
        2. Impact: What could have occurred if the 'Active Defense' had not intervened.
        3. Strategic Assurance: Explain why the IDS classified this with such confidence.
        
        Use executive, authoritative language. Do not use markdown (use plain text).
        """
        
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        return response.text
    except Exception as e:
        return f"Incident synthesis failure: {str(e)}"
