import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from datetime import datetime

class ThreatPDFReport:
    def __init__(self, filename):
        self.filename = filename
        self.doc = SimpleDocTemplate(self.filename, pagesize=letter, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
        self.styles = getSampleStyleSheet()
        self.story = []

    def build_header(self):
        title_style = ParagraphStyle('TitleStyle', 
                                     parent=self.styles['Heading1'],
                                     fontSize=22, 
                                     textColor=colors.HexColor("#4a90e2"),
                                     alignment=1)
        
        self.story.append(Paragraph("AdvancedIDS Executive Security Report", title_style))
        self.story.append(Spacer(1, 15))
        
        meta_style = ParagraphStyle('Meta', parent=self.styles['Normal'], alignment=1, textColor=colors.darkgray)
        self.story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", meta_style))
        self.story.append(Spacer(1, 30))

    def build_summary_table(self, logs):
        self.story.append(Paragraph("Executive Summary", self.styles['Heading2']))
        self.story.append(Spacer(1, 10))

        total = len(logs)
        high_conf = sum(1 for log in logs if log.confidence >= 0.95)
        
        data = [
            ["Total Threats Logged", "High Confidence Incidents (>95%)"],
            [str(total), str(high_conf)]
        ]

        t = Table(data, colWidths=[250, 250])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f8f9fa")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor("#4a90e2")),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.white),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#eaeaea"))
        ]))
        
        self.story.append(t)
        self.story.append(Spacer(1, 30))

    def build_log_table(self, logs):
        self.story.append(Paragraph("Detailed Threat Logs", self.styles['Heading2']))
        self.story.append(Spacer(1, 10))

        data = [["Timestamp", "Source IP", "Classification", "Confidence"]]
        for log in logs[:100]:  # Limit to latest 100 on PDF
            data.append([
                log.timestamp.strftime('%m-%d %H:%M:%S'),
                log.source_ip,
                log.label,
                f"{log.confidence*100:.1f}%"
            ])

        t = Table(data, colWidths=[120, 130, 150, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#4a90e2")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 12),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey)
        ]))

        self.story.append(t)

    def generate(self, logs):
        self.build_header()
        self.build_summary_table(logs)
        self.build_log_table(logs)
        self.doc.build(self.story)
        return self.filename
