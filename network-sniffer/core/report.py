
from reportlab.pdfgen import canvas
def generate_pdf(events):
    c = canvas.Canvas("IDS_Report.pdf")
    c.drawString(50,800,"Enterprise IDS Report")
    y = 760
    for e in events:
        c.drawString(50,y,e); y -= 20
    c.save()
