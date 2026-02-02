
from core.ml_detector import MLDetector
from core.mitre import mitre_map

class IDSEngine:
    def __init__(self):
        self.events = []
        self.ml = MLDetector()

    def analyze(self, pkt):
        alerts = []
        if pkt["length"] < 100:
            alerts.append("Port Scan detected")
        if pkt["length"] > 1500:
            alerts.append("Flood detected")
        if self.ml.detect(pkt["length"]):
            alerts.append("ML Anomaly detected")

        for a in alerts:
            self.events.append(a + " " + mitre_map(a))
        return alerts
