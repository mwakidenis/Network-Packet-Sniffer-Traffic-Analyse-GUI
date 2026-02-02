
def mitre_map(alert):
    if "Port" in alert: return "(T1046)"
    if "Flood" in alert: return "(T1499)"
    return "(Generic)"
