
class MLDetector:
    def __init__(self):
        self.threshold = 2000
    def detect(self, value):
        return value > self.threshold
