from PySide6.QtWidgets import QWidget, QVBoxLayout
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from collections import defaultdict
import threading

class TrafficChart(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.fig = Figure(figsize=(5, 3))
        self.canvas = FigureCanvas(self.fig)
        self.layout.addWidget(self.canvas)
        self.ax_bandwidth = self.fig.add_subplot(211)
        self.ax_protocol = self.fig.add_subplot(212)

        # Data
        self.bandwidth_data = []
        self.protocol_count = defaultdict(int)

    def update_chart(self, pkt_summary, pkt_length):
        # Update bandwidth
        self.bandwidth_data.append(pkt_length)
        if len(self.bandwidth_data) > 50:
            self.bandwidth_data.pop(0)

        # Update protocol count
        proto = pkt_summary.split()[0]  # crude protocol extraction
        self.protocol_count[proto] += 1

        # Plot
        self.ax_bandwidth.clear()
        self.ax_bandwidth.plot(self.bandwidth_data, color='cyan')
        self.ax_bandwidth.set_title("Bandwidth over time")

        self.ax_protocol.clear()
        self.ax_protocol.bar(self.protocol_count.keys(), self.protocol_count.values(), color='magenta')
        self.ax_protocol.set_title("Protocol count")

        self.canvas.draw()
