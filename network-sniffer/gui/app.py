from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QComboBox, QFileDialog
)
from PySide6.QtCore import Qt
from gui.charts import TrafficChart
from utils.theme import DARK_THEME
from core.scapy_sniffer import ScapySniffer
from core.pyshark_sniffer import PySharkSniffer
from core.ids_engine import IDSEngine
from core.report import generate_pdf
from core.pcap_manager import PCAPManager

class EnterpriseIDS(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enterprise Network IDS")
        self.resize(1200, 800)
        self.setStyleSheet(DARK_THEME)

        # IDS and sniffers
        self.ids = IDSEngine()
        self.sniffer = None
        self.pyshark_sniffer = None
        self.packets = []
        self.pcap_manager = PCAPManager()

        # Chart widget
        self.chart_widget = TrafficChart()

        # GUI init
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        layout = QVBoxLayout()

        # --- Top control bar ---
        self.controls_layout = QHBoxLayout()
        self.iface = QComboBox()
        self.iface.addItems(["Ethernet", "Wi-Fi"])

        # Buttons
        self.btn_start = QPushButton("Start Capture")
        self.btn_stop = QPushButton("Stop Capture")
        self.btn_start_pyshark = QPushButton("Start Wireshark Bridge")
        self.btn_stop_pyshark = QPushButton("Stop Wireshark Bridge")
        self.btn_report = QPushButton("Generate Report")
        self.btn_export_pcap = QPushButton("Export PCAP")
        self.btn_import_pcap = QPushButton("Import PCAP")

        for w in [
            self.iface, self.btn_start, self.btn_stop,
            self.btn_start_pyshark, self.btn_stop_pyshark,
            self.btn_export_pcap, self.btn_import_pcap,
            self.btn_report
        ]:
            self.controls_layout.addWidget(w)

        layout.addLayout(self.controls_layout)

        # --- Log / packet view ---
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        # --- Add chart ---
        layout.addWidget(self.chart_widget)

        central.setLayout(layout)
        self.setCentralWidget(central)

        # --- Connect signals ---
        self.btn_start.clicked.connect(self.start_capture)
        self.btn_stop.clicked.connect(self.stop_capture)
        self.btn_report.clicked.connect(self.make_report)
        self.btn_export_pcap.clicked.connect(self.export_pcap)
        self.btn_import_pcap.clicked.connect(self.import_pcap)
        self.btn_start_pyshark.clicked.connect(self.start_pyshark)
        self.btn_stop_pyshark.clicked.connect(self.stop_pyshark)

    # ---------------- Scapy Capture ----------------
    def start_capture(self):
        if self.sniffer is None:
            self.sniffer = ScapySniffer(self.iface.currentText())
            self.sniffer.packet_signal.connect(self.handle_packet)
            self.sniffer.start()
            self.log.append("Scapy capture started...")

    def stop_capture(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer.wait()
            self.sniffer = None
            self.log.append("Scapy capture stopped.")

    def handle_packet(self, pkt):
        self.packets.append(pkt)
        try:
            length = len(pkt)
        except Exception:
            length = 0

        alerts = self.ids.analyze({
            "summary": pkt.summary(),
            "length": length
        })
        for a in alerts:
            self.log.append(a)

        self.chart_widget.update_chart(pkt.summary(), length)

    # ---------------- PyShark Capture ----------------
    def start_pyshark(self):
        if self.pyshark_sniffer is None:
            self.pyshark_sniffer = PySharkSniffer(self.iface.currentText())
            self.pyshark_sniffer.packet_signal.connect(self.handle_pyshark_packet)
            self.pyshark_sniffer.start()
            self.log.append("Wireshark live bridge started.")

    def stop_pyshark(self):
        if self.pyshark_sniffer:
            self.pyshark_sniffer.stop()
            self.pyshark_sniffer.wait()
            self.pyshark_sniffer = None
            self.log.append("Wireshark live bridge stopped.")

    def handle_pyshark_packet(self, pkt):
        summary = getattr(pkt, "summary", str(pkt))

        # Convert PyShark length safely to int
        try:
            length = int(getattr(pkt, "length", 0))
        except (TypeError, ValueError):
            length = 0

        alerts = self.ids.analyze({
            "summary": summary,
            "length": length
        })
        for a in alerts:
            self.log.append("[PyShark] " + a)

        self.chart_widget.update_chart(summary, length)

    # ---------------- PCAP Functions ----------------
    def export_pcap(self):
        if not self.sniffer:
            self.log.append("No active capture to export.")
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export PCAP", "", "PCAP Files (*.pcap)"
        )
        if filename:
            self.sniffer.export_pcap(filename)
            self.log.append(f"PCAP exported: {filename}")

    def import_pcap(self):
        if not self.sniffer:
            self.sniffer = ScapySniffer(self.iface.currentText())
            self.sniffer.packet_signal.connect(self.handle_packet)
            self.sniffer.start()
        filename, _ = QFileDialog.getOpenFileName(
            self, "Import PCAP", "", "PCAP Files (*.pcap)"
        )
        if filename:
            pkts = self.sniffer.import_pcap(filename)
            self.log.append(f"Imported {len(pkts)} packets from {filename}")

    # ---------------- Report ----------------
    def make_report(self):
        generate_pdf(self.ids.events)
        self.log.append("IDS_Report.pdf generated.")

    # ---------------- Clean exit ----------------
    def closeEvent(self, event):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer.wait()
        if self.pyshark_sniffer:
            self.pyshark_sniffer.stop()
            self.pyshark_sniffer.wait()
        event.accept()
