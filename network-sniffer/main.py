import sys
from PySide6.QtWidgets import QApplication
from gui.app import EnterpriseIDS

if __name__ == "__main__":
    # 1️⃣ QApplication must be created first
    app = QApplication(sys.argv)

    # 2️⃣ Create main window AFTER QApplication
    window = EnterpriseIDS()
    window.show()

    # 3️⃣ Start Qt event loop
    sys.exit(app.exec())
