from PySide6.QtCore import QThread, Signal
import pyshark
import asyncio
from utils.logger import log

class PySharkSniffer(QThread):
    packet_signal = Signal(object)

    # Set your TShark path here
    TSHARK_PATH = r"D:\Wireshark\tshark.exe"

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.running = True
        self.capture = None
        self.loop = None

        # Configure pyshark to use TShark
        pyshark.tshark.tshark.tshark_path = self.TSHARK_PATH

    def run(self):
        """
        Start live capture using PyShark on selected interface
        """
        try:
            # Create a dedicated event loop for this thread
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            self.capture = pyshark.LiveCapture(
                interface=self.iface,
                tshark_path=self.TSHARK_PATH
            )

            # Use async loop to sniff continuously
            self.loop.run_until_complete(self._sniff_loop())

        except Exception as e:
            log(f"PySharkSniffer error: {e}")
        finally:
            # Cleanup
            if self.capture:
                try:
                    self.loop.run_until_complete(self.capture.close_async())
                except Exception:
                    pass
            if self.loop and not self.loop.is_closed():
                self.loop.close()

    async def _sniff_loop(self):
        """
        Async loop to emit packets continuously
        """
        async for pkt in self.capture.sniff_continuously():
            if not self.running:
                break
            self.packet_signal.emit(pkt)

    def stop(self):
        """
        Stop live capture safely
        """
        self.running = False

        if self.capture and self.loop:
            # Close capture properly
            try:
                future = asyncio.run_coroutine_threadsafe(self.capture.close_async(), self.loop)
                future.result(timeout=3)
            except Exception as e:
                log(f"Error closing PyShark capture: {e}")

        self.quit()
        self.wait()
