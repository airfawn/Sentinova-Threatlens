import sys
import time


def main() -> None:
	from PySide6.QtWidgets import QApplication

	from sentinova_threatlens.config import AppConfig
	from sentinova_threatlens.gui import theme
	from sentinova_threatlens.gui.main_window import MainWindow

	print("Creating app...")
	app = QApplication(sys.argv)
	print("App created")
	theme.apply(app)
	print("Theme applied")
	win = MainWindow(AppConfig())
	print("MainWindow created")
	win.show()
	print("Window shown")
	app.processEvents()
	print("Events processed")
	time.sleep(1)
	win.close()
	print("Closed successfully")


if __name__ == "__main__":
	main()