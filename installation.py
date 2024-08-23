import sys
import subprocess
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QPushButton, QRadioButton, QVBoxLayout,
    QWidget, QTextEdit, QProgressBar, QStackedWidget, QHBoxLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal


class InstallThread(QThread):
    update_progress = pyqtSignal(int)
    update_text = pyqtSignal(str)
    installation_finished = pyqtSignal()

    def run(self):
        try:
            # Run the PowerShell script
            process = subprocess.Popen(
                ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "install.ps1"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Read PowerShell output in real-time and update the progress bar
            for line in process.stdout:
                if "Progress:" in line:
                    # Assuming output format "Progress: X%"
                    progress_value = int(line.strip().split(":")[1].replace("%", ""))
                    self.update_progress.emit(progress_value)
                else:
                    # Update any other output to the GUI
                    self.update_text.emit(line.strip())

            process.wait()

            # Signal that installation is finished
            self.installation_finished.emit()

        except Exception as e:
            print(f"Error during installation: {e}")


class EULAWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Dell Power Manager Service v3.14.0")
        self.setGeometry(300, 300, 600, 400)

        self.stack = QStackedWidget(self)
        self.setCentralWidget(self.stack)

        self.startPage = QWidget()
        self.create_start_page()

        self.eulaPage = QWidget()
        self.create_eula_page()

        self.installPage = QWidget()
        self.create_installation_page()

        self.stack.addWidget(self.startPage)
        self.stack.addWidget(self.eulaPage)
        self.stack.addWidget(self.installPage)

    def create_start_page(self):
        layout = QVBoxLayout()

        title = QLabel("Dell Power Manager Service", self)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #1A73E8; padding: 20px;")

        description = QLabel("Welcome to the Dell Power Manager Service installation wizard.\nClick 'Next' to proceed.", self)
        description.setStyleSheet("font-size: 16px; color: #333; padding: 10px;")

        next_button = QPushButton("Next", self)
        next_button.clicked.connect(self.on_next_clicked_start)
        next_button.setStyleSheet("background-color: #1A73E8; color: white; padding: 10px 20px; border-radius: 8px;")

        layout.addWidget(title)
        layout.addWidget(description)
        layout.addWidget(next_button, alignment=Qt.AlignCenter)

        self.startPage.setLayout(layout)

    def create_eula_page(self):
        layout = QVBoxLayout()

        title = QLabel("Dell End User License Agreement - Dell Software", self)
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #1A73E8; padding: 10px;")

        eula_text = QTextEdit(self)
        eula_text.setReadOnly(True)
        eula_text.setText("THIS END USER LICENSE AGREEMENT (EULA) IS A LEGAL AGREEMENT...")
        eula_text.setStyleSheet("border: 1px solid #B0BEC5; background-color: #FAFAFA; padding: 10px;")

        self.acceptRadio = QRadioButton("I accept the terms in the license agreement", self)
        self.declineRadio = QRadioButton("I do not accept the terms in the license agreement", self)

        radio_style = "QRadioButton { color: #333; padding: 5px; } QRadioButton::indicator { width: 18px; height: 18px; }"
        self.acceptRadio.setStyleSheet(radio_style)
        self.declineRadio.setStyleSheet(radio_style)

        self.next_button_eula = QPushButton("Next", self)
        self.next_button_eula.clicked.connect(self.on_next_clicked_eula)
        self.next_button_eula.setStyleSheet("background-color: #1A73E8; color: white; padding: 8px 16px; border-radius: 5px;")
        self.next_button_eula.setEnabled(False)

        back_button = QPushButton("Back", self)
        back_button.clicked.connect(self.on_back_clicked_eula)
        back_button.setStyleSheet("background-color: #ECECEC; padding: 8px 16px; border-radius: 5px;")

        cancel_button = QPushButton("Cancel", self)
        cancel_button.clicked.connect(self.on_cancel_clicked_eula)
        cancel_button.setStyleSheet("background-color: #ECECEC; padding: 8px 16px; border-radius: 5px;")

        button_layout = QHBoxLayout()
        button_layout.addWidget(back_button)
        button_layout.addStretch()
        button_layout.addWidget(self.next_button_eula)
        button_layout.addWidget(cancel_button)

        layout.addWidget(title)
        layout.addWidget(eula_text)
        layout.addWidget(self.acceptRadio)
        layout.addWidget(self.declineRadio)
        layout.addLayout(button_layout)

        self.acceptRadio.toggled.connect(self.on_radio_button_toggled)

        self.eulaPage.setLayout(layout)

    def create_installation_page(self):
        layout = QVBoxLayout()

        installing_label = QLabel("Installing...", self)
        installing_label.setAlignment(Qt.AlignCenter)
        installing_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #1A73E8; padding: 20px;")

        self.progressBar = QProgressBar(self)
        self.progressBar.setValue(0)
        self.progressBar.setStyleSheet("""
            QProgressBar { border: 1px solid #B0BEC5; border-radius: 5px; text-align: center; height: 25px; }
            QProgressBar::chunk { background-color: #1A73E8; width: 20px; }
        """)

        self.output_text = QTextEdit(self)
        self.output_text.setReadOnly(True)
        self.output_text.setStyleSheet("border: 1px solid #B0BEC5; background-color: #FAFAFA; padding: 10px;")

        self.close_button = QPushButton("Close", self)
        self.close_button.clicked.connect(self.close)
        self.close_button.setStyleSheet("background-color: #1A73E8; color: white; padding: 5px 10px; border-radius: 5px;")
        self.close_button.setVisible(False)

        layout.addWidget(installing_label)
        layout.addWidget(self.progressBar)
        layout.addWidget(self.output_text)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.close_button)

        layout.addLayout(button_layout)

        self.installPage.setLayout(layout)

    def on_next_clicked_start(self):
        self.stack.setCurrentWidget(self.eulaPage)

    def on_next_clicked_eula(self):
        if self.acceptRadio.isChecked():
            self.stack.setCurrentWidget(self.installPage)
            self.start_installation()
        else:
            self.declineRadio.setChecked(True)

    def on_back_clicked_eula(self):
        self.stack.setCurrentWidget(self.startPage)

    def on_cancel_clicked_eula(self):
        self.close()

    def on_radio_button_toggled(self):
        self.next_button_eula.setEnabled(self.acceptRadio.isChecked())

    def start_installation(self):
        self.install_thread = InstallThread()
        self.install_thread.update_progress.connect(self.update_progress)
        self.install_thread.update_text.connect(self.update_text)
        self.install_thread.installation_finished.connect(self.installation_complete)
        self.install_thread.start()

    def update_progress(self, value):
        self.progressBar.setValue(value)

    def update_text(self, text):
        self.output_text.append(text)

    def installation_complete(self):
        self.progressBar.setValue(100)
        self.close_button.setVisible(True)


if __name__ == "__main__":
    app = QApplication(sys.argv) 
    window = EULAWindow()
    window.show()
    sys.exit(app.exec_())
