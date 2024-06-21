import sys
import cv2
import numpy as np
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget, QPushButton
from PyQt5.QtGui import QImage, QPixmap
from PyQt5.QtCore import QTimer, Qt

class CameraApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Finger Drawing App")
        self.setGeometry(100, 100, 640, 480)

        self.video_label = QLabel(self)
        self.video_label.resize(640, 480)

        self.start_button = QPushButton('Start Camera', self)
        self.start_button.setGeometry(10, 10, 100, 30)
        self.start_button.clicked.connect(self.start_camera)

        self.stop_button = QPushButton('Stop Camera', self)
        self.stop_button.setGeometry(120, 10, 100, 30)
        self.stop_button.clicked.connect(self.stop_camera)
        self.stop_button.setEnabled(False)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_frame)

        layout = QVBoxLayout()
        layout.addWidget(self.video_label)
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        self.camera = None
        self.is_camera_running = False
        self.drawing = False
        self.last_point1 = None
        self.last_point2 = None

    def start_camera(self):
        if not self.is_camera_running:
            self.camera = cv2.VideoCapture(0)  # Open default camera (usually 0 or -1)
            if not self.camera.isOpened():
                self.video_label.setText("Error: Could not open camera.")
                return

            self.is_camera_running = True
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.timer.start(30)  # 30 milliseconds

    def stop_camera(self):
        if self.is_camera_running:
            self.is_camera_running = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.timer.stop()
            self.camera.release()

    def update_frame(self):
        ret, frame = self.camera.read()
        if ret:
            frame = cv2.flip(frame, 1)  # Mirror view
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

            # Convert frame to grayscale for processing
            frame_gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

            # Apply Gaussian blur to reduce noise
            frame_blur = cv2.GaussianBlur(frame_gray, (5, 5), 0)

            # Threshold the image to get binary image of the hand
            _, binary = cv2.threshold(frame_blur, 70, 255, cv2.THRESH_BINARY_INV+cv2.THRESH_OTSU)

            # Find contours in the binary image
            contours, _ = cv2.findContours(binary, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)

            # Find the largest contour (hand)
            if contours:
                hand_contour = max(contours, key=cv2.contourArea)
                hull = cv2.convexHull(hand_contour, returnPoints=False)
                defects = cv2.convexityDefects(hand_contour, hull)

                if defects is not None:
                    for i in range(defects.shape[0]):
                        s, e, f, d = defects[i, 0]
                        start = tuple(hand_contour[s][0])
                        end = tuple(hand_contour[e][0])
                        far = tuple(hand_contour[f][0])

                        # Draw when two fingers are detected (adjust this threshold as needed)
                        if d > 30000:
                            cv2.circle(frame_rgb, far, 5, [0, 0, 255], -1)

                            if self.last_point1 is None:
                                self.last_point1 = far
                            elif self.last_point2 is None:
                                self.last_point2 = far
                                self.drawing = True
                            else:
                                self.last_point1 = far
                                self.last_point2 = None
                                self.drawing = False

                            if self.drawing and self.last_point1 is not None and self.last_point2 is not None:
                                cv2.line(frame_rgb, self.last_point1, self.last_point2, (255, 0, 0), 5)
                                self.last_point1 = self.last_point2
                                self.last_point2 = None

            # Display the frame with drawing on PyQt5 QLabel
            frame_qimg = QImage(frame_rgb.data, frame_rgb.shape[1], frame_rgb.shape[0], QImage.Format_RGB888)
            self.video_label.setPixmap(QPixmap.fromImage(frame_qimg).scaled(640, 480, Qt.KeepAspectRatio))

        else:
            self.stop_camera()
            self.video_label.setText("Error: Could not read frame.")

    def closeEvent(self, event):
        self.stop_camera()
        event.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CameraApp()
    window.show()
    sys.exit(app.exec_())
