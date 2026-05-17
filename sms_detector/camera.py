from tkinter import messagebox

import customtkinter as ctk
from PIL import Image, ImageTk

try:
    import cv2
    CAMERA_AVAILABLE = True
except ImportError:
    cv2 = None
    CAMERA_AVAILABLE = False


class CameraWindow(ctk.CTkToplevel):
    def __init__(self, parent, on_capture_callback):
        super().__init__(parent)
        self.title("📷 Camera Capture")
        self.geometry("660x520")
        self.resizable(False, False)
        self.on_capture_callback = on_capture_callback
        self.cap = None
        self.running = False
        self.current_frame = None
        self._build_ui()
        self._start_camera()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        ctk.CTkLabel(
            self,
            text="Position the SMS message in the frame, then capture.",
            font=ctk.CTkFont(size=12),
            text_color="#9CA3AF",
        ).pack(pady=(12, 6))

        self.canvas = ctk.CTkLabel(self, text="", width=640, height=400)
        self.canvas.pack(padx=10)

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(pady=10)

        ctk.CTkButton(
            btn_row,
            text="📸  Capture & Scan",
            command=self._capture,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#00C48C",
            hover_color="#00A374",
            text_color="#0D1117",
            height=40,
            width=180,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_row,
            text="Cancel",
            command=self._on_close,
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            hover_color="#374151",
            height=40,
            width=100,
        ).pack(side="left")

    def _start_camera(self):
        if not CAMERA_AVAILABLE:
            messagebox.showerror("Camera Error", "opencv-python is not installed.")
            self.destroy()
            return
        self.cap = cv2.VideoCapture(0)
        if not self.cap.isOpened():
            messagebox.showerror("Camera Error", "Could not open camera.")
            self.destroy()
            return
        self.running = True
        self._update_feed()

    def _update_feed(self):
        if not self.running:
            return
        ret, frame = self.cap.read()
        if ret:
            self.current_frame = frame
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(rgb).resize((640, 400))
            photo = ImageTk.PhotoImage(img)
            self.canvas.configure(image=photo)
            self.canvas.image = photo
        self.after(30, self._update_feed)

    def _capture(self):
        if self.current_frame is None:
            messagebox.showerror("Error", "No frame captured.")
            return
        rgb = cv2.cvtColor(self.current_frame, cv2.COLOR_BGR2RGB)
        image = Image.fromarray(rgb)
        self._on_close()
        self.on_capture_callback(image)

    def _on_close(self):
        self.running = False
        if self.cap:
            self.cap.release()
        self.destroy()
