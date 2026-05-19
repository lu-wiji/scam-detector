import csv
import threading
from datetime import datetime
from tkinter import messagebox, filedialog

import customtkinter as ctk
from PIL import Image, ImageTk

from .camera import CameraWindow, CAMERA_AVAILABLE
from .config import GMAIL_SENDER
from .gmail_report import send_gmail_report
from .ocr import extract_text
from .rules import RULES, scan_message

SCAN_HISTORY = []


class SMSDetectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SMS Phishing & Spam Detector")
        self.geometry("950x750")
        self.minsize(800, 600)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.last_result = None
        self.recipient_var = ctk.StringVar(value=GMAIL_SENDER)
        self.chat_message_text = ""
        self.chat_result = None
        self.chat_questions = []
        self.chat_question_index = 0
        self.chat_answers = []
        self._build_ui()

    # ── Layout ──────────────────────────────
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(self, fg_color="#0D1117", corner_radius=0, height=64)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        ctk.CTkLabel(
            header,
            text="🛡️  SMS Phishing & Spam Detector",
            font=ctk.CTkFont(family="Courier New", size=20, weight="bold"),
            text_color="#00C48C",
        ).pack(side="left", padx=24, pady=14)
        ctk.CTkLabel(
            header,
            text="Regex + OCR Threat Detection",
            font=ctk.CTkFont(size=11),
            text_color="#555E6E",
        ).pack(side="right", padx=24)

        # Tabs
        self.tabs = ctk.CTkTabview(self, fg_color="#0D1B2A")
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=12, pady=(6, 12))
        self.tabs.add("Scanner")
        self.tabs.add("Image Scan")
        self.tabs.add("Rule Engine")
        self.tabs.add("History")

        self._build_scanner_tab(self.tabs.tab("Scanner"))
        self._build_image_tab(self.tabs.tab("Image Scan"))
        self._build_rules_tab(self.tabs.tab("Rule Engine"))
        self._build_history_tab(self.tabs.tab("History"))

    # ── Scanner Tab ─────────────────────────
    def _build_scanner_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        input_frame = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10)
        input_frame.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 6))
        input_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            input_frame,
            text="Security Assistant Chat",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#00C48C",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 2))

        ctk.CTkLabel(
            input_frame,
            text="Paste a message and the assistant will question it like a senior security analyst.",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#9CA3AF",
        ).grid(row=1, column=0, sticky="w", padx=14, pady=(0, 6))

        self.sms_input = ctk.CTkTextbox(
            input_frame,
            height=100,
            font=ctk.CTkFont(family="Courier New", size=13),
            fg_color="#0D1117",
            text_color="#E5E7EB",
            border_color="#1F2937",
            border_width=1,
        )
        self.sms_input.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 4))

        btn_row = ctk.CTkFrame(input_frame, fg_color="transparent")
        btn_row.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 10))
        btn_row.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            btn_row,
            text="⚡  START REVIEW",
            command=self._run_text_scan,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#00C48C",
            hover_color="#00A374",
            text_color="#0D1117",
            height=38,
            width=180,
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(
            btn_row,
            text="Clear",
            command=self._clear_text,
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            hover_color="#374151",
            height=38,
            width=80,
        ).grid(row=0, column=1, sticky="w", padx=(8, 0))

        self.recipient_entry = ctk.CTkEntry(
            btn_row,
            textvariable=self.recipient_var,
            height=38,
            placeholder_text="Recipient email",
        )
        self.recipient_entry.grid(row=0, column=2, sticky="ew", padx=(12, 12))

        ctk.CTkButton(
            btn_row,
            text="📤 Export Report",
            command=lambda: self._export_report(self.sms_input.get("1.0", "end").strip()),
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            hover_color="#374151",
            height=38,
            width=130,
        ).grid(row=0, column=4, sticky="e")

        ctk.CTkButton(
            btn_row,
            text="📧 Send Report",
            command=self._send_latest_report,
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            hover_color="#374151",
            height=38,
            width=120,
        ).grid(row=0, column=3, sticky="e", padx=(0, 8))

        self.initial_read_frame = ctk.CTkFrame(parent, fg_color="#0D1B2A", corner_radius=10)
        self.initial_read_frame.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 4))
        self.initial_read_frame.grid_columnconfigure(0, weight=1)
        self._clear_initial_read()

        self.chat_status = ctk.CTkLabel(
            parent,
            text="The assistant will explain its analysis and ask follow-up questions here.",
            font=ctk.CTkFont(size=12),
            text_color="#9CA3AF",
        )
        self.chat_status.grid(row=2, column=0, sticky="w", padx=8, pady=(0, 4))

        self.chat_history_frame = ctk.CTkScrollableFrame(
            parent, fg_color="#0D1B2A", corner_radius=10
        )
        self.chat_history_frame.grid(row=3, column=0, sticky="nsew", padx=4, pady=(0, 4))
        self.chat_history_frame.grid_columnconfigure(0, weight=1)
        self._render_chat_history()

        answer_bar = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10)
        answer_bar.grid(row=4, column=0, sticky="ew", padx=4, pady=(0, 4))
        answer_bar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            answer_bar,
            text="Answer the assistant",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#9CA3AF",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 4))

        answer_buttons = ctk.CTkFrame(answer_bar, fg_color="transparent")
        answer_buttons.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 12))
        answer_buttons.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.yes_button = ctk.CTkButton(
            answer_buttons,
            text="Yes",
            command=lambda: self._handle_chat_answer("yes"),
            fg_color="#1D4ED8",
            hover_color="#1E40AF",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
        )
        self.yes_button.grid(row=0, column=0, padx=(0, 8), sticky="ew")

        self.no_button = ctk.CTkButton(
            answer_buttons,
            text="No",
            command=lambda: self._handle_chat_answer("no"),
            fg_color="#374151",
            hover_color="#4B5563",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
        )
        self.no_button.grid(row=0, column=1, padx=(0, 8), sticky="ew")

        self.unsure_button = ctk.CTkButton(
            answer_buttons,
            text="Unsure",
            command=lambda: self._handle_chat_answer("unsure"),
            fg_color="#7C3AED",
            hover_color="#6D28D9",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
        )
        self.unsure_button.grid(row=0, column=2, padx=(0, 8), sticky="ew")

        self.reset_button = ctk.CTkButton(
            answer_buttons,
            text="Reset",
            command=self._reset_security_chat,
            fg_color="#1F2937",
            hover_color="#374151",
            font=ctk.CTkFont(size=12),
            height=36,
        )
        self.reset_button.grid(row=0, column=3, sticky="ew")

        self._set_chat_answer_state("disabled")

    # ── Image Scan Tab ───────────────────────
    def _build_image_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(2, weight=1)

        # Top action buttons
        action_frame = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10)
        action_frame.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 6))
        action_frame.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(
            action_frame,
            text="Scan an SMS screenshot or photo — OCR extracts the text automatically.",
            font=ctk.CTkFont(size=12),
            text_color="#9CA3AF",
        ).grid(row=0, column=0, columnspan=2, padx=14, pady=(10, 8))

        ctk.CTkButton(
            action_frame,
            text="📁  Upload Image",
            command=self._upload_image,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#1D4ED8",
            hover_color="#1E40AF",
            height=44,
        ).grid(row=1, column=0, padx=(14, 6), pady=(0, 12), sticky="ew")

        cam_btn = ctk.CTkButton(
            action_frame,
            text="📷  Capture from Camera",
            command=self._open_camera,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#7C3AED" if CAMERA_AVAILABLE else "#374151",
            hover_color="#6D28D9" if CAMERA_AVAILABLE else "#374151",
            height=44,
            state="normal" if CAMERA_AVAILABLE else "disabled",
        )
        cam_btn.grid(row=1, column=1, padx=(6, 14), pady=(0, 12), sticky="ew")

        ctk.CTkButton(
            action_frame,
            text="📧  Send Report",
            command=self._send_latest_report,
            font=ctk.CTkFont(size=12),
            fg_color="#1F2937",
            hover_color="#374151",
            height=38,
        ).grid(row=2, column=0, columnspan=2, padx=14, pady=(0, 10), sticky="ew")

        if not CAMERA_AVAILABLE:
            ctk.CTkLabel(
                action_frame,
                text="⚠ opencv-python not installed — camera unavailable",
                font=ctk.CTkFont(size=10),
                text_color="#6B7280",
            ).grid(row=3, column=0, columnspan=2, pady=(0, 8))

        # Image preview + extracted text side by side
        preview_frame = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10)
        preview_frame.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 6))
        preview_frame.grid_columnconfigure(0, weight=1)
        preview_frame.grid_columnconfigure(1, weight=1)

        # Left: image preview
        ctk.CTkLabel(
            preview_frame,
            text="Image Preview",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#6B7280",
        ).grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        self.image_preview_label = ctk.CTkLabel(
            preview_frame,
            text="No image loaded",
            font=ctk.CTkFont(size=12),
            text_color="#374151",
            width=300,
            height=180,
            fg_color="#0D1117",
            corner_radius=6,
        )
        self.image_preview_label.grid(row=1, column=0, padx=14, pady=(0, 12), sticky="nsew")

        # Right: extracted text
        ctk.CTkLabel(
            preview_frame,
            text="Extracted Text (auto OCR)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#6B7280",
        ).grid(row=0, column=1, padx=14, pady=(10, 4), sticky="w")

        self.ocr_text_box = ctk.CTkTextbox(
            preview_frame,
            height=180,
            font=ctk.CTkFont(family="Courier New", size=11),
            fg_color="#0D1117",
            text_color="#00C48C",
            border_color="#1F2937",
            border_width=1,
        )
        self.ocr_text_box.grid(row=1, column=1, padx=14, pady=(0, 12), sticky="nsew")

        # Status bar
        self.ocr_status = ctk.CTkLabel(
            parent,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="#9CA3AF",
        )
        self.ocr_status.grid(row=2, column=0, sticky="n", pady=(0, 4))

        # Results
        self.image_results_frame = ctk.CTkScrollableFrame(
            parent, fg_color="#0D1B2A", corner_radius=10
        )
        self.image_results_frame.grid(row=3, column=0, sticky="nsew", padx=4, pady=(0, 4))
        self.image_results_frame.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(3, weight=1)
        self._show_placeholder(self.image_results_frame)

    # ── Image Pipeline ───────────────────────
    def _upload_image(self):
        path = filedialog.askopenfilename(
            title="Select SMS Screenshot or Photo",
            filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff *.webp")],
        )
        if not path:
            return
        image = Image.open(path)
        self._run_image_pipeline(image)

    def _open_camera(self):
        if not CAMERA_AVAILABLE:
            messagebox.showwarning("Unavailable", "Install opencv-python to use camera.")
            return
        CameraWindow(self, on_capture_callback=self._run_image_pipeline)

    def _run_image_pipeline(self, image: Image.Image):
        """Automated pipeline: show preview → OCR → scan → results."""
        # Show preview
        self._show_image_preview(image)

        # Update status
        self.ocr_status.configure(text="⏳ Running OCR... please wait", text_color="#FFD700")

        # Clear previous
        self.ocr_text_box.delete("1.0", "end")
        self._show_placeholder(self.image_results_frame)

        # Run OCR + scan in background thread so UI stays responsive
        def pipeline():
            try:
                # Step 1: OCR
                text = extract_text(image)

                # Step 2: Update UI with extracted text
                self.after(0, lambda: self._set_ocr_text(text))

                if not text:
                    self.after(0, lambda: self.ocr_status.configure(
                        text="⚠ No text detected in image. Try a clearer photo.",
                        text_color="#FF8C00",
                    ))
                    return

                # Step 3: Auto scan
                self.after(0, lambda: self.ocr_status.configure(
                    text="🔍 Scanning extracted text...", text_color="#00C48C"
                ))
                result = scan_message(text)
                SCAN_HISTORY.append(result)

                # Step 4: Display results
                self.after(0, lambda: self._finish_image_pipeline(result))

            except Exception as e:
                self.after(0, lambda: self.ocr_status.configure(
                    text=f"❌ Error: {e}", text_color="#FF4C4C"
                ))

        threading.Thread(target=pipeline, daemon=True).start()

    def _set_ocr_text(self, text):
        self.ocr_text_box.delete("1.0", "end")
        self.ocr_text_box.insert("1.0", text if text else "(no text found)")

    def _finish_image_pipeline(self, result):
        self.ocr_status.configure(
            text=f"✅ Scan complete — {len(result['findings'])} threat(s) found",
            text_color="#00C48C",
        )
        self.last_result = result
        self._refresh_history()
        self._display_results(result, self.image_results_frame)

    def _show_image_preview(self, image: Image.Image):
        preview = image.copy()
        preview.thumbnail((300, 180))
        photo = ImageTk.PhotoImage(preview)
        self.image_preview_label.configure(image=photo, text="")
        self.image_preview_label.image = photo

    # ── Shared Results Renderer ──────────────
    def _show_placeholder(self, frame):
        for w in frame.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            frame,
            text="Results will appear here after scanning.",
            font=ctk.CTkFont(size=13),
            text_color="#374151",
        ).pack(pady=40)

    def _display_results(self, result: dict, frame):
        for w in frame.winfo_children():
            w.destroy()

        # Risk banner
        banner = ctk.CTkFrame(
            frame,
            fg_color=result["risk_bg"],
            border_color=result["risk_color"],
            border_width=2,
            corner_radius=10,
        )
        banner.pack(fill="x", padx=4, pady=(6, 10))

        ctk.CTkLabel(
            banner,
            text=f"{result.get('risk_icon', '')}  {result['risk']}",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=result["risk_color"],
        ).pack(side="left", padx=20, pady=14)

        ctk.CTkLabel(
            banner,
            text=f"Threat Score: {result['score']}/100",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=result["risk_color"],
        ).pack(side="right", padx=20)

        # Score bar
        bar_frame = ctk.CTkFrame(frame, fg_color="#111827", corner_radius=8)
        bar_frame.pack(fill="x", padx=4, pady=(0, 10))
        ctk.CTkLabel(
            bar_frame, text="Threat Level",
            font=ctk.CTkFont(size=11), text_color="#9CA3AF",
        ).pack(anchor="w", padx=12, pady=(8, 2))
        bar = ctk.CTkProgressBar(
            bar_frame, progress_color=result["risk_color"],
            fg_color="#1F2937", height=14,
        )
        bar.pack(fill="x", padx=12, pady=(0, 10))
        bar.set(result["score"] / 100)

        if not result["findings"]:
            ctk.CTkLabel(
                frame,
                text="✅  No threats detected. Message appears safe.",
                font=ctk.CTkFont(size=14),
                text_color="#00C48C",
            ).pack(pady=20)
            return

        ctk.CTkLabel(
            frame,
            text=f"⚠️  {len(result['findings'])} threat pattern(s) found:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#E5E7EB",
        ).pack(anchor="w", padx=8, pady=(0, 6))

        for finding in result["findings"]:
            card = ctk.CTkFrame(
                frame,
                fg_color="#111827",
                border_color=finding["color"],
                border_width=1,
                corner_radius=8,
            )
            card.pack(fill="x", padx=4, pady=3)
            card.grid_columnconfigure(1, weight=1)

            badge = ctk.CTkFrame(card, fg_color=finding["badge_bg"], corner_radius=6, width=140)
            badge.grid(row=0, column=0, padx=(10, 8), pady=10, sticky="ns")
            ctk.CTkLabel(
                badge,
                text=finding["category"],
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color=finding["color"],
                wraplength=120,
            ).pack(padx=8, pady=6)

            detail = ctk.CTkFrame(card, fg_color="transparent")
            detail.grid(row=0, column=1, sticky="ew", pady=8, padx=(0, 10))

            ctk.CTkLabel(
                detail,
                text=finding["description"],
                font=ctk.CTkFont(size=12),
                text_color="#D1D5DB",
                anchor="w",
            ).pack(anchor="w")

            match_str = "  |  ".join(f'"{m}"' for m in finding["matches"][:4])
            ctk.CTkLabel(
                detail,
                text=f"Matched: {match_str}",
                font=ctk.CTkFont(family="Courier New", size=11),
                text_color="#6B7280",
                anchor="w",
            ).pack(anchor="w")

            ctk.CTkLabel(
                card,
                text=f"+{finding['score']}",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=finding["color"],
            ).grid(row=0, column=2, padx=12)

    # ── Text Scanner ────────────────────────
    def _run_text_scan(self):
        text = self.sms_input.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Empty Input", "Please paste an SMS message first.")
            return
        result = scan_message(text)
        self.last_result = result
        SCAN_HISTORY.append(result)
        self._start_security_chat(text=text, result=result)

    def _clear_text(self):
        self.sms_input.delete("1.0", "end")
        self._reset_security_chat()

    def _send_latest_report(self):
        if self.last_result is None:
            messagebox.showwarning("No Report", "Run a scan first.")
            return
        recipient = self.recipient_var.get().strip()
        if not recipient or "@" not in recipient:
            messagebox.showwarning("Invalid Email", "Enter a valid recipient email.")
            return
        try:
            send_gmail_report(self.last_result, recipient)
            messagebox.showinfo("Sent", f"Report sent to {recipient}.")
        except Exception as exc:
            messagebox.showerror("Email Error", str(exc))

    # ── Export ───────────────────────────────
    def _export_report(self, text):
        if not text:
            messagebox.showwarning("Nothing to Export", "Run a scan first.")
            return
        result = scan_message(text)
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Report", "*.txt"), ("CSV", "*.csv")],
            initialfile=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        )
        if not path:
            return
        if path.endswith(".csv"):
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp", "Risk Level", "Score", "Category", "Description", "Matches"])
                for finding in result["findings"]:
                    w.writerow([
                        result["timestamp"], result["risk"], result["score"],
                        finding["category"], finding["description"],
                        "; ".join(finding["matches"]),
                    ])
        else:
            with open(path, "w") as f:
                f.write("SMS PHISHING DETECTOR — SCAN REPORT\n")
                f.write("=" * 50 + "\n")
                f.write(f"Timestamp : {result['timestamp']}\n")
                f.write(f"Risk Level: {result['risk']} (Score: {result['score']}/100)\n\n")
                f.write(f"Message Preview:\n{result['message_preview']}\n\n")
                f.write(f"Findings ({len(result['findings'])}):\n" + "-" * 40 + "\n")
                for i, finding in enumerate(result["findings"], 1):
                    f.write(f"{i}. [{finding['category']}] +{finding['score']} pts\n")
                    f.write(f"   {finding['description']}\n")
                    f.write(f"   Matched: {', '.join(finding['matches'])}\n\n")
        messagebox.showinfo("Exported", f"Report saved to:\n{path}")

    # ── Rules Tab ───────────────────────────
    def _build_rules_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        scroll = ctk.CTkScrollableFrame(parent, fg_color="#0D1B2A")
        scroll.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        scroll.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            scroll,
            text="Active Regex Rules",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#E5E7EB",
        ).pack(anchor="w", padx=8, pady=(8, 12))

        for rule in RULES:
            card = ctk.CTkFrame(scroll, fg_color="#111827", corner_radius=8)
            card.pack(fill="x", padx=4, pady=4)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(10, 2))

            ctk.CTkLabel(
                top,
                text=rule["category"],
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=rule["color"],
            ).pack(side="left")
            ctk.CTkLabel(
                top,
                text=f"Score weight: +{rule['score']}",
                font=ctk.CTkFont(size=11),
                text_color="#6B7280",
            ).pack(side="right")

            ctk.CTkLabel(
                card,
                text=rule["description"],
                font=ctk.CTkFont(size=11),
                text_color="#9CA3AF",
                anchor="w",
            ).pack(anchor="w", padx=12, pady=(0, 4))

            pattern_box = ctk.CTkTextbox(
                card,
                height=36,
                font=ctk.CTkFont(family="Courier New", size=10),
                fg_color="#0D1117",
                text_color="#00C48C",
                border_width=0,
            )
            pattern_box.pack(fill="x", padx=12, pady=(0, 10))
            pattern_box.insert("1.0", rule["pattern"])
            pattern_box.configure(state="disabled")

    # ── History Tab ─────────────────────────
    def _build_history_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)

        self.history_frame = ctk.CTkScrollableFrame(parent, fg_color="#0D1B2A")
        self.history_frame.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        self.history_frame.grid_columnconfigure(0, weight=1)
        self._refresh_history()

    def _refresh_history(self):
        for w in self.history_frame.winfo_children():
            w.destroy()

        ctk.CTkLabel(
            self.history_frame,
            text="Scan History",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#E5E7EB",
        ).pack(anchor="w", padx=8, pady=(8, 12))

        if not SCAN_HISTORY:
            ctk.CTkLabel(
                self.history_frame,
                text="No scans yet.",
                font=ctk.CTkFont(size=13),
                text_color="#374151",
            ).pack(pady=30)
            return

        for entry in reversed(SCAN_HISTORY):
            row = ctk.CTkFrame(
                self.history_frame,
                fg_color="#111827",
                border_color=entry["risk_color"],
                border_width=1,
                corner_radius=8,
            )
            row.pack(fill="x", padx=4, pady=3)

            ctk.CTkLabel(
                row,
                text=f"{entry.get('risk_icon', '')} {entry['risk']}",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=entry["risk_color"],
                width=120,
            ).pack(side="left", padx=12, pady=10)

            ctk.CTkLabel(
                row,
                text=entry["message_preview"],
                font=ctk.CTkFont(family="Courier New", size=10),
                text_color="#6B7280",
            ).pack(side="left", padx=8)

            ctk.CTkLabel(
                row,
                text=entry["timestamp"],
                font=ctk.CTkFont(size=10),
                text_color="#374151",
            ).pack(side="right", padx=12)

    def _reset_security_chat(self):
        self.chat_message_text = ""
        self.chat_result = None
        self.chat_questions = []
        self.chat_question_index = 0
        self.chat_answers = []
        self.chat_status.configure(
            text="The assistant will explain its analysis and ask follow-up questions here.",
            text_color="#9CA3AF",
        )
        self._clear_initial_read()
        self._render_chat_history()
        self._set_chat_answer_state("disabled")

    def _start_security_chat(self, text=None, result=None):
        if text is None:
            text = self.sms_input.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Empty Input", "Paste a message to review first.")
            return

        self.chat_message_text = text
        self.chat_result = result or scan_message(text)
        self.chat_answers = []
        self.chat_questions = self._build_chat_questions(text, self.chat_result)
        self.chat_question_index = 0

        self._render_initial_read(self.chat_result)
        self._render_chat_history()
        self._append_chat_message("user", text)
        self._append_chat_message(
            "assistant",
            self._build_chat_summary(self.chat_result),
        )

        if self.chat_questions:
            self._append_chat_message("assistant", self.chat_questions[0])
            self._set_chat_answer_state("normal")
            self.chat_status.configure(text="Review started. Answer the follow-up questions below.", text_color="#00C48C")
        else:
            self._append_chat_message(
                "assistant",
                "I do not need more context for this one. The current evidence is enough to classify it.",
            )
            self._append_chat_message("assistant", self._build_chat_final_assessment())
            self._set_chat_answer_state("disabled")
            self.chat_status.configure(text="Review complete.", text_color="#00C48C")

    def _clear_initial_read(self):
        for widget in self.initial_read_frame.winfo_children():
            widget.destroy()
        ctk.CTkLabel(
            self.initial_read_frame,
            text="Initial read will appear here after a review starts.",
            font=ctk.CTkFont(size=12),
            text_color="#374151",
            anchor="w",
        ).pack(anchor="w", padx=12, pady=12)

    def _render_initial_read(self, result: dict):
        for widget in self.initial_read_frame.winfo_children():
            widget.destroy()

        banner = ctk.CTkFrame(
            self.initial_read_frame,
            fg_color=result["risk_bg"],
            border_color=result["risk_color"],
            border_width=2,
            corner_radius=10,
        )
        banner.pack(fill="x", padx=4, pady=4)
        banner.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            banner,
            text=f"{result.get('risk_icon', '')}  {result['risk']}",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=result["risk_color"],
        ).grid(row=0, column=0, padx=18, pady=14, sticky="w")

        summary = self._build_chat_summary(result)
        ctk.CTkLabel(
            banner,
            text=summary,
            font=ctk.CTkFont(size=12),
            text_color="#E5E7EB",
            wraplength=650,
            justify="left",
            anchor="w",
        ).grid(row=0, column=1, padx=(0, 16), pady=14, sticky="w")

        ctk.CTkLabel(
            banner,
            text=f"Threat Score: {result['score']}/100",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=result["risk_color"],
        ).grid(row=0, column=2, padx=16, pady=14, sticky="e")

    def _handle_chat_answer(self, answer: str):
        if not self.chat_result or not self.chat_questions:
            messagebox.showinfo("Start Review", "Start a review first.")
            return

        current_question = self.chat_questions[self.chat_question_index]
        self.chat_answers.append({"question": current_question, "answer": answer})
        self._append_chat_message("user", answer.capitalize())

        self.chat_question_index += 1
        if self.chat_question_index < len(self.chat_questions):
            next_question = self.chat_questions[self.chat_question_index]
            self._append_chat_message("assistant", next_question)
            self.chat_status.configure(
                text=f"Question {self.chat_question_index + 1} of {len(self.chat_questions)}.",
                text_color="#00C48C",
            )
            return

        final_message = self._build_chat_final_assessment()
        self._append_chat_message("assistant", final_message)
        self._set_chat_answer_state("disabled")
        self.chat_status.configure(text="Review complete.", text_color="#00C48C")

    def _build_chat_questions(self, text: str, result: dict):
        questions = []
        lower_text = text.lower()
        hit_categories = {finding["category"] for finding in result["findings"]}

        if any(keyword in lower_text for keyword in ["otp", "password", "pin", "code"]):
            questions.append("Did the sender ask you to share an OTP, password, PIN, or verification code?")
        if any(keyword in lower_text for keyword in ["telegram", "whatsapp", "viber", "signal", "hr", "add"]):
            questions.append("Did the message push you to continue the conversation on Telegram, WhatsApp, or another external app?")
        if any(keyword in lower_text for keyword in ["link", "click", "download", "attachment", "file", "macros"]):
            questions.append("Did it ask you to click a link, download a file, open an attachment, or enable macros?")
        if any(keyword in lower_text for keyword in ["urgent", "immediately", "now", "locked", "suspended", "limited time", "within 24"]):
            questions.append("Did it use urgency or pressure to make you act immediately?")
        if any(keyword in lower_text for keyword in ["job", "hiring", "part-time", "earn", "salary", "income", "gcash", "maya", "crypto", "gift card"]):
            questions.append("Did it promise easy money, a job offer, payment, or an upfront fee?")

        if not questions:
            if result["score"] >= 30:
                questions.append("Did anything in the message feel unusual, urgent, or out of context for this sender?")
            else:
                questions.append("Do you know this sender, and were you expecting this message?")

        if "OTP / Verification Theft" in hit_categories or "Account Impersonation" in hit_categories:
            questions.append("Does the message mention logging in, verifying, or recovering an account you did not request?")

        seen = set()
        ordered_questions = []
        for question in questions:
            if question not in seen:
                seen.add(question)
                ordered_questions.append(question)
        return ordered_questions[:4]

    def _build_chat_summary(self, result: dict) -> str:
        if result["risk"] == "SAFE":
            return "Initial read: this looks safe, but I still want to confirm the sender and intent before I clear it."

        findings = ", ".join(finding["category"] for finding in result["findings"][:4])
        return (
            f"Initial read: {result['risk']} with score {result['score']}/100. "
            f"The strongest signals right now are {findings or 'no clear signals yet'}. "
            "I will ask a few context questions to confirm whether this is phishing, spam, or a legitimate message."
        )

    def _build_chat_final_assessment(self) -> str:
        yes_count = sum(1 for item in self.chat_answers if item["answer"] == "yes")
        unsure_count = sum(1 for item in self.chat_answers if item["answer"] == "unsure")

        if not self.chat_result:
            return "I do not have a message to assess yet."

        findings = ", ".join(finding["category"] for finding in self.chat_result["findings"][:4])

        if yes_count >= 2 or self.chat_result["score"] >= 60:
            verdict = "High confidence phishing or scam"
        elif yes_count == 1 or self.chat_result["score"] >= 30:
            verdict = "Likely scam or suspicious"
        elif unsure_count > 0:
            verdict = "Needs caution and a manual review"
        else:
            verdict = "Low risk, but still worth verifying the sender"

        return (
            f"Final assessment: {verdict}. Based on the message content and your answers, I would treat this as "
            f"unsafe unless the sender and request can be independently verified. Key rule hits: {findings or 'none'}."
        )

    def _render_chat_history(self):
        for widget in self.chat_history_frame.winfo_children():
            widget.destroy()

        ctk.CTkLabel(
            self.chat_history_frame,
            text="Conversation",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#E5E7EB",
        ).pack(anchor="w", padx=8, pady=(8, 12))

        if not self.chat_message_text:
            ctk.CTkLabel(
                self.chat_history_frame,
                text="The assistant will guide the review here.",
                font=ctk.CTkFont(size=13),
                text_color="#374151",
            ).pack(pady=30)
            return

    def _append_chat_message(self, role: str, text: str):
        bubble = ctk.CTkFrame(
            self.chat_history_frame,
            fg_color="#0D1117" if role == "assistant" else "#111827",
            border_color="#00C48C" if role == "assistant" else "#1F2937",
            border_width=1,
            corner_radius=10,
        )
        bubble.pack(fill="x", padx=6, pady=4)
        bubble.grid_columnconfigure(0, weight=1)

        label = "Security Assistant" if role == "assistant" else "You"
        ctk.CTkLabel(
            bubble,
            text=label,
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#00C48C" if role == "assistant" else "#9CA3AF",
        ).grid(row=0, column=0, sticky="w", padx=10, pady=(8, 2))

        ctk.CTkLabel(
            bubble,
            text=text,
            font=ctk.CTkFont(size=12),
            text_color="#E5E7EB",
            wraplength=760,
            justify="left",
            anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=10, pady=(0, 10))

    def _set_chat_answer_state(self, state: str):
        for button in (self.yes_button, self.no_button, self.unsure_button):
            button.configure(state=state)
