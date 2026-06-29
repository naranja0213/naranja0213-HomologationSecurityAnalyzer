"""Tkinter GUI for Homologation Security Analyzer."""

from __future__ import annotations

import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from config import APP_NAME, DEFAULT_VT_DELAY_SECONDS, VT_API_KEY_ENV
from scanner import AnalysisResult, analyze_source


class HomologationSecurityAnalyzerApp(tk.Tk):
    """Desktop UI for choosing a package/folder and running the analysis."""

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("760x460")
        self.minsize(720, 430)

        self.source_path = tk.StringVar()
        self.api_key = tk.StringVar(value=os.environ.get(VT_API_KEY_ENV, ""))
        self.vt_delay = tk.IntVar(value=DEFAULT_VT_DELAY_SECONDS)
        self.status = tk.StringVar(value="Ready")
        self.report_path = tk.StringVar(value="")
        self.progress_value = tk.DoubleVar(value=0.0)

        self._worker: threading.Thread | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        main = ttk.Frame(self, padding=18)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(1, weight=1)

        ttk.Label(main, text=APP_NAME, font=("Segoe UI", 18, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 18)
        )

        ttk.Label(main, text="Source").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(main, textvariable=self.source_path).grid(row=1, column=1, sticky="ew", padx=8)
        source_buttons = ttk.Frame(main)
        source_buttons.grid(row=1, column=2, sticky="e")
        ttk.Button(source_buttons, text="ZIP", command=self._select_zip).grid(row=0, column=0, padx=(0, 4))
        ttk.Button(source_buttons, text="Folder", command=self._select_folder).grid(row=0, column=1)

        ttk.Label(main, text="VirusTotal API Key").grid(row=2, column=0, sticky="w", pady=6)
        ttk.Entry(main, textvariable=self.api_key, show="*").grid(
            row=2, column=1, columnspan=2, sticky="ew", padx=(8, 0)
        )

        ttk.Label(main, text="VT delay seconds").grid(row=3, column=0, sticky="w", pady=6)
        delay_box = ttk.Spinbox(main, from_=0, to=3600, textvariable=self.vt_delay, width=8)
        delay_box.grid(row=3, column=1, sticky="w", padx=8)

        self.start_button = ttk.Button(main, text="Start Analysis", command=self._start_analysis)
        self.start_button.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(18, 10))

        self.progress = ttk.Progressbar(
            main, variable=self.progress_value, maximum=100, mode="determinate"
        )
        self.progress.grid(row=5, column=0, columnspan=3, sticky="ew", pady=8)

        ttk.Label(main, textvariable=self.status).grid(row=6, column=0, columnspan=3, sticky="w")

        report_frame = ttk.LabelFrame(main, text="Output", padding=12)
        report_frame.grid(row=7, column=0, columnspan=3, sticky="nsew", pady=(18, 0))
        report_frame.columnconfigure(0, weight=1)
        ttk.Entry(report_frame, textvariable=self.report_path, state="readonly").grid(
            row=0, column=0, sticky="ew", padx=(0, 8)
        )
        ttk.Button(report_frame, text="Copy Path", command=self._copy_report_path).grid(row=0, column=1)

        tips = (
            "The tool queries VirusTotal by SHA256 only. Files are never uploaded. "
            "If no API key is provided, VirusTotal fields are skipped."
        )
        ttk.Label(main, text=tips, wraplength=700, foreground="#555555").grid(
            row=8, column=0, columnspan=3, sticky="w", pady=(16, 0)
        )

    def _select_zip(self) -> None:
        path = filedialog.askopenfilename(
            title="Select ZIP file",
            filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")],
        )
        if path:
            self.source_path.set(path)

    def _select_folder(self) -> None:
        path = filedialog.askdirectory(title="Select folder")
        if path:
            self.source_path.set(path)

    def _start_analysis(self) -> None:
        source = self.source_path.get().strip()
        if not source:
            messagebox.showwarning(APP_NAME, "Please select a ZIP file or folder.")
            return
        if not Path(source).exists():
            messagebox.showerror(APP_NAME, "The selected source path does not exist.")
            return
        if self._worker and self._worker.is_alive():
            return

        self.start_button.configure(state="disabled")
        self.progress_value.set(0)
        self.report_path.set("")
        self.status.set("Starting analysis...")

        self._worker = threading.Thread(target=self._run_analysis, daemon=True)
        self._worker.start()

    def _run_analysis(self) -> None:
        try:
            result = analyze_source(
                self.source_path.get().strip(),
                vt_api_key=self.api_key.get().strip(),
                vt_delay_seconds=int(self.vt_delay.get()),
                progress_callback=self._on_progress,
            )
            self.after(0, lambda: self._analysis_done(result))
        except Exception as exc:
            self.after(0, lambda: self._analysis_failed(exc))

    def _on_progress(self, current: int, total: int, message: str) -> None:
        percent = 0 if total <= 0 else min(100, max(0, (current / total) * 100))
        self.after(0, lambda: self._update_progress(percent, message))

    def _update_progress(self, percent: float, message: str) -> None:
        self.progress_value.set(percent)
        self.status.set(message)

    def _analysis_done(self, result: AnalysisResult) -> None:
        self.start_button.configure(state="normal")
        self.progress_value.set(100)
        self.report_path.set(str(result.report_path))
        self.status.set(
            f"Completed. Files: {result.total_files}, target files: {result.target_files}"
        )
        messagebox.showinfo(APP_NAME, f"Analysis completed.\n\nReport:\n{result.report_path}")

    def _analysis_failed(self, exc: Exception) -> None:
        self.start_button.configure(state="normal")
        self.status.set("Analysis failed")
        messagebox.showerror(APP_NAME, f"Analysis failed:\n{exc}")

    def _copy_report_path(self) -> None:
        value = self.report_path.get()
        if value:
            self.clipboard_clear()
            self.clipboard_append(value)
            self.status.set("Report path copied to clipboard")


def run_app() -> None:
    app = HomologationSecurityAnalyzerApp()
    app.mainloop()

