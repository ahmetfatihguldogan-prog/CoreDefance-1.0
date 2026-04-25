import os
import queue
import threading
import tkinter as tk
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable


APP_TITLE = CoreDefence Security
APP_SUBTITLE = Intelligent File Scanning Center
DAX_SUPPORT = DAX Support Account    support.dax@coredefence.security
DEFAULT_START_PATH = rCUsers
DEFAULT_BLACKLIST_PATH = blacklist_hashes.txt
SUSPICIOUS_EXTENSIONS = {.exe, .bat, .js, .dll}
HIDDEN_ATTRIBUTE = 0x2
SYSTEM_ATTRIBUTE = 0x4
CHUNK_SIZE = 65536

BG = #eef3f8
PANEL = #fbfdff
INK = #102033
MUTED = #5f7388
ACCENT = #0b6efd
ACCENT_SOFT = #d9e8ff
SUCCESS = #1f9d61
WARNING = #c27a00
DANGER = #c13c55
BORDER = #d7e1eb


@dataclass
class ScanResult
    path str
    status str
    reasons list[str] = field(default_factory=list)
    sha256 str  None = None
    severity str = clean
    visible_in_report bool = True


@dataclass
class ScanSummary
    scanned_files int = 0
    suspicious_files int = 0
    infected_files int = 0
    skipped_files int = 0
    quiet_suspicious_files int = 0
    results list[ScanResult] = field(default_factory=list)


def load_blacklist(blacklist_path str) - set[str]
    path = Path(blacklist_path)
    if not path.exists()
        return set()

    hashes set[str] = set()
    with path.open(r, encoding=utf-8) as handle
        for raw_line in handle
            line = raw_line.strip().lower()
            if not line or line.startswith(#)
                continue
            hashes.add(line)
    return hashes


def iter_files(start_path str)
    for root, dirs, files in os.walk(start_path, topdown=True, onerror=None)
        dirs[] = [name for name in dirs if not os.path.islink(os.path.join(root, name))]
        for file_name in files
            yield os.path.join(root, file_name)


def compute_sha256(file_path str) - str
    digest = hashlib.sha256()
    with open(file_path, rb) as handle
        while chunk = handle.read(CHUNK_SIZE)
            digest.update(chunk)
    return digest.hexdigest()


def get_windows_attributes(file_path str) - int
    try
        return os.stat(file_path).st_file_attributes
    except (AttributeError, OSError)
        return 0


def analyze_file(file_path str, blacklist_hashes set[str]) - ScanResult  None
    reasons list[str] = []
    normalized_path = file_path.lower()
    extension = Path(file_path).suffix.lower()

    extension_flag = extension in SUSPICIOUS_EXTENSIONS
    appdata_flag = appdata in normalized_path
    attributes = get_windows_attributes(file_path)
    hidden_flag = bool(attributes & HIDDEN_ATTRIBUTE)
    system_flag = bool(attributes & SYSTEM_ATTRIBUTE)

    if extension_flag
        reasons.append(fsuspicious extension {extension})
    if appdata_flag
        reasons.append(located inside AppData)
    if hidden_flag
        reasons.append(hidden filefolder)
    if system_flag
        reasons.append(system filefolder)

    try
        sha256_hash = compute_sha256(file_path)
    except (PermissionError, OSError)
        return None

    if sha256_hash in blacklist_hashes
        return ScanResult(
            path=file_path,
            status=VIRUS FOUND,
            reasons=reasons or [blacklist match],
            sha256=sha256_hash,
            severity=critical,
            visible_in_report=True,
        )

    if reasons
        only_appdata = appdata_flag and not any((extension_flag, hidden_flag, system_flag))
        return ScanResult(
            path=file_path,
            status=SUSPICIOUS,
            reasons=reasons,
            sha256=sha256_hash,
            severity=info if only_appdata else warning,
            visible_in_report=not only_appdata,
        )

    return ScanResult(
        path=file_path,
        status=CLEAN,
        sha256=sha256_hash,
        severity=clean,
        visible_in_report=False,
    )


def run_scan(
    start_path str,
    blacklist_path str,
    show_clean bool = False,
    include_low_priority bool = False,
    progress_callback Callable[[str, int], None]  None = None,
    result_callback Callable[[ScanResult], None]  None = None,
) - ScanSummary
    blacklist_hashes = load_blacklist(blacklist_path)
    summary = ScanSummary()

    for file_path in iter_files(start_path)
        if progress_callback
            progress_callback(file_path, summary.scanned_files)

        result = analyze_file(file_path, blacklist_hashes)
        if result is None
            summary.skipped_files += 1
            continue

        summary.scanned_files += 1

        if result.status == VIRUS FOUND
            summary.infected_files += 1
            summary.results.append(result)
            if result_callback
                result_callback(result)
            continue

        if result.status == SUSPICIOUS
            summary.suspicious_files += 1
            if result.visible_in_report or include_low_priority
                summary.results.append(result)
                if result_callback
                    result_callback(result)
            else
                summary.quiet_suspicious_files += 1
            continue

        if show_clean
            summary.results.append(result)
            if result_callback
                result_callback(result)

    return summary


class CoreDefenceApp
    def __init__(self, root tk.Tk) - None
        self.root = root
        self.root.title(f{APP_TITLE} - File Scanning Engine)
        self.root.geometry(1380x860)
        self.root.minsize(1180, 760)
        self.root.configure(bg=BG)

        self.blacklist_path = str(Path(DEFAULT_BLACKLIST_PATH).resolve())
        self.selected_path = tk.StringVar(value=self._default_target())
        self.status_text = tk.StringVar(value=Ready to scan)
        self.scan_target_text = tk.StringVar(value=self.selected_path.get())
        self.progress_text = tk.StringVar(value=Ready)
        self.support_text = tk.StringVar(value=DAX_SUPPORT)
        self.low_priority_var = tk.BooleanVar(value=False)

        self.result_queue queue.Queue = queue.Queue()
        self.scan_thread threading.Thread  None = None
        self.is_scanning = False
        self.summary ScanSummary  None = None

        self._configure_style()
        self._build_layout()
        self._populate_drive_buttons()
        self.root.after(150, self._drain_queue)

    def _default_target(self) - str
        home = Path.home()
        return str(home) if home.exists() else C

    def _configure_style(self) - None
        style = ttk.Style()
        style.theme_use(clam)
        style.configure(TFrame, background=BG)
        style.configure(Panel.TFrame, background=PANEL, relief=flat)
        style.configure(Hero.TFrame, background=INK)
        style.configure(Title.TLabel, background=INK, foreground=white, font=(Segoe UI Semibold, 28))
        style.configure(Subtitle.TLabel, background=INK, foreground=#cfd9e7, font=(Segoe UI, 11))
        style.configure(Section.TLabel, background=PANEL, foreground=INK, font=(Segoe UI Semibold, 13))
        style.configure(Body.TLabel, background=PANEL, foreground=MUTED, font=(Segoe UI, 10))
        style.configure(StatValue.TLabel, background=PANEL, foreground=INK, font=(Segoe UI Semibold, 24))
        style.configure(StatCaption.TLabel, background=PANEL, foreground=MUTED, font=(Segoe UI, 10))
        style.configure(Accent.TButton, font=(Segoe UI Semibold, 10), padding=(14, 10))
        style.map(Accent.TButton, background=[(active, #0957c3), (!disabled, ACCENT)], foreground=[(!disabled, white)])
        style.configure(Ghost.TButton, font=(Segoe UI, 10), padding=(12, 9), background=PANEL)
        style.configure(TCheckbutton, background=PANEL, foreground=INK, font=(Segoe UI, 10))
        style.configure(TEntry, fieldbackground=white, padding=8)
        style.configure(Horizontal.TProgressbar, troughcolor=#dfe8f1, background=ACCENT, bordercolor=#dfe8f1, lightcolor=ACCENT, darkcolor=ACCENT)

    def _build_layout(self) - None
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(fill=both, expand=True, padx=24, pady=24)
        outer.grid_columnconfigure(0, weight=3)
        outer.grid_columnconfigure(1, weight=2)
        outer.grid_rowconfigure(1, weight=1)

        hero = tk.Frame(outer, bg=INK, bd=0, highlightthickness=0)
        hero.grid(row=0, column=0, columnspan=2, sticky=nsew, pady=(0, 18))
        hero.grid_columnconfigure(0, weight=1)
        hero.grid_columnconfigure(1, weight=0)

        ttk.Label(hero, text=APP_TITLE, style=Title.TLabel).grid(row=0, column=0, sticky=w, padx=28, pady=(22, 4))
        ttk.Label(hero, text=APP_SUBTITLE, style=Subtitle.TLabel).grid(row=1, column=0, sticky=w, padx=28)
        ttk.Label(
            hero,
            text=A calm, controlled scanning experience that keeps the user in charge,
            style=Subtitle.TLabel,
        ).grid(row=2, column=0, sticky=w, padx=28, pady=(4, 22))

        support_badge = tk.Label(
            hero,
            textvariable=self.support_text,
            bg=#16304d,
            fg=#dbe9ff,
            font=(Segoe UI Semibold, 10),
            padx=16,
            pady=10,
        )
        support_badge.grid(row=0, column=1, rowspan=3, sticky=e, padx=28)

        left = tk.Frame(outer, bg=BG)
        left.grid(row=1, column=0, sticky=nsew, padx=(0, 10))
        left.grid_rowconfigure(2, weight=1)
        left.grid_columnconfigure(0, weight=1)

        right = tk.Frame(outer, bg=BG)
        right.grid(row=1, column=1, sticky=nsew, padx=(10, 0))
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        self._build_control_panel(left)
        self._build_stats_panel(left)
        self._build_results_panel(left)
        self._build_side_panel(right)

    def _build_control_panel(self, parent tk.Widget) - None
        panel = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        panel.grid(row=0, column=0, sticky=ew, pady=(0, 14))
        panel.grid_columnconfigure(1, weight=1)

        ttk.Label(panel, text=Scan Control, style=Section.TLabel).grid(row=0, column=0, columnspan=3, sticky=w, padx=20, pady=(18, 4))
        ttk.Label(
            panel,
            text=Choose the drive or folder yourself. The system scans only the target you select.,
            style=Body.TLabel,
        ).grid(row=1, column=0, columnspan=3, sticky=w, padx=20, pady=(0, 16))

        target_entry = ttk.Entry(panel, textvariable=self.selected_path)
        target_entry.grid(row=2, column=0, columnspan=2, sticky=ew, padx=(20, 10), pady=(0, 12))
        ttk.Button(panel, text=Choose Folder, command=self.choose_folder, style=Ghost.TButton).grid(row=2, column=2, sticky=ew, padx=(0, 20), pady=(0, 12))

        drives_wrap = tk.Frame(panel, bg=PANEL)
        drives_wrap.grid(row=3, column=0, columnspan=3, sticky=ew, padx=20, pady=(0, 12))
        drives_wrap.grid_columnconfigure(0, weight=1)
        ttk.Label(drives_wrap, text=Quick Targets, style=Body.TLabel).grid(row=0, column=0, sticky=w)
        self.drive_buttons_frame = tk.Frame(drives_wrap, bg=PANEL)
        self.drive_buttons_frame.grid(row=1, column=0, sticky=w, pady=(8, 0))

        ttk.Checkbutton(
            panel,
            text=Show low-priority AppData entries too,
            variable=self.low_priority_var,
        ).grid(row=4, column=0, columnspan=2, sticky=w, padx=20, pady=(0, 16))

        actions = tk.Frame(panel, bg=PANEL)
        actions.grid(row=4, column=2, sticky=e, padx=20, pady=(0, 16))
        ttk.Button(actions, text=Start Scan, command=self.start_scan, style=Accent.TButton).pack(side=left)

    def _build_stats_panel(self, parent tk.Widget) - None
        wrap = tk.Frame(parent, bg=BG)
        wrap.grid(row=1, column=0, sticky=ew, pady=(0, 14))
        for column in range(4)
            wrap.grid_columnconfigure(column, weight=1)

        self.stat_vars = {
            scanned tk.StringVar(value=0),
            suspicious tk.StringVar(value=0),
            infected tk.StringVar(value=0),
            skipped tk.StringVar(value=0),
        }

        items = [
            (Scanned, scanned),
            (Suspicious, suspicious),
            (Infected, infected),
            (Skipped, skipped),
        ]

        for index, (label, key) in enumerate(items)
            card = tk.Frame(wrap, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
            card.grid(row=0, column=index, sticky=nsew, padx=(0 if index == 0 else 6, 0 if index == 3 else 6))
            ttk.Label(card, textvariable=self.stat_vars[key], style=StatValue.TLabel).pack(anchor=w, padx=18, pady=(16, 2))
            ttk.Label(card, text=label, style=StatCaption.TLabel).pack(anchor=w, padx=18, pady=(0, 14))

    def _build_results_panel(self, parent tk.Widget) - None
        panel = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        panel.grid(row=2, column=0, sticky=nsew)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(3, weight=1)

        ttk.Label(panel, text=Live Findings, style=Section.TLabel).grid(row=0, column=0, sticky=w, padx=20, pady=(18, 4))
        ttk.Label(
            panel,
            text=Only meaningful findings are listed. Low-signal AppData entries are summarized.,
            style=Body.TLabel,
        ).grid(row=1, column=0, sticky=w, padx=20, pady=(0, 12))

        self.progress = ttk.Progressbar(panel, mode=indeterminate)
        self.progress.grid(row=2, column=0, sticky=ew, padx=20, pady=(0, 8))

        self.results_box = tk.Text(
            panel,
            wrap=word,
            bg=white,
            fg=INK,
            relief=flat,
            font=(Consolas, 10),
            padx=14,
            pady=14,
            insertbackground=INK,
        )
        self.results_box.grid(row=3, column=0, sticky=nsew, padx=20, pady=(0, 10))
        self.results_box.tag_configure(critical, foreground=DANGER)
        self.results_box.tag_configure(warning, foreground=WARNING)
        self.results_box.tag_configure(clean, foreground=MUTED)

        footer = tk.Frame(panel, bg=PANEL)
        footer.grid(row=4, column=0, sticky=ew, padx=20, pady=(0, 18))
        footer.grid_columnconfigure(0, weight=1)
        ttk.Label(footer, textvariable=self.progress_text, style=Body.TLabel).grid(row=0, column=0, sticky=w)
        ttk.Label(footer, textvariable=self.status_text, style=Body.TLabel).grid(row=0, column=1, sticky=e)

    def _build_side_panel(self, parent tk.Widget) - None
        summary_panel = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        summary_panel.grid(row=0, column=0, sticky=ew, pady=(0, 14))
        summary_panel.grid_columnconfigure(0, weight=1)

        ttk.Label(summary_panel, text=Operation Summary, style=Section.TLabel).grid(row=0, column=0, sticky=w, padx=20, pady=(18, 4))
        self.target_label = ttk.Label(summary_panel, textvariable=self.scan_target_text, style=Body.TLabel)
        self.target_label.grid(row=1, column=0, sticky=w, padx=20, pady=(0, 8))

        self.summary_box = tk.Text(
            summary_panel,
            wrap=word,
            height=10,
            bg=ACCENT_SOFT,
            fg=INK,
            relief=flat,
            font=(Segoe UI, 10),
            padx=14,
            pady=14,
        )
        self.summary_box.grid(row=2, column=0, sticky=ew, padx=20, pady=(0, 18))
        self.summary_box.insert(1.0, The post-scan summary will appear here.)
        self.summary_box.configure(state=disabled)

        support_panel = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        support_panel.grid(row=1, column=0, sticky=nsew)
        support_panel.grid_columnconfigure(0, weight=1)
        support_panel.grid_rowconfigure(2, weight=1)

        ttk.Label(support_panel, text=DAX Support, style=Section.TLabel).grid(row=0, column=0, sticky=w, padx=20, pady=(18, 4))
        ttk.Label(
            support_panel,
            text=A dedicated support area that reinforces trust and creates a clear enterprise contact point.,
            style=Body.TLabel,
        ).grid(row=1, column=0, sticky=w, padx=20, pady=(0, 12))

        dax_card = tk.Frame(support_panel, bg=#f3f8ff, highlightbackground=#bfd2f0, highlightthickness=1)
        dax_card.grid(row=2, column=0, sticky=nsew, padx=20, pady=(0, 20))
        dax_card.grid_columnconfigure(0, weight=1)

        tk.Label(dax_card, text=DAX, bg=#f3f8ff, fg=ACCENT, font=(Segoe UI Semibold, 26)).grid(row=0, column=0, sticky=w, padx=18, pady=(18, 2))
        tk.Label(dax_card, text=CoreDefence Security Support Channel, bg=#f3f8ff, fg=INK, font=(Segoe UI Semibold, 11)).grid(row=1, column=0, sticky=w, padx=18)
        tk.Label(
            dax_card,
            text=support.dax@coredefence.securitynPriority Enterprise technical support and scan guidance,
            bg=#f3f8ff,
            fg=MUTED,
            justify=left,
            font=(Segoe UI, 10),
        ).grid(row=2, column=0, sticky=w, padx=18, pady=(6, 18))

    def _populate_drive_buttons(self) - None
        for child in self.drive_buttons_frame.winfo_children()
            child.destroy()

        for drive in self._list_drives()
            button = tk.Button(
                self.drive_buttons_frame,
                text=drive,
                command=lambda path=drive self.selected_path.set(path),
                bg=#ffffff,
                fg=INK,
                activebackground=ACCENT_SOFT,
                activeforeground=INK,
                bd=0,
                padx=14,
                pady=8,
                font=(Segoe UI Semibold, 10),
                highlightbackground=BORDER,
                highlightthickness=1,
            )
            button.pack(side=left, padx=(0, 8))

    def _list_drives(self) - list[str]
        drives = []
        for letter in ABCDEFGHIJKLMNOPQRSTUVWXYZ
            drive = f{letter}
            if os.path.exists(drive)
                drives.append(drive)
        return drives or [C]

    def choose_folder(self) - None
        selected = filedialog.askdirectory(title=Choose the folder to scan)
        if selected
            self.selected_path.set(selected)

    def start_scan(self) - None
        if self.is_scanning
            messagebox.showinfo(Scan in progress, Please wait for the current scan to finish.)
            return

        target = self.selected_path.get().strip()
        if not target or not os.path.exists(target)
            messagebox.showerror(Invalid target, Please choose an existing drive or folder.)
            return

        self.is_scanning = True
        self.summary = None
        self.scan_target_text.set(target)
        self.status_text.set(Scan running)
        self.progress_text.set(Analyzing files...)
        self._reset_output()
        self.progress.start(12)

        self.scan_thread = threading.Thread(target=self._scan_worker, args=(target,), daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, target str) - None
        def on_progress(path str, scanned int) - None
            self.result_queue.put((progress, path, scanned))

        def on_result(result ScanResult) - None
            self.result_queue.put((result, result))

        try
            summary = run_scan(
                start_path=target,
                blacklist_path=self.blacklist_path,
                include_low_priority=self.low_priority_var.get(),
                progress_callback=on_progress,
                result_callback=on_result,
            )
        except Exception as exc
            self.result_queue.put((error, str(exc)))
            return

        self.result_queue.put((done, summary))

    def _drain_queue(self) - None
        while True
            try
                item = self.result_queue.get_nowait()
            except queue.Empty
                break

            event = item[0]
            if event == progress
                _, path, scanned = item
                self.progress_text.set(fScanned {scanned}  Latest file {path})
            elif event == result
                _, result = item
                self._append_result(result)
            elif event == done
                _, summary = item
                self._finish_scan(summary)
            elif event == error
                _, error_message = item
                self._finish_error(error_message)

        self.root.after(150, self._drain_queue)

    def _append_result(self, result ScanResult) - None
        self.results_box.configure(state=normal)
        reasons = , .join(result.reasons) if result.reasons else -
        line = f[{result.status}] {result.path}nSHA256 {result.sha256}nReason {reasons}nn
        tag = critical if result.severity == critical else warning
        self.results_box.insert(end, line, tag)
        self.results_box.see(end)
        self.results_box.configure(state=disabled)

    def _finish_scan(self, summary ScanSummary) - None
        self.is_scanning = False
        self.summary = summary
        self.progress.stop()
        self.status_text.set(Scan completed)
        self.progress_text.set(Scan finished)
        self.stat_vars[scanned].set(str(summary.scanned_files))
        self.stat_vars[suspicious].set(str(summary.suspicious_files))
        self.stat_vars[infected].set(str(summary.infected_files))
        self.stat_vars[skipped].set(str(summary.skipped_files))

        if not summary.results
            self.results_box.configure(state=normal)
            self.results_box.insert(
                end,
                No visible critical or high-priority suspicious findings were detected.n,
                clean,
            )
            self.results_box.configure(state=disabled)

        summary_text = (
            fSelected target {self.scan_target_text.get()}n
            fScanned files {summary.scanned_files}n
            fSuspicious files {summary.suspicious_files}n
            fInfected files {summary.infected_files}n
            fSkipped files {summary.skipped_files}n
            fSummarized low-priority AppData entries {summary.quiet_suspicious_files}n
            Note Only meaningful suspicious findings and signature matches are shown in the main list.
        )
        self.summary_box.configure(state=normal)
        self.summary_box.delete(1.0, end)
        self.summary_box.insert(1.0, summary_text)
        self.summary_box.configure(state=disabled)

    def _finish_error(self, error_message str) - None
        self.is_scanning = False
        self.progress.stop()
        self.status_text.set(Scan stopped with an error)
        self.progress_text.set(The operation could not be completed)
        messagebox.showerror(Scan error, error_message)

    def _reset_output(self) - None
        for key in self.stat_vars
            self.stat_vars[key].set(0)

        self.results_box.configure(state=normal)
        self.results_box.delete(1.0, end)
        self.results_box.configure(state=disabled)

        self.summary_box.configure(state=normal)
        self.summary_box.delete(1.0, end)
        self.summary_box.insert(1.0, Scan is running. Findings will be summarized here as they complete.)
        self.summary_box.configure(state=disabled)


def main() - None
    root = tk.Tk()
    app = CoreDefenceApp(root)
    root.mainloop()


if __name__ == __main__
    main()
