# ==========================================================
# LOG-BASED THREAT DETECTION SYSTEM (FINAL – ALL FEATURES)
# ==========================================================

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import ttkbootstrap as tb
from ttkbootstrap.widgets.scrolled import ScrolledText

import re, urllib.parse, html
from collections import OrderedDict
from datetime import datetime
import threading, time

# PDF
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# Dashboard
import matplotlib.pyplot as plt

# ==========================================================
# THREAT INTELLIGENCE (IOC)
# ==========================================================

KNOWN_MALICIOUS_IPS = {"1.2.3.4", "5.6.7.8", "8.8.8.8"}
KNOWN_ATTACK_TOOLS = ["sqlmap", "nikto", "nmap", "acunetix", "curl", "wget"]

# ==========================================================
# ATTACK PATTERNS
# ==========================================================

DEFAULT_PATTERNS = OrderedDict([
    ("Failed Login", r"\b(failed|unauthorized|invalid password|authentication failure|login failed)\b"),
    ("Credential Stuffing", r"(username=|login=|user=).{1,80}(password=|pass=)"),
    ("SQL Injection", r"(union\s+select|select\s+\*|drop\s+table|--|;--)"),
    ("SQLi Tautology", r"(\bor\b\s*1\s*=\s*1|'?\s*or\s*'?\s*1'?\s*=\s*'?\s*1)"),
    ("XSS", r"(<script|javascript:|onerror=|onload=)"),
    ("Directory Traversal", r"(\.\./|\.\.\\|%2e%2e)"),
    ("Command Injection", r"(\|\||;|&&|\bwget\b|\bcurl\b)"),
    ("Local File Inclusion", r"(/etc/passwd|/etc/shadow)"),
    ("SSRF", r"(127\.0\.0\.1|localhost|169\.254)"),
    ("Recon Probes", r"(/robots\.txt|/sitemap\.xml|/\.git)"),
    ("Admin Login Probe", r"(/admin|/administrator|/manager/html)"),
    ("Repeated 4xx/5xx", r"\b(401|403|404|500|502|503|504)\b"),
    ("Long Query / Exfiltration", r".{200,}"),
    ("Scanner / Automation", r"(sqlmap|nikto|nmap|acunetix|curl|wget)")
])

# ==========================================================
# AUTO-BLOCK CONFIG
# ==========================================================

BLOCK_THRESHOLD = 3
ip_counter = {}
blacklist = set()

# ==========================================================
# LOG PARSER
# ==========================================================

APACHE_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>.*?)\] "(?P<request>.*?)" (?P<status>\d{3})'
)

def parse_log_line(line):
    m = APACHE_PATTERN.search(line)
    if m:
        return m.group("time"), m.group("ip"), m.group("request"), m.group("status"), line
    return "-", "N/A", line[:80], "-", line

# ==========================================================
# NORMALIZATION
# ==========================================================

def normalize(text):
    return html.unescape(urllib.parse.unquote(text)).lower()

# ==========================================================
# DETECTION ENGINE
# ==========================================================

def detect(text, ip):
    hits = []
    norm = normalize(text)

    for name, pattern in DEFAULT_PATTERNS.items():
        if re.search(pattern, norm):
            hits.append(name)

    if ip in KNOWN_MALICIOUS_IPS:
        hits.append("KNOWN MALICIOUS IP (IOC)")

    for tool in KNOWN_ATTACK_TOOLS:
        if tool in norm:
            hits.append("KNOWN ATTACK TOOL (IOC)")
            break

    return list(set(hits))

def analyze_line(line):
    time_, ip, request, status, raw = parse_log_line(line)
    detections = detect(f"{request} {raw}", ip)

    if detections:
        ip_counter[ip] = ip_counter.get(ip, 0) + 1
        if ip_counter[ip] >= BLOCK_THRESHOLD:
            blacklist.add(ip)
            detections.append("AUTO-BLOCKED IP")

    return time_, ip, status, request, detections

# ==========================================================
# PDF REPORT
# ==========================================================

def generate_pdf():
    if not results:
        messagebox.showinfo("PDF", "No attacks detected")
        return

    fname = f"Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    c = canvas.Canvas(fname, pagesize=A4)
    y = 800

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Log-Based Threat Detection Report")
    y -= 40

    c.setFont("Helvetica", 10)
    for i, r in enumerate(results, 1):
        c.drawString(50, y, f"{i}. {r[0]} | {r[1]} | {', '.join(r[4])}")
        y -= 18
        if y < 60:
            c.showPage()
            y = 800

    c.save()
    messagebox.showinfo("PDF", f"Saved as {fname}")

# ==========================================================
# DASHBOARD
# ==========================================================

def show_dashboard():
    if not results:
        return
    stats = {}
    for r in results:
        for d in r[4]:
            stats[d] = stats.get(d, 0) + 1

    plt.bar(stats.keys(), stats.values())
    plt.xticks(rotation=45)
    plt.title("Attack Distribution")
    plt.tight_layout()
    plt.show()

# ==========================================================
# SHOW RULES
# ==========================================================

def show_rules():
    win = tk.Toplevel(app)
    win.title("Configured Rules")
    win.geometry("700x500")

    box = ScrolledText(win)
    box.pack(fill="both", expand=True)

    for n, p in DEFAULT_PATTERNS.items():
        box.insert(tk.END, f"{n}\n{p}\n\n")

# ==========================================================
# REAL-TIME MONITOR
# ==========================================================

def start_monitor():
    if not logfile:
        messagebox.showwarning("Monitor", "Select log file first")
        return

    def tail():
        with open(logfile, "r", errors="ignore") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    r = analyze_line(line)
                    if r[4]:
                        add_to_tables(r)
                        messagebox.showwarning("ALERT", f"{r[1]} ➜ {r[4]}")
                time.sleep(1)

    threading.Thread(target=tail, daemon=True).start()

# ==========================================================
# GUI HELPERS
# ==========================================================

results = []
logfile = None

def add_to_tables(r):
    severity = "critical" if "AUTO-BLOCKED IP" in r[4] else "alert"

    log_table.insert("", tk.END, values=r[:4], tags=(severity,))

    for d in r[4]:
        alerts_table.insert("", tk.END, values=(d, r[0], r[1], r[3][:60]))

def browse():
    global logfile, results
    logfile = filedialog.askopenfilename()
    if not logfile:
        return

    log_table.delete(*log_table.get_children())
    alerts_table.delete(*alerts_table.get_children())
    results.clear()

    with open(logfile, "r", errors="ignore") as f:
        for line in f:
            r = analyze_line(line)
            if r[4]:
                results.append(r)
                add_to_tables(r)

# ==========================================================
# MAIN WINDOW
# ==========================================================

app = tb.Window(themename="darkly")
app.title("Log-Based Threat Detection System")
app.geometry("1300x700")

tb.Label(app, text="Log-Based Threat Detection System",
         font=("Segoe UI", 18, "bold")).pack(pady=10)

btns = tb.Frame(app)
btns.pack()

tb.Button(btns, text="Browse Log File", command=browse).pack(side=tk.LEFT, padx=5)
tb.Button(btns, text="Show Rules", command=show_rules).pack(side=tk.LEFT, padx=5)
tb.Button(btns, text="Generate PDF", command=generate_pdf).pack(side=tk.LEFT, padx=5)
tb.Button(btns, text="Dashboard", command=show_dashboard).pack(side=tk.LEFT, padx=5)
tb.Button(btns, text="Start Real-Time Monitor", command=start_monitor).pack(side=tk.LEFT, padx=5)
tb.Button(btns, text="Exit", command=app.destroy).pack(side=tk.LEFT, padx=5)

panel = tb.Panedwindow(app, orient=tk.HORIZONTAL)
panel.pack(fill="both", expand=True, padx=10, pady=10)

left = tb.Frame(panel)
panel.add(left, weight=3)

cols = ("Time", "IP", "Status", "Request")
log_table = ttk.Treeview(left, columns=cols, show="headings")

for c in cols:
    log_table.heading(c, text=c)
    log_table.column(c, width=220)

log_table.tag_configure("alert", background="#7a1f1f", foreground="white")
log_table.tag_configure("critical", background="#4a0f0f", foreground="white")

log_table.pack(fill="both", expand=True)

right = tb.Labelframe(panel, text="Alerts Panel")
panel.add(right, weight=1)

alert_cols = ("Rule", "Time", "IP", "Snippet")
alerts_table = ttk.Treeview(right, columns=alert_cols, show="headings")

for c in alert_cols:
    alerts_table.heading(c, text=c)
    alerts_table.column(c, width=150)

alerts_table.column("Snippet", width=300)
alerts_table.pack(fill="both", expand=True)

app.mainloop()
