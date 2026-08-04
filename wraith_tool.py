import os
import sys
import time
import ipaddress
import socket
import html
from concurrent.futures import ThreadPoolExecutor, as_completed

# Avoid a PyQt5/ibus startup warning caused by QSocketNotifier initialization.
# This must override the desktop environment, not merely provide a default.
os.environ["QT_IM_MODULE"] = ""

from PyQt5.QtCore import Qt, QTimer, QRectF, QObject, QThread, pyqtSignal
from PyQt5.QtGui import (
    QFont, QIcon, QPixmap, QPainter, QColor, QLinearGradient, QRadialGradient,
    QPainterPath, QFontMetrics, QKeySequence,
)
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QHBoxLayout, QSizePolicy, QMessageBox, QFrame, QProgressBar,
    QTextBrowser, QScrollArea, QShortcut, QGraphicsDropShadowEffect,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(SCRIPT_DIR, "assets")

CYAN = QColor(79, 216, 255)
PURPLE = QColor(179, 136, 255)
PURPLE_DEEP = QColor(124, 77, 255)
GREEN = QColor(57, 255, 136)
AMBER = QColor(255, 196, 74)
DIM = QColor(140, 130, 160)
WHITE = QColor(232, 230, 240)
BRIGHT = QColor(255, 255, 255)
PANEL_BG = QColor(18, 12, 32)
PANEL_BORDER = QColor(86, 62, 130)

# design space (trimmed from the video's 1080x1920 canvas — that extra bottom
# margin existed for YouTube's mobile UI safe zone, which doesn't apply here)
DW, DH = 1080, 1480
PANEL_LEFT, PANEL_TOP, PANEL_RIGHT, PANEL_BOTTOM = 46, 460, 1034, 1430
TITLEBAR_H = 58
LOG_TOP = PANEL_TOP + TITLEBAR_H + 26
LOG_BOTTOM = PANEL_BOTTOM - 20
LOG_LEFT = PANEL_LEFT + 34
LINE_H = 47
FADE_DUR = 0.22
STATS_T0 = 11.5
CTA_T0 = 12.6
STATS = [("3", "HOSTS UP"), ("4", "PORTS OPEN"), ("1", "FLAGGED")]
STAT_COLORS = [GREEN, CYAN, AMBER]


def build_entries(tool_name, target):
    network = ipaddress.ip_network(target, strict=False)
    hosts = [str(host) for _, host in zip(range(4), network.hosts())]
    if len(hosts) < 4:
        raise ValueError("target network must contain at least four usable hosts")
    shift = 0.4
    return [
        {"type": "command", "prompt": "$ ", "cmd": "python3 wraith_tool.py", "t0": 0.3, "t1": 1.5},
        {"type": "text", "text": f"[INIT] Loading {tool_name} Scanner v2.1...", "color": WHITE, "t0": 1.4 + shift},
        {"type": "text", "text": "[INIT] Modules: tcp_probe, banner_grab, cve_check", "color": CYAN,
         "t0": 1.8 + shift},
        {"type": "text", "text": f"[SCAN] Parsed target: {target} (local lab)", "color": WHITE, "t0": 2.3 + shift},
        {"type": "progress", "label": "Sweeping hosts", "color": CYAN, "t0": 2.8 + shift, "t1": 3.6 + shift},
        {"type": "text", "text": f"[SCAN] Host {hosts[0]} -> UP", "color": GREEN, "t0": 3.9 + shift},
        {"type": "text", "text": f"[SCAN] Host {hosts[1]} -> UP", "color": GREEN, "t0": 4.15 + shift},
        {"type": "text", "text": f"[SCAN] Host {hosts[2]} -> UP", "color": GREEN, "t0": 4.4 + shift},
        {"type": "text", "text": f"[SCAN] Host {hosts[3]} -> DOWN", "color": DIM, "t0": 4.7 + shift},
        {"type": "text", "text": f"[PORT] {hosts[0]}:22  -> OPEN (ssh)", "color": CYAN, "t0": 5.2 + shift},
        {"type": "text", "text": f"[PORT] {hosts[0]}:80  -> OPEN (http)", "color": CYAN, "t0": 5.45 + shift},
        {"type": "text", "text": f"[PORT] {hosts[1]}:443 -> OPEN (https)", "color": CYAN, "t0": 5.7 + shift},
        {"type": "text", "text": f"[PORT] {hosts[2]}:3306 -> OPEN (mysql)", "color": CYAN, "t0": 5.95 + shift},
        {"type": "text", "text": "[PHASE 2] Grabbing service banners...", "color": PURPLE, "t0": 6.4 + shift},
        {"type": "progress", "label": "Fingerprinting", "color": PURPLE, "t0": 6.7 + shift, "t1": 7.2 + shift},
        {"type": "text", "text": "[BANNER] 22/tcp  -> OpenSSH 9.6", "color": WHITE, "t0": 7.5 + shift},
        {"type": "text", "text": "[BANNER] 80/tcp  -> nginx 1.25.3", "color": WHITE, "t0": 7.75 + shift},
        {"type": "text", "text": "[BANNER] 443/tcp -> nginx 1.25.3 (TLS)", "color": WHITE, "t0": 8.0 + shift},
        {"type": "text", "text": "[BANNER] 3306/tcp -> MySQL 8.0.36", "color": WHITE, "t0": 8.25 + shift},
        {"type": "text", "text": "[PHASE 3] Checking for known CVEs...", "color": PURPLE, "t0": 8.7 + shift},
        {"type": "text", "text": "[WARN] nginx 1.25.3 -> 1 known CVE (low)", "color": AMBER, "t0": 9.3 + shift},
        {"type": "text", "text": "[OK] OpenSSH 9.6 -> up to date", "color": GREEN, "t0": 9.75 + shift},
        {"type": "text", "text": "[OK] MySQL 8.0.36 -> up to date", "color": GREEN, "t0": 10.15 + shift},
        {"type": "text", "text": "[DONE] Scan complete in 0.84s", "color": BRIGHT, "t0": 10.7 + shift},
    ]


def lerp_color(c1, c2, t):
    t = max(0.0, min(1.0, t))
    r = c1.red() + (c2.red() - c1.red()) * t
    g = c1.green() + (c2.green() - c1.green()) * t
    b = c1.blue() + (c2.blue() - c1.blue()) * t
    return QColor(int(r), int(g), int(b))


class TerminalWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(488, 668)  # locked to the DW:DH design ratio, no stretch/letterbox possible
        self.tool_name = "WRAITH"
        self.target = "192.168.1.0/24"
        self.entries = build_entries(self.tool_name, self.target)
        self.start_time = None
        self.running = False
        self.frozen_elapsed = 0.0
        self.scroll_cur = 0.0

        self.font_banner = QFont("DejaVu Sans Mono", 40, QFont.Bold)
        self.font_sub = QFont("DejaVu Sans Mono", 12)
        self.font_log = QFont("DejaVu Sans Mono", 15, QFont.Bold)
        self.font_titlebar = QFont("DejaVu Sans Mono", 12)
        self.font_caption = QFont("DejaVu Sans", 19, QFont.Bold)
        self.font_stat_num = QFont("DejaVu Sans", 22, QFont.Bold)
        self.font_stat_lbl = QFont("DejaVu Sans Mono", 10)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update)

    def launch(self, tool_name, target, hook, cta):
        self.tool_name = tool_name or "WRAITH"
        self.target = target or "192.168.1.0/24"
        self.hook = (hook or "I built a port scanner from scratch").upper()
        self.cta = (cta or "Full breakdown in Phase 2").upper()
        self.entries = build_entries(self.tool_name, self.target)
        self.start_time = time.time()
        self.running = True
        self.scroll_cur = 0.0
        self.timer.start(33)

    def elapsed(self):
        if self.running:
            e = time.time() - self.start_time
            if e >= CTA_T0 + 2.5:
                self.running = False
                self.timer.stop()
                self.frozen_elapsed = CTA_T0 + 2.5
                return self.frozen_elapsed
            return e
        return self.frozen_elapsed

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setRenderHint(QPainter.TextAntialiasing)
        p.scale(self.width() / DW, self.height() / DH)

        t = self.elapsed()

        self._draw_background(p)
        self._draw_banner(p)
        self._draw_panel_chrome(p)
        revealed, typing_now, typing_text = self._compute_revealed(t)
        self._draw_log(p, revealed, typing_now, typing_text, t)
        self._draw_panel_border(p)
        if hasattr(self, "hook") and t <= 2.6:
            self._draw_caption(p, self.hook, 150)
        if hasattr(self, "hook") and 6.4 <= t <= 9.4:
            self._draw_caption(p, "SCANNING MY OWN LAB NETWORK", 1330)
        if t >= STATS_T0:
            alpha = min(1.0, (t - STATS_T0) / 0.4)
            self._draw_stats(p, alpha)
        if t >= CTA_T0 and hasattr(self, "cta"):
            self._draw_caption(p, self.cta, 1330)

    def _draw_background(self, p):
        grad = QLinearGradient(0, 0, 0, DH)
        grad.setColorAt(0, QColor(26, 13, 46))
        grad.setColorAt(1, QColor(6, 4, 12))
        p.fillRect(QRectF(0, 0, DW, DH), grad)

        radial = QRadialGradient(DW / 2, 300, 560)
        radial.setColorAt(0, QColor(130, 80, 230, 55))
        radial.setColorAt(1, QColor(130, 80, 230, 0))
        p.setPen(Qt.NoPen)
        p.setBrush(radial)
        p.drawRect(QRectF(0, 0, DW, DH))

        p.setPen(QColor(180, 160, 220, 14))
        p.setBrush(QColor(180, 160, 220, 14))
        for gy in range(20, DH, 44):
            for gx in range(20, DW, 44):
                p.drawEllipse(QRectF(gx, gy, 2, 2))

    def _draw_banner(self, p):
        p.setFont(self.font_banner)
        for dx, dy, a in [(-2, 0, 30), (2, 0, 30), (0, -2, 30), (0, 2, 30)]:
            p.setPen(QColor(PURPLE_DEEP.red(), PURPLE_DEEP.green(), PURPLE_DEEP.blue(), a))
            p.drawText(60 + dx, 250 + 62 + dy, self.tool_name)
        p.setPen(PURPLE)
        p.drawText(60, 250 + 62, self.tool_name)
        p.setFont(self.font_sub)
        p.setPen(DIM)
        p.drawText(64, 336 + 20, "void phantoms // recon module v2.1")

    def _draw_panel_chrome(self, p):
        shadow_path = QPainterPath()
        shadow_path.addRoundedRect(QRectF(PANEL_LEFT, PANEL_TOP + 10, PANEL_RIGHT - PANEL_LEFT,
                                           PANEL_BOTTOM - PANEL_TOP), 26, 26)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(0, 0, 0, 90))
        p.drawPath(shadow_path)

        path = QPainterPath()
        path.addRoundedRect(QRectF(PANEL_LEFT, PANEL_TOP, PANEL_RIGHT - PANEL_LEFT,
                                    PANEL_BOTTOM - PANEL_TOP), 26, 26)
        p.setBrush(PANEL_BG)
        p.setPen(Qt.NoPen)
        p.drawPath(path)

        p.save()
        p.setClipPath(path)
        title_rect = QRectF(PANEL_LEFT, PANEL_TOP, PANEL_RIGHT - PANEL_LEFT, TITLEBAR_H + 20)
        p.fillRect(title_rect, QColor(28, 20, 46))
        p.restore()

        p.setPen(PANEL_BORDER)
        p.drawLine(PANEL_LEFT, PANEL_TOP + TITLEBAR_H, PANEL_RIGHT, PANEL_TOP + TITLEBAR_H)

        dots_y = PANEL_TOP + TITLEBAR_H // 2
        for i, c in enumerate([QColor(255, 95, 86), QColor(255, 189, 46), QColor(39, 201, 63)]):
            cx = PANEL_LEFT + 28 + i * 30
            p.setBrush(c)
            p.setPen(Qt.NoPen)
            p.drawEllipse(QRectF(cx - 8, dots_y - 8, 16, 16))

        p.setFont(self.font_titlebar)
        p.setPen(DIM)
        p.drawText(PANEL_LEFT + 130, dots_y + 6, f"{self.tool_name.lower()}.sh — recon module")

    def _draw_panel_border(self, p):
        path = QPainterPath()
        path.addRoundedRect(QRectF(PANEL_LEFT, PANEL_TOP, PANEL_RIGHT - PANEL_LEFT,
                                    PANEL_BOTTOM - PANEL_TOP), 26, 26)
        p.setBrush(Qt.NoBrush)
        p.setPen(PANEL_BORDER)
        p.drawPath(path)

    def _compute_revealed(self, t):
        revealed = []
        typing_now = False
        typing_text = ""
        for e in self.entries:
            if e["t0"] <= t:
                if e["type"] == "text":
                    revealed.append((e["text"], e["color"], e["t0"]))
                elif e["type"] == "command":
                    t0, t1 = e["t0"], e["t1"]
                    frac = 1.0 if t >= t1 else max(0.0, (t - t0) / (t1 - t0))
                    nchars = int(len(e["cmd"]) * frac)
                    shown = e["prompt"] + e["cmd"][:nchars]
                    revealed.append((shown, BRIGHT, t0))
                    if t < t1:
                        typing_now = True
                        typing_text = shown
                else:
                    t0, t1 = e["t0"], e["t1"]
                    frac = 1.0 if t >= t1 else max(0.0, (t - t0) / (t1 - t0))
                    barlen = 14
                    filled = int(barlen * frac)
                    bar = "#" * filled + "." * (barlen - filled)
                    pct = int(frac * 100)
                    revealed.append((f"{e['label']} [{bar}] {pct:3d}%", e["color"], t0))
        return revealed, typing_now, typing_text

    def _draw_log(self, p, revealed, typing_now, typing_text, t):
        target_scroll = max(0, (len(revealed) - 1) * LINE_H - (LOG_BOTTOM - LOG_TOP) + LINE_H)
        self.scroll_cur += (target_scroll - self.scroll_cur) * 0.22

        p.setFont(self.font_log)
        fm = QFontMetrics(self.font_log)
        for i, (text, color, appear_t) in enumerate(revealed):
            y = LOG_TOP + i * LINE_H - self.scroll_cur
            if y < LOG_TOP - LINE_H or y > LOG_BOTTOM:
                continue
            age = t - appear_t
            draw_color = lerp_color(PANEL_BG, color, age / FADE_DUR) if (age < FADE_DUR and not typing_now) else color
            p.setPen(draw_color)
            p.drawText(LOG_LEFT, int(y + 32), text)

        if typing_now:
            blink_on = int(t * 3) % 2 == 0
            last_y = LOG_TOP + (len(revealed) - 1) * LINE_H - self.scroll_cur
            tw = fm.horizontalAdvance(typing_text)
            if blink_on:
                p.fillRect(QRectF(LOG_LEFT + tw + 4, last_y + 2, 16, 32), WHITE)
        elif revealed:
            blink_on = int(t * 2) % 2 == 0
            cy = LOG_TOP + len(revealed) * LINE_H - self.scroll_cur
            if blink_on and LOG_TOP - 10 <= cy <= LOG_BOTTOM:
                p.fillRect(QRectF(LOG_LEFT, cy + 4, 16, 26), WHITE)

        if t >= STATS_T0:
            dim_alpha = int(200 * min(1.0, (t - STATS_T0) / 0.5))
            dim_path = QPainterPath()
            dim_path.addRoundedRect(QRectF(PANEL_LEFT + 3, LOG_TOP - 16, PANEL_RIGHT - PANEL_LEFT - 6,
                                            PANEL_BOTTOM - LOG_TOP + 16 - 3), 10, 10)
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(8, 5, 16, dim_alpha))
            p.drawPath(dim_path)

    def _draw_caption(self, p, text, cy):
        p.setFont(self.font_caption)
        fm = QFontMetrics(self.font_caption)
        tw = fm.horizontalAdvance(text)
        th = fm.height()
        x = (DW - tw) / 2
        pad_x, pad_y = 28, 18
        box = QRectF(x - pad_x, cy - pad_y, tw + 2 * pad_x, th + 2 * pad_y)
        path = QPainterPath()
        path.addRoundedRect(box, 14, 14)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(10, 6, 20, 220))
        p.drawPath(path)
        p.setPen(QColor(PURPLE.red(), PURPLE.green(), PURPLE.blue(), 200))
        p.setBrush(Qt.NoBrush)
        p.drawPath(path)
        p.setBrush(PURPLE)
        p.setPen(Qt.NoPen)
        p.drawRect(QRectF(box.left(), box.top() + 6, 5, box.height() - 12))
        p.setPen(BRIGHT)
        p.drawText(int(x), int(cy + th - 4), text)

    def _draw_stats(self, p, alpha):
        n = len(STATS)
        box_w, box_h, gap = 300, 96, 18
        total_w = n * box_w + (n - 1) * gap
        x0 = (DW - total_w) / 2
        y0 = 1170
        a = int(210 * alpha)
        for i, (num, lbl) in enumerate(STATS):
            bx = x0 + i * (box_w + gap)
            box = QRectF(bx, y0, box_w, box_h)
            path = QPainterPath()
            path.addRoundedRect(box, 16, 16)
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(10, 6, 20, a))
            p.drawPath(path)
            c = STAT_COLORS[i]
            p.setPen(QColor(c.red(), c.green(), c.blue(), min(200, a)))
            p.setBrush(Qt.NoBrush)
            p.drawPath(path)

            p.setFont(self.font_stat_num)
            fm = QFontMetrics(self.font_stat_num)
            nw = fm.horizontalAdvance(num)
            p.setPen(lerp_color(QColor(10, 6, 20), c, alpha))
            p.drawText(int(bx + box_w / 2 - nw / 2), int(y0 + 46), num)

            p.setFont(self.font_stat_lbl)
            fm2 = QFontMetrics(self.font_stat_lbl)
            lw = fm2.horizontalAdvance(lbl)
            p.setPen(lerp_color(QColor(10, 6, 20), DIM, alpha))
            p.drawText(int(bx + box_w / 2 - lw / 2), int(y0 + 78), lbl)


COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 587: "submission", 993: "imaps",
    995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
}


class ScanWorker(QObject):
    output = pyqtSignal(str, str, str)
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, network):
        super().__init__()
        self.network = network
        self.started_at = None

    def _probe(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.35)
        try:
            if sock.connect_ex((host, port)) != 0:
                return None
            banner = ""
            try:
                sock.settimeout(0.45)
                if port in (80, 8080):
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: scan.local\r\n\r\n")
                data = sock.recv(200)
                printable = "".join(chr(byte) if 32 <= byte <= 126 else " " for byte in data)
                banner = " ".join(printable.split())[:100]
            except (OSError, socket.timeout):
                pass
            return host, port, banner
        finally:
            sock.close()

    def run(self):
        try:
            self.started_at = time.monotonic()
            hosts = [str(host) for host in self.network.hosts()]
            if not hosts and self.network.num_addresses == 1:
                hosts = [str(self.network.network_address)]
            jobs = [(host, port) for host in hosts for port in COMMON_PORTS]
            self.output.emit("INIT", f"Real TCP connect scan: {len(hosts)} host(s), {len(COMMON_PORTS)} common ports", "INITIALIZATION")
            self.output.emit("INFO", "Only open TCP ports generate host findings; no simulated results are used", "INITIALIZATION")

            findings = []
            completed = 0
            with ThreadPoolExecutor(max_workers=min(64, max(1, len(jobs)))) as pool:
                futures = [pool.submit(self._probe, host, port) for host, port in jobs]
                for future in as_completed(futures):
                    completed += 1
                    result = future.result()
                    if result:
                        findings.append(result)
                    if completed % 25 == 0 or completed == len(jobs):
                        self.progress.emit(completed, len(jobs))

            findings.sort(key=lambda item: (ipaddress.ip_address(item[0]), item[1]))
            open_hosts = sorted({host for host, _, _ in findings}, key=ipaddress.ip_address)
            if open_hosts:
                for host in open_hosts:
                    self.output.emit("HOST", f"{host} answered on a tested TCP port", "DISCOVERY")
                for host, port, banner in findings:
                    service = COMMON_PORTS.get(port, "unknown")
                    self.output.emit("OPEN", f"{host:<15} {port:>5}/tcp  {service}", "OPEN PORTS")
                for host, port, banner in findings:
                    if banner:
                        self.output.emit("BANNER", f"{host}:{port}  {banner}", "SERVICE BANNERS")
            else:
                self.output.emit("NONE", "No open ports found in the tested common-port set", "DISCOVERY")

            elapsed = time.monotonic() - self.started_at
            self.finished.emit({
                "hosts_tested": len(hosts), "hosts_found": len(open_hosts),
                "ports_open": len(findings), "elapsed": elapsed,
                "findings": findings,
            })
        except Exception as exc:
            self.failed.emit(str(exc))


def forward_wheel_event(widget, event):
    """Send a wheel event up to the nearest ancestor QScrollArea's scrollbar.

    Used by widgets that are sized to fit their content and never scroll
    themselves, so the mouse wheel always drives the window's one scrollbar
    regardless of which inner widget the cursor happens to be over.
    """
    ancestor = widget.parentWidget()
    while ancestor is not None and not isinstance(ancestor, QScrollArea):
        ancestor = ancestor.parentWidget()
    if ancestor is None:
        event.ignore()
        return
    bar = ancestor.verticalScrollBar()
    bar.setValue(bar.value() - event.angleDelta().y())
    event.accept()


class AutoHeightTextBrowser(QTextBrowser):
    """QTextBrowser that grows to fit its content instead of scrolling —
    keeps the whole app to a single outer scrollbar."""

    heightChanged = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._last_height = None
        self.document().documentLayout().documentSizeChanged.connect(self._autosize)

    def _autosize(self):
        margins = self.contentsMargins()
        height = self.document().size().height()
        height += margins.top() + margins.bottom() + self.frameWidth() * 2 + 6
        height = max(60, int(height))
        if height != self._last_height:
            self._last_height = height
            self.setFixedHeight(height)
            self.heightChanged.emit()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.document().setTextWidth(self.viewport().width())
        self._autosize()

    def wheelEvent(self, event):
        # This widget never scrolls internally (it's sized to fit its content).
        # Qt's implicit ignore()-then-bubble-to-parent behavior for wheel
        # events happens below the level sendEvent()/notify() can reach, so
        # it isn't reliably testable and isn't trusted here — the event is
        # forwarded to the window's single outer scroll area explicitly.
        forward_wheel_event(self, event)


STATUS_COLORS = {
    "INIT": "#b388ff", "INFO": "#8f829f", "HOST": "#55e6a5", "OPEN": "#4fd8ff",
    "BANNER": "#e8e6f0", "NONE": "#8f829f", "ERROR": "#ff6b88",
}
STATUS_PLACEHOLDER_HTML = "<span style='color:#8f829f'>Console ready — enter a private lab network above and press LAUNCH.</span>"
CLEARED_PLACEHOLDER_HTML = "<span style='color:#8f829f'>Console cleared. Enter a private target to begin a new scan.</span>"


class LiveOutputConsole(AutoHeightTextBrowser):
    """Renders scan events as a clean, color-coded log instead of a raw
    ASCII/monospace dump — status labels are colored and long details
    (service banners) wrap naturally instead of needing manual line-wrapping
    or a horizontal scrollbar."""

    def __init__(self):
        super().__init__()
        self.setObjectName("outputConsole")
        self.setOpenExternalLinks(False)
        self.setMinimumHeight(60)
        self.started_at = None
        self.last_section = None
        self._blocks = []
        self.setHtml(STATUS_PLACEHOLDER_HTML)

    def show_placeholder(self, html_text=CLEARED_PLACEHOLDER_HTML):
        self._blocks = []
        self.setHtml(html_text)

    def _render(self):
        self.setHtml("".join(self._blocks))

    def begin(self, target):
        self.started_at = time.monotonic()
        self.last_section = None
        self._blocks = [
            "<div style='margin-bottom:10px;'>"
            "<span style='color:#8f829f;font-size:10px;letter-spacing:1px;'>TARGET</span> "
            f"<span style='color:#e8e6f0;font-weight:bold;font-family:DejaVu Sans Mono;'>{html.escape(target)}</span>"
            "</div>"
        ]
        self._render()

    def add_event(self, status, detail, section):
        if section != self.last_section:
            self._blocks.append(
                "<div style='margin:14px 0 5px 0;padding-bottom:3px;"
                "border-bottom:1px solid #2b203b;color:#8f829f;font-size:10px;"
                f"font-weight:bold;letter-spacing:2px;'>{html.escape(section)}</div>"
            )
            self.last_section = section
        elapsed = time.monotonic() - self.started_at if self.started_at else 0
        minutes, seconds = divmod(elapsed, 60)
        stamp = f"{int(minutes):02d}:{seconds:05.2f}"
        color = STATUS_COLORS.get(status, "#e8e6f0")
        # A <table> is used instead of inline-block spans for the column
        # layout — Qt's rich-text engine doesn't reliably honor CSS
        # display/width on inline spans, but table cell widths and per-cell
        # wrapping are well supported.
        self._blocks.append(
            "<table width='100%' cellspacing='0' cellpadding='0' style='margin:5px 0;'><tr>"
            f"<td width='50' style='color:#5b5170;font-family:DejaVu Sans Mono;"
            f"font-size:10px;vertical-align:top;'>{stamp}</td>"
            f"<td width='68' style='color:{color};font-weight:bold;font-size:10px;"
            f"letter-spacing:1px;vertical-align:top;'>{html.escape(status)}</td>"
            f"<td style='color:#dcd6e6;vertical-align:top;'>{html.escape(detail)}</td>"
            "</tr></table>"
        )
        self._render()

    def complete(self, result):
        self._blocks.append(
            "<div style='margin-top:12px;padding-top:8px;border-top:1px solid #2b203b;"
            "color:#e8e6f0;font-size:11px;'>"
            "<span style='color:#55e6a5;font-weight:bold;letter-spacing:1px;'>SUMMARY</span>"
            f"&nbsp;&nbsp;&nbsp;{result['hosts_tested']} tested"
            f"&nbsp;&nbsp;•&nbsp;&nbsp;{result['hosts_found']} responding"
            f"&nbsp;&nbsp;•&nbsp;&nbsp;{result['ports_open']} open ports"
            f"&nbsp;&nbsp;•&nbsp;&nbsp;{result['elapsed']:.2f}s"
            "</div>"
        )
        self._render()


class VoidPhantomsTool(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wraith Spectrum — Void Phantoms")
        self.resize(1100, 820)
        self.setMinimumSize(760, 600)
        icon_path = os.path.join(ASSETS, "logo_icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.scan_thread = None
        self.scan_worker = None
        self._build_ui()
        self._apply_style()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 24)
        root.setSpacing(16)

        logo_path = os.path.join(ASSETS, "logo_icon.png")
        header = QHBoxLayout()
        logo_label = QLabel()
        if os.path.exists(logo_path):
            pix = QPixmap(logo_path).scaledToHeight(54, Qt.SmoothTransformation)
            logo_label.setPixmap(pix)
        header.addWidget(logo_label)

        title_box = QVBoxLayout()
        title_box.setSpacing(0)
        name = QLabel("VOID PHANTOMS")
        name.setObjectName("brandName")
        sub = QLabel("WRAITH SPECTRUM  //  SECURITY ANALYSIS")
        sub.setObjectName("brandSub")
        title_box.addWidget(name)
        title_box.addWidget(sub)
        header.addLayout(title_box)
        header.addStretch()
        scan_badge = QLabel("●  LIVE TCP ENGINE")
        scan_badge.setObjectName("scanBadge")
        header.addWidget(scan_badge)
        self.fullscreen_btn = QPushButton("⛶  MAXIMIZE")
        self.fullscreen_btn.setObjectName("fullscreenBtn")
        self.fullscreen_btn.setCursor(Qt.PointingHandCursor)
        self.fullscreen_btn.clicked.connect(self.toggle_maximized)
        header.addWidget(self.fullscreen_btn)
        root.addLayout(header)

        self.fullscreen_shortcut = QShortcut(QKeySequence("F11"), self)
        self.fullscreen_shortcut.activated.connect(self.toggle_maximized)
        self.restore_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.restore_shortcut.activated.connect(self.restore_window)

        description = QLabel("Discover reachable services on authorized private IPv4 networks.")
        description.setObjectName("description")
        root.addWidget(description)

        divider = QFrame()
        divider.setObjectName("divider")
        divider.setFrameShape(QFrame.HLine)
        root.addWidget(divider)

        target_label = QLabel("LAB NETWORK TARGET")
        target_label.setObjectName("fieldLabel")
        root.addWidget(target_label)

        input_row = QHBoxLayout()
        self.target_edit = QLineEdit("192.168.1.0/24")
        self.target_edit.setObjectName("targetEdit")
        self.launch_btn = QPushButton("LAUNCH")
        self.launch_btn.setObjectName("launchBtn")
        self.launch_btn.setCursor(Qt.PointingHandCursor)
        self.launch_btn.clicked.connect(self.on_launch)
        self.clear_btn = QPushButton("CLEAR")
        self.clear_btn.setObjectName("clearBtn")
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.clear_btn.clicked.connect(lambda: self.terminal.show_placeholder())
        input_row.addWidget(self.target_edit, stretch=1)
        input_row.addWidget(self.clear_btn)
        input_row.addWidget(self.launch_btn)
        root.addLayout(input_row)

        self.terminal_card = QFrame()
        terminal_card = self.terminal_card
        terminal_card.setObjectName("terminalCard")
        terminal_layout = QVBoxLayout(terminal_card)
        terminal_layout.setContentsMargins(16, 13, 16, 14)
        terminal_title = QLabel("SCAN CONSOLE")
        terminal_title.setObjectName("terminalTitle")
        terminal_sub = QLabel("LIVE TCP CONNECT OUTPUT  •  RAW LOG")
        terminal_sub.setObjectName("cardSub")
        terminal_divider = QFrame()
        terminal_divider.setObjectName("terminalDivider")
        terminal_divider.setFrameShape(QFrame.HLine)
        self.terminal = LiveOutputConsole()
        terminal_layout.addWidget(terminal_title)
        terminal_layout.addWidget(terminal_sub)
        terminal_layout.addSpacing(4)
        terminal_layout.addWidget(terminal_divider)
        terminal_layout.addSpacing(6)
        terminal_layout.addWidget(self.terminal)

        self.analysis_container = QWidget()
        analysis_container = self.analysis_container
        analysis_container.setObjectName("analysisContainer")
        analysis_row = QHBoxLayout()
        analysis_container.setLayout(analysis_row)
        analysis_row.setContentsMargins(0, 0, 0, 0)
        analysis_row.setSpacing(18)

        self.red_card = QFrame()
        red_card = self.red_card
        red_card.setObjectName("redCard")
        red_card.setMinimumHeight(150)
        red_layout = QVBoxLayout(red_card)
        red_layout.setContentsMargins(16, 13, 16, 14)
        red_title = QLabel("RED PHANTOM")
        red_title.setObjectName("redTitle")
        red_sub = QLabel("EXPOSURE INTELLIGENCE  •  CVE SIGNALS")
        red_sub.setObjectName("cardSub")
        red_divider = QFrame()
        red_divider.setObjectName("redDivider")
        red_divider.setFrameShape(QFrame.HLine)
        self.red_output = AutoHeightTextBrowser()
        self.red_output.setObjectName("redOutput")
        self.red_output.setOpenExternalLinks(False)
        self.red_output.setHtml("<span style='color:#8f829f'>Exposure findings will appear after the scan.</span>")
        red_layout.addWidget(red_title)
        red_layout.addWidget(red_sub)
        red_layout.addSpacing(4)
        red_layout.addWidget(red_divider)
        red_layout.addSpacing(6)
        red_layout.addWidget(self.red_output)

        self.blue_card = QFrame()
        blue_card = self.blue_card
        blue_card.setObjectName("blueCard")
        blue_card.setMinimumHeight(150)
        blue_layout = QVBoxLayout(blue_card)
        blue_layout.setContentsMargins(16, 13, 16, 14)
        blue_title = QLabel("BLUE PHANTOM")
        blue_title.setObjectName("blueTitle")
        blue_sub = QLabel("HARDENING GUIDANCE  •  RISK REDUCTION")
        blue_sub.setObjectName("cardSub")
        blue_divider = QFrame()
        blue_divider.setObjectName("blueDivider")
        blue_divider.setFrameShape(QFrame.HLine)
        self.blue_output = AutoHeightTextBrowser()
        self.blue_output.setObjectName("blueOutput")
        self.blue_output.setOpenExternalLinks(False)
        self.blue_output.setHtml("<span style='color:#8f829f'>Defensive recommendations will appear after the scan.</span>")
        blue_layout.addWidget(blue_title)
        blue_layout.addWidget(blue_sub)
        blue_layout.addSpacing(4)
        blue_layout.addWidget(blue_divider)
        blue_layout.addSpacing(6)
        blue_layout.addWidget(self.blue_output)

        analysis_row.addWidget(red_card, stretch=1, alignment=Qt.AlignTop)
        analysis_row.addWidget(blue_card, stretch=1, alignment=Qt.AlignTop)

        for widget, glow_color in (
            (terminal_card, QColor(179, 136, 255)),
            (red_card, QColor(255, 85, 119)),
            (blue_card, QColor(79, 216, 255)),
        ):
            shadow = QGraphicsDropShadowEffect(widget)
            shadow.setBlurRadius(30)
            shadow.setOffset(0, 4)
            shadow.setColor(QColor(glow_color.red(), glow_color.green(), glow_color.blue(), 70))
            widget.setGraphicsEffect(shadow)

        self.workspace = QWidget()
        workspace = self.workspace
        workspace.setObjectName("workspace")
        workspace_layout = QVBoxLayout(workspace)
        workspace_layout.setContentsMargins(0, 0, 4, 0)
        workspace_layout.setSpacing(16)
        workspace_layout.addWidget(terminal_card)
        workspace_layout.addWidget(analysis_container)
        workspace_layout.addStretch()

        scroll_area = QScrollArea()
        scroll_area.setObjectName("workspaceScroll")
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll_area.setWidget(workspace)
        root.addWidget(scroll_area, stretch=1)

        # Qt's automatic layout-invalidation cascade doesn't reliably bubble
        # a size change up through two stretched siblings in the analysis
        # row, so the analysis cards and workspace are resynced explicitly,
        # top-down, whenever any auto-growing widget's content changes —
        # this is what keeps the whole window to a single scrollbar.
        self.terminal.heightChanged.connect(self._sync_workspace_height)
        self.red_output.heightChanged.connect(self._sync_workspace_height)
        self.blue_output.heightChanged.connect(self._sync_workspace_height)

        footer = QHBoxLayout()
        self.status_label = QLabel("READY  •  Private IPv4 networks only")
        self.status_label.setObjectName("statusLabel")
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("scanProgress")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedWidth(220)
        footer.addWidget(self.status_label, stretch=1)
        footer.addWidget(self.progress_bar)
        root.addLayout(footer)

    def _sync_workspace_height(self):
        self.terminal_card.setFixedHeight(self.terminal_card.sizeHint().height())
        self.red_card.setFixedHeight(self.red_card.sizeHint().height())
        self.blue_card.setFixedHeight(self.blue_card.sizeHint().height())
        self.analysis_container.setFixedHeight(
            max(self.red_card.height(), self.blue_card.height())
        )
        self.workspace.setFixedHeight(self.workspace.sizeHint().height())

    def _apply_style(self):
        self.setStyleSheet("""
            QWidget {
    background-color: #08050f;
    color: #e8e6f0;
    font-family: 'DejaVu Sans';
    font-size: 18px;
}

QLabel {
    background: transparent;
}

QToolTip {
    background-color: #1a1128;
    color: #e8e6f0;
    border: 1px solid #4a3765;
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 16px;
}

#brandName {
    color: #ffffff;
    font-weight: bold;
    font-size: 34px;
    letter-spacing: 3px;
}

#brandSub {
    color: #8c81a3;
    font-size: 24px;
    letter-spacing: 2px;
}

#description {
    color: #9a8ead;
    font-size: 18px;
    padding-bottom: 8px;
}

#scanBadge {
    color: #55e6a5;
    background-color: #10241f;
    border: 1px solid #245443;
    border-radius: 18px;
    padding: 12px 26px;
    font-size: 17px;
    font-weight: bold;
    letter-spacing: 1px;
}

#fullscreenBtn {
    color: #c7bdd3;
    background-color: #171023;
    border: 1px solid #3b2d50;
    border-radius: 10px;
    padding: 14px 24px;
    font-size: 18px;
    font-weight: bold;
    letter-spacing: 1px;
}

#fullscreenBtn:hover {
    color: #ffffff;
    border-color: #73569b;
    background-color: #21172f;
}

#divider {
    color: #2c2042;
    background-color: #2c2042;
    max-height: 2px;
}

#fieldLabel {
    color: #a99bbb;
    font-size: 18px;
    font-weight: bold;
    letter-spacing: 1px;
}

#targetEdit {
    background-color: #140c26;
    border: 1px solid #3d2d5c;
    border-radius: 8px;
    padding: 18px 22px;
    color: #e8e6f0;
    font-family: 'DejaVu Sans Mono';
    font-size: 20px;
    min-height: 54px;
}

#targetEdit:focus {
    border: 2px solid #4fd8ff;
}

#launchBtn {
    background-color: qlineargradient(
        x1:0, y1:0,
        x2:1, y2:0,
        stop:0 #4fd8ff,
        stop:1 #b388ff
    );
    color: #0a0612;
    font-weight: bold;
    letter-spacing: 1px;
    border: none;
    border-radius: 8px;
    padding: 16px 34px;
    font-size: 20px;
    min-height: 56px;
}

#launchBtn:hover {
    background-color: qlineargradient(
        x1:0, y1:0,
        x2:1, y2:0,
        stop:0 #6ee2ff,
        stop:1 #c7a6ff
    );
}

#launchBtn:disabled {
    background-color: #241a3a;
    color: #8c81a3;
}

#clearBtn {
    background-color: #171023;
    color: #b8adc8;
    border: 1px solid #3b2d50;
    border-radius: 8px;
    padding: 16px 30px;
    font-size: 20px;
    font-weight: bold;
    letter-spacing: 1px;
    min-height: 56px;
}

#clearBtn:hover {
    color: #ffffff;
    border-color: #73569b;
    background-color: #21172f;
}

#outputConsole {
    background: transparent;
    border: none;
    padding: 10px;
    color: #d9f8ff;
    selection-background-color: #6545a3;
    font-size: 18px;
    line-height: 1.7;
}

#statusLabel {
    color: #897c9d;
    font-family: 'DejaVu Sans Mono';
    font-size: 17px;
}

#scanProgress {
    background-color: #171023;
    border: 1px solid #392952;
    border-radius: 6px;
    min-height: 12px;
    max-height: 12px;
}

#scanProgress::chunk {
    border-radius: 5px;
    background-color: qlineargradient(
        x1:0, y1:0,
        x2:1, y2:0,
        stop:0 #4fd8ff,
        stop:1 #b388ff
    );
}

#terminalCard {
    background-color: #0e0a18;
    border: 1px solid #4a3765;
    border-left: 4px solid #b388ff;
    border-radius: 12px;
    padding: 12px;
}

#redCard {
    background-color: #130b12;
    border: 1px solid #5b2735;
    border-left: 4px solid #ff5577;
    border-radius: 12px;
    padding: 12px;
}

#blueCard {
    background-color: #09121a;
    border: 1px solid #204b65;
    border-left: 4px solid #4fd8ff;
    border-radius: 12px;
    padding: 12px;
}

#terminalTitle,
#redTitle,
#blueTitle {
    font-size: 28px;
    font-weight: bold;
    letter-spacing: 2px;
}

#terminalTitle {
    color: #cdb6ff;
}

#redTitle {
    color: #ff6b88;
}

#blueTitle {
    color: #59dcff;
}

#cardSub {
    color: #8f829f;
    font-size: 16px;
    font-weight: bold;
    letter-spacing: 1px;
}

#terminalDivider {
    background-color: #3a2b55;
    max-height: 2px;
    border: none;
}

#redDivider {
    background-color: #4a2530;
    max-height: 2px;
    border: none;
}

#blueDivider {
    background-color: #1f4258;
    max-height: 2px;
    border: none;
}

#redOutput,
#blueOutput {
    background: transparent;
    border: none;
    color: #ddd6e6;
    font-family: 'DejaVu Sans';
    font-size: 18px;
    line-height: 1.7;
}

#workspace {
    background: transparent;
}

QScrollArea#workspaceScroll {
    background: transparent;
    border: none;
}

QScrollArea#workspaceScroll > QWidget > QWidget {
    background: transparent;
}

QScrollBar:vertical {
    background: transparent;
    width: 16px;
    margin: 4px 4px 4px 0px;
}

QScrollBar::handle:vertical {
    background: #3d2d5c;
    border-radius: 8px;
    min-height: 50px;
}

QScrollBar::handle:vertical:hover {
    background: #6b4f96;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar::add-page:vertical,
QScrollBar::sub-page:vertical {
    background: none;
}

QScrollBar:horizontal {
    height: 0px;
}

QMessageBox {
    background-color: #0c0818;
}

QMessageBox QLabel {
    color: #e8e6f0;
    font-size: 18px;
    background: transparent;
}

QMessageBox QPushButton {
    background-color: qlineargradient(
        x1:0, y1:0,
        x2:1, y2:0,
        stop:0 #4fd8ff,
        stop:1 #b388ff
    );
    color: #0a0612;
    font-weight: bold;
    letter-spacing: 1px;
    border: none;
    border-radius: 8px;
    padding: 14px 28px;
    min-width: 110px;
    font-size: 18px;
}

QMessageBox QPushButton:hover {
    background-color: qlineargradient(
        x1:0, y1:0,
        x2:1, y2:0,
        stop:0 #6ee2ff,
        stop:1 #c7a6ff
    );
}
        """)

    def toggle_maximized(self):
        if self.isMaximized():
            self.showNormal()
            self.fullscreen_btn.setText("⛶  MAXIMIZE")
        else:
            self.showMaximized()
            self.fullscreen_btn.setText("❐  RESTORE")

    def restore_window(self):
        if self.isMaximized() or self.isFullScreen():
            self.showNormal()
            self.fullscreen_btn.setText("⛶  MAXIMIZE")

    def on_launch(self):
        target = self.target_edit.text().strip() or "192.168.1.0/24"
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            QMessageBox.warning(self, "Invalid target", "Enter a valid IPv4 network in CIDR notation.")
            self.target_edit.setFocus()
            return

        private_ranges = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if network.version != 4:
            QMessageBox.warning(self, "IPv4 only", "Enter an IPv4 host or network.")
            self.target_edit.setFocus()
            return

        is_private_target = any(network.subnet_of(item) for item in private_ranges)
        if not is_private_target:
            QMessageBox.warning(
                self,
                "Private targets only",
                "Enter an address from 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16.",
            )
            self.target_edit.setFocus()
            return

        if network.num_addresses > 256:
            QMessageBox.warning(self, "Network too large", "Scan one private host or a network no larger than /24.")
            self.target_edit.setFocus()
            return

        target = str(network)
        self.target_edit.setText(target)
        self.launch_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.red_output.setHtml("<span style='color:#a997b4'>Analyzing live exposure data...</span>")
        self.blue_output.setHtml("<span style='color:#a997b4'>Preparing defensive guidance...</span>")
        self.status_label.setText(f"RUNNING  •  {target}")
        self.terminal.begin(target)

        self.scan_thread = QThread(self)
        self.scan_worker = ScanWorker(network)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.output.connect(self.terminal.add_event)
        self.scan_worker.progress.connect(self._scan_progress)
        self.scan_worker.finished.connect(self._scan_complete)
        self.scan_worker.failed.connect(self._scan_failed)
        self.scan_worker.finished.connect(self.scan_thread.quit)
        self.scan_worker.failed.connect(self.scan_thread.quit)
        self.scan_thread.finished.connect(self.scan_worker.deleteLater)
        self.scan_thread.finished.connect(self._scan_thread_finished)
        self.scan_thread.start()

    def _scan_progress(self, completed, total):
        percent = int(completed * 100 / total) if total else 100
        self.progress_bar.setValue(percent)
        self.status_label.setText(f"SCANNING  •  {percent}%  •  {completed}/{total} probes")

    def _scan_complete(self, result):
        self.terminal.complete(result)
        self._render_analysis(result["findings"])
        self.launch_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)
        self.progress_bar.setValue(100)
        self.status_label.setText(
            f"COMPLETE  •  {result['hosts_found']} responding  •  {result['ports_open']} open ports"
        )

    def _scan_failed(self, message):
        self.terminal.add_event("ERROR", message, "SCAN ERROR")
        self.launch_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("FAILED  •  See console for details")

    def _render_analysis(self, findings):
        risk_profiles = {
            21: ("HIGH", "FTP may expose credentials and data without encryption", "Disable FTP or replace it with SFTP/FTPS"),
            22: ("LOW", "Remote administration is reachable", "Use key authentication, disable root login, and restrict source addresses"),
            23: ("CRITICAL", "Telnet sends management traffic and credentials in clear text", "Disable Telnet and replace it with SSH"),
            53: ("MEDIUM", "DNS is reachable over TCP", "Restrict recursion and zone transfers to trusted systems"),
            80: ("MEDIUM", "Unencrypted HTTP service is reachable", "Redirect to HTTPS, patch the server, and remove unused pages"),
            135: ("HIGH", "Windows RPC is exposed to the scanned network", "Limit RPC with host firewall rules and network segmentation"),
            139: ("HIGH", "Legacy NetBIOS file-sharing surface is reachable", "Disable NetBIOS where unnecessary and restrict file-sharing access"),
            443: ("LOW", "HTTPS service is reachable", "Keep TLS and the web stack patched; disable legacy protocols"),
            445: ("HIGH", "SMB is reachable and commonly targeted", "Disable SMBv1, patch hosts, and allow SMB only between trusted systems"),
            1433: ("HIGH", "Microsoft SQL Server is reachable", "Restrict database access and require encrypted authenticated connections"),
            3306: ("HIGH", "MySQL is reachable", "Bind to trusted interfaces and restrict access with firewall rules"),
            3389: ("HIGH", "Remote Desktop is reachable", "Require NLA and MFA, patch the host, and restrict RDP through a VPN"),
            5432: ("HIGH", "PostgreSQL is reachable", "Restrict listen addresses and enforce strong authenticated TLS access"),
            6379: ("CRITICAL", "Redis is reachable and may expose sensitive data", "Restrict Redis to trusted hosts and require authentication with TLS"),
            8080: ("MEDIUM", "Alternate HTTP service is reachable", "Review the application, patch it, and place it behind authenticated HTTPS"),
            8443: ("MEDIUM", "Alternate HTTPS management service is reachable", "Restrict management access and keep its TLS stack patched"),
        }
        severity_colors = {"CRITICAL": "#ff5577", "HIGH": "#ff7b72", "MEDIUM": "#f2c14e", "LOW": "#62d6a8"}
        banners = {(host, port): banner for host, port, banner in findings if banner}
        ordered = sorted(
            findings,
            key=lambda item: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(risk_profiles.get(item[1], ("LOW", "", ""))[0], 4), item[0], item[1]),
        )

        red_items = []
        blue_items = []
        seen_guidance = set()
        for host, port, _banner in ordered:
            service = COMMON_PORTS.get(port, "unknown")
            severity, exposure, guidance = risk_profiles.get(
                port,
                ("LOW", "A reachable TCP service increases the host's attack surface", "Verify that the service is required, patched, and access-controlled"),
            )
            color = severity_colors[severity]
            evidence = banners.get((host, port), "No version banner returned")
            cve_state = (
                "Version evidence captured — correlate with a current CVE database before testing"
                if (host, port) in banners
                else "Not verified — exact product and version were not identified"
            )
            red_items.append(
                f"<div style='margin-bottom:11px'><b style='color:{color}'>{severity}</b> "
                f"<b style='color:#f0eaf4'>{html.escape(host)}:{port} / {html.escape(service)}</b><br>"
                f"<span style='color:#c8bdcf'>{html.escape(exposure)}</span><br>"
                f"<span style='color:#8f829f'>Evidence:</span> {html.escape(evidence)}<br>"
                f"<span style='color:#8f829f'>CVE status:</span> {html.escape(cve_state)}</div>"
            )
            guidance_key = (port, guidance)
            if guidance_key not in seen_guidance:
                seen_guidance.add(guidance_key)
                blue_items.append(
                    f"<div style='margin-bottom:11px'><b style='color:#59dcff'>{port}/tcp · {html.escape(service)}</b><br>"
                    f"<span style='color:#d6e8ef'>{html.escape(guidance)}</span></div>"
                )

        if not findings:
            red_html = "<b style='color:#62d6a8'>NO COMMON TCP EXPOSURE FOUND</b><br><span style='color:#8f829f'>This is not proof that the host is vulnerability-free.</span>"
            blue_html = "<b style='color:#59dcff'>MAINTAIN DEFENSIVE BASELINE</b><br><span style='color:#c8dce5'>Continue patching, monitoring, segmentation, and least-privilege access.</span>"
        else:
            red_html = "".join(red_items)
            blue_html = "".join(blue_items)
        self.red_output.setHtml(red_html)
        self.blue_output.setHtml(blue_html)

    def _scan_thread_finished(self):
        thread = self.scan_thread
        self.scan_worker = None
        self.scan_thread = None
        if thread is not None:
            thread.deleteLater()


def main():
    app = QApplication(sys.argv)
    win = VoidPhantomsTool()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
