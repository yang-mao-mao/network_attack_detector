#!/usr/bin/env python3
"""
Packet Capture — split window for packet display and network capture control.

Access restriction (per task1.md):
  - Read+Write: only files in this directory (packet_capture/).
  - Read-only:   files elsewhere — writing outside is forbidden.

Layout
------
  +---------------------------------------------+
  |  menu_bar                                    |
  |  +-----------------------------------------+ |
  |  |  File  |  Network                       | |
  |  +-----------------------------------------+ |
  +---------------------------------------------+
  |  QSplitter (vertical, resizable)            |
  |  +-----------------------------------------+ |
  |  |  Upper: packet table / placeholder      | |
  |  |  (black bg, white text)                 | |
  |  +-----------------------------------------+ |
  |  |  Lower: detail view (initially hidden)   | |
  |  +-----------------------------------------+ |
  +---------------------------------------------+

Dependencies: PyQt6 only (per task restriction).
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path
from typing import Any

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMenu,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

# =============================================================================
# Path helpers — cross-platform (Windows / Linux)
# =============================================================================
_THIS_DIR = Path(__file__).resolve().parent  # .../src/ui/packet_capture

# Allowed write directory (per task1.md access restriction)
_ALLOWED_WRITE_DIR: Path = _THIS_DIR

# Add src/ to sys.path so we can import capture.{interface,live_capture}
_CAPTURE_SRC = _THIS_DIR.parent.parent  # .../src/
if str(_CAPTURE_SRC) not in sys.path:
    sys.path.insert(0, str(_CAPTURE_SRC))

from capture.interface import CaptureInterface
from capture.live_capture import LiveCapture, CaptureState


def _is_write_allowed(path: Path) -> bool:
    """Check whether *path* is inside the allowed write directory."""
    try:
        path.resolve().relative_to(_ALLOWED_WRITE_DIR.resolve())
        return True
    except ValueError:
        return False


# =============================================================================
# CSS / STYLE MACROS — all colours and reusable stylesheet templates
# =============================================================================
# Naming convention
#   CLR_*           – colour hex values (dark theme)
#   CSS_*           – reusable Qt stylesheet fragment ({placeholders} allowed)

# ── Colour palette ──────────────────────────────────────────────────────────

CLR_BG_0          = "#1e1e1e"   # deepest  — main window, table bg
CLR_BG_1          = "#2d2d2d"   # mid-dark — panel frames, scroll bars
CLR_BG_2          = "#3c3c3c"   # mid      — input fields, hover

CLR_BORDER        = "#3e3e3e"   # subtle hairline — splitter handles, grid lines
CLR_BORDER_VIS    = "#555555"   # visible edge

CLR_TEXT          = "#d4d4d4"   # primary body text
CLR_TEXT_MUTED    = "#888888"   # muted / placeholder / secondary text
CLR_TEXT_INVERSE  = "#ffffff"   # text on coloured backgrounds

CLR_ACCENT        = "#007acc"   # main accent  — header underlines
CLR_SECTION_BG    = "#252525"   # header-bar background

CLR_SELECTION_BG  = "#094771"   # selected row background (blue)


# ── Reusable CSS templates ──────────────────────────────────────────────────

CSS_SPLITTER_HANDLE = (
    "QSplitter::handle {{ background-color: {CLR_BORDER}; }}"
)

CSS_SCROLL_AREA = (
    "QScrollArea {{ border: none; background-color: {CLR_BG_0}; }}"
    "QScrollBar:vertical {{ background: {CLR_BG_1}; width: 8px; }}"
    "QScrollBar::handle:vertical {{ background: {CLR_BORDER_VIS};"
    "border-radius: 4px; min-height: 30px; }}"
    "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}"
)

CSS_TABLE = (
    "QTableWidget {{"
    "background-color: {CLR_BG_0}; color: {CLR_TEXT};"
    "gridline-color: {CLR_BORDER}; border: 1px solid {CLR_BORDER};"
    "font-size: 12px;"
    "}}"
    "QTableWidget::item {{ padding: 4px 8px; }}"
    "QTableWidget::item:selected {{"
    "background-color: {CLR_SELECTION_BG}; color: {CLR_TEXT_INVERSE};"
    "}}"
    "QHeaderView::section {{"
    "background-color: {CLR_SECTION_BG}; color: {CLR_TEXT};"
    "padding: 5px 8px; border: none;"
    "border-bottom: 2px solid {CLR_ACCENT}; font-weight: bold;"
    "}}"
)

CSS_APP_GLOBAL = (
    "QMainWindow {{ background-color: {CLR_BG_0}; }}"
    "QMenuBar {{"
    "background-color: {CLR_BG_1}; color: {CLR_TEXT};"
    "border-bottom: 1px solid {CLR_BORDER}; padding: 2px 4px;"
    "}}"
    "QMenuBar::item {{"
    "background-color: transparent; color: {CLR_TEXT};"
    "padding: 4px 12px;"
    "}}"
    "QMenuBar::item:selected {{"
    "background-color: {CLR_SELECTION_BG};"
    "}}"
    "QMenu {{"
    "background-color: {CLR_BG_1}; color: {CLR_TEXT};"
    "border: 1px solid {CLR_BORDER_VIS};"
    "}}"
    "QMenu::item {{"
    "padding: 6px 30px 6px 20px;"
    "}}"
    "QMenu::item:selected {{"
    "background-color: {CLR_SELECTION_BG};"
    "}}"
    "QMenu::item:disabled {{"
    "color: {CLR_TEXT_MUTED};"
    "}}"
    "QToolTip {{"
    "background-color: {CLR_BG_1}; color: {CLR_TEXT};"
    "border: 1px solid {CLR_BORDER_VIS};"
    "}}"
)

# Detail-view label style — white text, word-wrap enabled
CSS_DETAIL_LABEL = (
    "QLabel {{"
    "color: {CLR_TEXT}; background-color: transparent;"
    "padding: 2px 8px; font-size: 13px;"
    "}}"
)


# =============================================================================
# PacketCaptureWindow — the composite main window
# =============================================================================
class PacketCaptureWindow(QMainWindow):
    """Top-level window: menu bar | upper packet table | lower detail view.

    The upper area shows a table of received ``PacketInfo`` objects (from
    ``core.models``) with columns: source IP, destination IP, destination
    port, protocol, length.

    When a row is selected it highlights in blue (white text), and the
    lower detail panel opens showing every field of the ``PacketInfo``
    in definition order.

    Public API for receiving packets from external programs
    -------------------------------------------------------
    Other modules can feed packets into this window in two ways:

    1. Call the ``add_packet(packet)`` slot directly (main-thread safe).
    2. Emit the ``packet_received`` signal — it is connected to
       ``add_packet`` so both paths work identically.

    Example::

        window.add_packet(my_packet_info)
        # or, from a different module:
        window.packet_received.emit(my_packet_info)
    """

    # Signal: emit with a PacketInfo object to add it to the table.
    # Connected to add_packet() so either the signal or the slot works.
    packet_received = pyqtSignal(object)

    # ── Table column configuration ─────────────────────────────────────────
    # Must match the fields we extract from PacketInfo for the summary row.
    _COLUMNS = [
        ("src_ip",     "源 IP"),
        ("dst_ip",     "目的 IP"),
        ("dst_port",   "目的端口"),
        ("protocol",   "协议"),
        ("length",     "长度"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Packet Capture — Network Attack Detector")
        self.resize(1000, 650)

        # Capture state
        self._capturing: bool = False
        self._capture_device: str | None = None

        # LiveCapture instance (created on start, destroyed on stop)
        self._live_capture: LiveCapture | None = None

        # Packet storage
        self._packets: list[Any] = []  # PacketInfo instances

        # Stats polling timer (matches the polling loop in live_capture.py's main)
        self._stats_timer = QTimer(self)
        self._stats_timer.timeout.connect(self._on_stats_timer)

        # Menu references (kept for enable/disable toggling)
        self._start_menu: QMenu | None = None
        self._stop_action: QAction | None = None
        self._pause_action: QAction | None = None
        self._resume_action: QAction | None = None

        self._build_ui()
        self._connect_signals()

    # ── UI construction ─────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Assemble the complete layout: menu bar + vertical splitter +
        status bar."""
        self._build_menu_bar()

        # Central: vertical splitter (upper table | lower detail)
        self._splitter = QSplitter(Qt.Orientation.Vertical)
        self._splitter.setHandleWidth(3)
        self._splitter.setStyleSheet(CSS_SPLITTER_HANDLE.format(
            CLR_BORDER=CLR_BORDER))

        # Upper — packet table + "NO TRAFFIC FOUND" placeholder
        self._upper_stack = QStackedWidget()
        self._upper_stack.addWidget(self._build_table_page())
        self._upper_stack.addWidget(self._build_placeholder_page())
        self._upper_stack.setCurrentIndex(0)  # default: empty table
        self._splitter.addWidget(self._upper_stack)

        # Lower — detail view (initially hidden via zero size)
        self._detail_widget = self._build_detail_panel()
        self._splitter.addWidget(self._detail_widget)

        # Initially hide lower panel by giving all space to upper
        self._splitter.setSizes([650, 0])

        self.setCentralWidget(self._splitter)

        # Status bar for capture stats (matches stats polling in main())
        self._status_bar = self.statusBar()
        self._status_bar.setStyleSheet(
            f"background-color: {CLR_SECTION_BG}; color: {CLR_TEXT};"
            f"border-top: 1px solid {CLR_BORDER}; padding: 2px 8px;"
        )
        self._status_bar.showMessage("Ready")

    def _build_menu_bar(self) -> None:
        """Create the menu bar with File and Network menus."""
        menu_bar = self.menuBar()

        # ── File menu ───────────────────────────────────────────────────
        file_menu = menu_bar.addMenu("File")
        open_action = QAction("Open…", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._on_file_open)
        file_menu.addAction(open_action)

        # ── Network menu ────────────────────────────────────────────────
        network_menu = menu_bar.addMenu("Network")

        # Start Capturing — a submenu populated dynamically with interfaces
        self._start_menu = QMenu("Start Capturing", self)
        self._start_menu.aboutToShow.connect(self._populate_interfaces)
        network_menu.addMenu(self._start_menu)

        # Stop Capturing — initially disabled (gray, unclickable)
        self._stop_action = QAction("Stop Capturing", self)
        self._stop_action.setEnabled(False)
        self._stop_action.triggered.connect(self._on_stop_capturing)
        network_menu.addAction(self._stop_action)

        # Pause Capturing — initially disabled (gray, unclickable)
        self._pause_action = QAction("PAUSE CAPTURING", self)
        self._pause_action.setEnabled(False)
        self._pause_action.triggered.connect(self._on_pause_capturing)
        network_menu.addAction(self._pause_action)

        # Resume Capturing — initially disabled (gray, unclickable)
        self._resume_action = QAction("RESUME CAPTURING", self)
        self._resume_action.setEnabled(False)
        self._resume_action.triggered.connect(self._on_resume_capturing)
        network_menu.addAction(self._resume_action)


    def _build_table_page(self) -> QWidget:
        """Build the packet summary table (upper area)."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        self._table = QTableWidget(0, len(self._COLUMNS))
        self._table.setHorizontalHeaderLabels([c[1] for c in self._COLUMNS])
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(False)

        hdr = self._table.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)

        self._table.setStyleSheet(CSS_TABLE.format(
            CLR_BG_0=CLR_BG_0, CLR_TEXT=CLR_TEXT,
            CLR_BORDER=CLR_BORDER, CLR_SECTION_BG=CLR_SECTION_BG,
            CLR_ACCENT=CLR_ACCENT,
            CLR_SELECTION_BG=CLR_SELECTION_BG,
            CLR_TEXT_INVERSE=CLR_TEXT_INVERSE,
        ))

        # Connect row-selection signal
        self._table.itemSelectionChanged.connect(self._on_selection_changed)

        layout.addWidget(self._table)
        return container

    def _build_placeholder_page(self) -> QWidget:
        """Build the "NO TRAFFIC FOUND" placeholder (shown after capture
        starts but before any packets arrive)."""
        container = QWidget()
        container.setStyleSheet(f"background-color: {CLR_BG_0};")
        layout = QVBoxLayout(container)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._placeholder_label = QLabel("")
        self._placeholder_label.setFont(QFont("Segoe UI", 16))
        self._placeholder_label.setStyleSheet(
            f"color: {CLR_TEXT_MUTED};")
        self._placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._placeholder_label)
        return container

    def _build_detail_panel(self) -> QWidget:
        """Build the lower detail panel — a scrollable area showing all
        PacketInfo fields in definition order."""
        container = QWidget()
        container.setStyleSheet(f"background-color: {CLR_BG_0};")
        outer = QVBoxLayout(container)
        outer.setContentsMargins(0, 0, 0, 0)

        # Section header
        header = QLabel("Packet Detail")
        header.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        header.setStyleSheet(
            f"color: {CLR_TEXT}; background-color: {CLR_SECTION_BG};"
            f"padding: 8px 12px; border-bottom: 2px solid {CLR_ACCENT};"
        )
        outer.addWidget(header)

        # Scrollable detail content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(CSS_SCROLL_AREA.format(
            CLR_BG_0=CLR_BG_0, CLR_BG_1=CLR_BG_1,
            CLR_BORDER_VIS=CLR_BORDER_VIS,
        ))

        self._detail_content = QWidget()
        self._detail_content.setStyleSheet(
            f"background-color: {CLR_BG_0};")
        self._detail_layout = QVBoxLayout(self._detail_content)
        self._detail_layout.setContentsMargins(8, 8, 8, 8)
        self._detail_layout.setSpacing(2)
        self._detail_layout.addStretch()
        scroll.setWidget(self._detail_content)
        outer.addWidget(scroll, stretch=1)

        return container

    # ── Signal wiring ───────────────────────────────────────────────────────

    def _connect_signals(self) -> None:
        """Wire the packet_received signal to the add_packet slot."""
        self.packet_received.connect(self.add_packet)

    # ── Menu: File → Open ──────────────────────────────────────────────────

    def _on_file_open(self) -> None:
        """Open a file dialog (native file manager) for the user to select
        a file.  The path is printed to stdout; loading logic can be
        extended here."""
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Open File",
            str(_THIS_DIR),
            "All Files (*)",
        )
        if path_str:
            print(f"File selected: {path_str}")
            # Future: parse the file for packet data and call add_packet().

    # ── Menu: Network → Start Capturing (interface submenu) ────────────────

    def _populate_interfaces(self) -> None:
        """Populate the Start Capturing submenu with a list of available
        network interfaces.  Called each time the submenu is about to show
        (``aboutToShow``), so the list is always fresh.

        Uses ``CaptureInterface.get_interfaces()`` from
        ``capture.interface`` to enumerate interfaces.
        """
        if self._start_menu is None:
            return

        # Clear previous entries
        self._start_menu.clear()

        try:
            interfaces = CaptureInterface.get_interfaces(only_up=True)
        except Exception:
            # Fallback: provide at least the loopback
            interfaces = []

        if not interfaces:
            no_iface = QAction("(no interfaces found)", self)
            no_iface.setEnabled(False)
            self._start_menu.addAction(no_iface)
            return

        for iface in interfaces:
            label = f"{iface.name}"
            if iface.ip_addresses:
                label += f"  ({', '.join(iface.ip_addresses)})"
            action = QAction(label, self)
            action.triggered.connect(
                lambda _checked, dev=iface.name: self._on_start_capturing(dev)
            )
            self._start_menu.addAction(action)

    def _on_start_capturing(self, device: str) -> None:
        """Begin capturing on *device*.

        - Creates a ``LiveCapture`` instance and calls ``start()``.
        - Registers a packet handler that emits ``packet_received``.
        - Disables the Start Capturing submenu and enables Stop / Pause.
        - Shows the "NO TRAFFIC FOUND" placeholder in the table area.

        Any exception from the underlying capture layer is caught so the
        GUI never crashes — the UI is reset to a safe idle state and the
        error is logged to stderr.
        """
        if self._capturing:
            return  # already capturing — do nothing

        self._capturing = True
        self._capture_device = device

        print(f"Start Capturing | Device: {device}")

        try:
            # Create and start LiveCapture (matching live_capture.py main())
            self._live_capture = LiveCapture(
                interface=device,
                bpf_filter="",
                packet_count=0,  # 0 = unlimited for GUI
            )
            self._live_capture.add_handler(self._on_packet_received)
            self._live_capture.start()
        except Exception:
            traceback.print_exc()
            print(
                f"[ERROR] Failed to start capture on {device}. "
                f"Resetting to idle state.",
                file=sys.stderr,
            )
            # Safely reset everything
            self._safe_reset_capture_state()
            return

        # Disable Start Capturing, enable Stop / Pause
        if self._start_menu is not None:
            self._start_menu.setEnabled(False)
        if self._stop_action is not None:
            self._stop_action.setEnabled(True)
        if self._pause_action is not None:
            self._pause_action.setEnabled(True)
        if self._resume_action is not None:
            self._resume_action.setEnabled(False)

        # Start stats polling timer (matching main()'s polling loop)
        self._stats_timer.start(1000)

        # Show "NO TRAFFIC FOUND" placeholder
        self._show_no_traffic_placeholder()

    # ── Menu: Network → Stop Capturing ─────────────────────────────────────

    def _on_stop_capturing(self) -> None:
        """Stop the active capture.

        - Calls ``LiveCapture.stop()`` and cleans up the instance.
        - Re-enables the Start Capturing submenu.
        - Disables Stop / Pause / Resume actions (gray, unclickable).

        Always resets the UI to a safe idle state even if the underlying
        capture layer raises an exception.
        """
        if not self._capturing:
            return

        device = self._capture_device or "unknown"
        print(f"Stop Capturing | Device: {device}")

        # Try to stop LiveCapture gracefully; reset UI regardless of outcome
        try:
            if self._live_capture is not None:
                self._live_capture.stop()
        except Exception:
            traceback.print_exc()
            print(
                "[ERROR] Exception while stopping capture. "
                "Resetting UI to idle state.",
                file=sys.stderr,
            )

        # Always clean up internal state
        self._live_capture = None
        self._capturing = False
        self._capture_device = None

        # Stop stats polling timer
        self._stats_timer.stop()
        self._status_bar.showMessage("Capture stopped")

        # Re-enable Start Capturing, disable Stop / Pause / Resume
        if self._start_menu is not None:
            self._start_menu.setEnabled(True)
        if self._stop_action is not None:
            self._stop_action.setEnabled(False)
        if self._pause_action is not None:
            self._pause_action.setEnabled(False)
        if self._resume_action is not None:
            self._resume_action.setEnabled(False)

    # ── Menu: Network → Pause Capturing ────────────────────────────────────

    def _on_pause_capturing(self) -> None:
        """Pause the active capture.

        - Calls ``LiveCapture.pause()``.
        - Disables the Pause action and enables the Resume action.

        On failure the button states are still toggled (safe fallback)
        and the error is logged.
        """
        try:
            if self._live_capture is not None:
                self._live_capture.pause()
        except Exception:
            traceback.print_exc()
            print("[ERROR] Failed to pause capture.", file=sys.stderr)
        finally:
            if self._pause_action is not None:
                self._pause_action.setEnabled(False)
            if self._resume_action is not None:
                self._resume_action.setEnabled(True)

    # ── Menu: Network → Resume Capturing ───────────────────────────────────

    def _on_resume_capturing(self) -> None:
        """Resume the paused capture.

        - Calls ``LiveCapture.resume()``.
        - Disables the Resume action and enables the Pause action.

        On failure the button states are still toggled (safe fallback)
        and the error is logged.
        """
        try:
            if self._live_capture is not None:
                self._live_capture.resume()
        except Exception:
            traceback.print_exc()
            print("[ERROR] Failed to resume capture.", file=sys.stderr)
        finally:
            if self._pause_action is not None:
                self._pause_action.setEnabled(True)
            if self._resume_action is not None:
                self._resume_action.setEnabled(False)

    # ── LiveCapture packet handler ─────────────────────────────────────────

    def _on_packet_received(self, packet_info: Any) -> None:
        """Handler called by ``LiveCapture`` (from its worker thread) for
        every captured packet.

        - Prints the packet summary to the terminal (matching the
          ``print_handler`` in ``live_capture.py``'s ``main()``).
        - Emits ``packet_received`` which is connected to ``add_packet`` via
          ``Qt.AutoConnection`` — when emitted from a non-main thread the
          signal is queued, so ``add_packet`` always runs in the main thread.

        Any exception during signal emission is caught and logged — a
        malformed packet must never crash the GUI.
        """
        try:
            # Print to terminal — matching live_capture.py main()'s print_handler
            print(packet_info.summary())
        except Exception:
            pass  # Best-effort terminal output

        try:
            self.packet_received.emit(packet_info)
        except Exception:
            traceback.print_exc()
            print(
                "[ERROR] Failed to process captured packet.",
                file=sys.stderr,
            )

    # ── Stats polling timer (matches main()'s polling loop) ──────────────────

    def _on_stats_timer(self) -> None:
        """Periodically poll capture stats and display in the status bar.

        This mirrors the ``time.sleep(1); capture.get_stats()`` polling
        loop in ``live_capture.py``'s ``main()`` function.
        """
        if self._live_capture is not None:
            try:
                stats = self._live_capture.get_stats()
                self._status_bar.showMessage(
                    f"Packets: {stats['total']} | "
                    f"TCP: {stats['tcp']} | UDP: {stats['udp']} | "
                    f"ICMP: {stats['icmp']} | Other: {stats['other']} | "
                    f"Dropped: {stats['dropped']}"
                )
            except Exception:
                pass  # Best-effort stats display

    # ── Safe state reset ────────────────────────────────────────────────────

    def _safe_reset_capture_state(self) -> None:
        """Reset all capture-related state to idle, swallowing any
        exception from the underlying capture layer.

        Call this when an error occurs during start/stop so the GUI
        always returns to a known-safe state.
        """
        # Attempt to stop the sniffer if it exists
        try:
            if self._live_capture is not None:
                self._live_capture.stop()
        except Exception:
            pass  # Best-effort — sniffer may already be dead

        self._live_capture = None
        self._capturing = False
        self._capture_device = None

        # Stop stats polling timer
        self._stats_timer.stop()

        # Reset menu items to idle state
        try:
            if self._start_menu is not None:
                self._start_menu.setEnabled(True)
            if self._stop_action is not None:
                self._stop_action.setEnabled(False)
            if self._pause_action is not None:
                self._pause_action.setEnabled(False)
            if self._resume_action is not None:
                self._resume_action.setEnabled(False)
        except Exception:
            pass  # Menu references should always be valid, but be defensive

    # ── Placeholder management ─────────────────────────────────────────────

    def _show_no_traffic_placeholder(self) -> None:
        """Switch the upper area to show the centred "NO TRAFFIC FOUND"
        message with the current capture device name."""
        device = self._capture_device or "unknown"
        self._placeholder_label.setText(
            f"NO TRAFFIC FOUND IN {device}")
        self._upper_stack.setCurrentIndex(1)  # placeholder page

    # ── Public API — receive packets from other programs ───────────────────

    def add_packet(self, packet: Any) -> None:
        """Add a ``PacketInfo`` instance to the table.

        This is the primary entry point for external modules to feed
        packet data into the packet-capture window.  Once at least one
        packet arrives the table page replaces the "NO TRAFFIC FOUND"
        placeholder.

        Any exception from malformed packet data is caught and logged —
        a bad packet must never crash the GUI.

        Parameters
        ----------
        packet : PacketInfo
            An instance of ``core.models.PacketInfo`` (or any object with
            matching attribute names: ``src_ip``, ``dst_ip``, ``dst_port``,
            ``protocol``, ``length``).
        """
        try:
            self._packets.append(packet)
            self._append_row(packet)
            # Switch from placeholder to table if this is the first packet
            if self._upper_stack.currentIndex() != 0:
                self._upper_stack.setCurrentIndex(0)
        except Exception:
            traceback.print_exc()
            print(
                "[ERROR] Failed to add packet to table.",
                file=sys.stderr,
            )

    def clear_packets(self) -> None:
        """Remove all packet rows and conditionally return to the
        placeholder view.  If capture is active the "NO TRAFFIC FOUND"
        placeholder is shown; otherwise the empty table is shown."""
        self._packets.clear()
        self._table.setRowCount(0)
        # Hide the lower detail panel
        self._hide_detail_panel()
        if self._capturing:
            self._show_no_traffic_placeholder()
        else:
            self._upper_stack.setCurrentIndex(0)  # empty table

    # ── Row selection → detail panel ───────────────────────────────────────

    def _on_selection_changed(self) -> None:
        """Handle row selection in the packet table.

        When a row is selected the lower detail panel opens (if it was
        hidden) and displays all PacketInfo fields in definition order.
        When selection is cleared the lower panel hides again.
        """
        selected_rows = self._table.selectionModel().selectedRows()
        if not selected_rows:
            self._hide_detail_panel()
            return

        row = selected_rows[0].row()
        if 0 <= row < len(self._packets):
            packet = self._packets[row]
            self._show_detail(packet)

    def _hide_detail_panel(self) -> None:
        """Collapse the lower detail panel (set its height to zero)."""
        self._clear_detail_content()
        total = self._splitter.height()
        self._splitter.setSizes([total, 0])

    def _show_detail(self, packet: Any) -> None:
        """Populate and reveal the lower detail panel for *packet*."""
        self._clear_detail_content()

        # Build field labels in PacketInfo definition order (from core.models)
        fields = self._extract_packet_fields(packet)
        for field_name, value in fields:
            lbl = QLabel(f"{field_name}: {value}")
            lbl.setFont(QFont("Segoe UI", 11))
            lbl.setStyleSheet(CSS_DETAIL_LABEL.format(CLR_TEXT=CLR_TEXT))
            lbl.setWordWrap(True)
            lbl.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            # Insert before the stretch
            self._detail_layout.insertWidget(
                self._detail_layout.count() - 1, lbl)

        # Reveal the lower panel (split evenly)
        total = self._splitter.height()
        self._splitter.setSizes([total * 2 // 3, total // 3])

    def _clear_detail_content(self) -> None:
        """Remove all detail-field labels from the lower panel."""
        for i in reversed(range(self._detail_layout.count())):
            item = self._detail_layout.itemAt(i)
            if item is not None:
                w = item.widget()
                if w is not None and isinstance(w, QLabel):
                    self._detail_layout.removeWidget(w)
                    w.deleteLater()

    @staticmethod
    def _extract_packet_fields(packet: Any) -> list[tuple[str, str]]:
        """Extract all fields from *packet* in PacketInfo definition order.

        The order matches ``core.models.PacketInfo`` dataclass fields:
        packet_id, timestamp, src_ip, dst_ip, src_port, dst_port,
        protocol, length, payload, payload_text, http, raw_summary,
        interface, metadata.

        Returns a list of (field_name, display_value) pairs.
        """
        field_names = [
            "packet_id", "timestamp", "src_ip", "dst_ip",
            "src_port", "dst_port", "protocol", "length",
            "payload", "payload_text", "http", "raw_summary",
            "interface", "metadata",
        ]

        result: list[tuple[str, str]] = []
        for name in field_names:
            try:
                raw = getattr(packet, name, None)
            except Exception:
                raw = None

            if raw is None:
                display = "—"
            elif name == "payload" and isinstance(raw, bytes):
                display = f"<{len(raw)} bytes>"
            elif hasattr(raw, "__dict__"):
                # Complex objects (HttpInfo, etc.) — use repr
                display = repr(raw)
            elif isinstance(raw, dict):
                display = str(raw) if raw else "—"
            else:
                display = str(raw)

            result.append((name, display))

        return result

    # ── Table helpers ──────────────────────────────────────────────────────

    def _append_row(self, packet: Any) -> None:
        """Render one PacketInfo as a table row."""
        row = self._table.rowCount()
        self._table.insertRow(row)

        # Column 0 — src_ip
        self._set_cell(row, 0, str(getattr(packet, "src_ip", None) or "—"))
        # Column 1 — dst_ip
        self._set_cell(row, 1, str(getattr(packet, "dst_ip", None) or "—"))
        # Column 2 — dst_port
        dst_port = getattr(packet, "dst_port", None)
        self._set_cell(row, 2, str(dst_port) if dst_port is not None else "—")
        # Column 3 — protocol
        protocol = getattr(packet, "protocol", None)
        raw_proto = getattr(protocol, "value", None)
        display_proto = raw_proto if raw_proto is not None else str(protocol or "—")
        self._set_cell(row, 3, display_proto)
        # Column 4 — length
        length = getattr(packet, "length", 0)
        self._set_cell(row, 4, str(length))

    def _set_cell(self, row: int, col: int,
                  text: str) -> QTableWidgetItem | None:
        """Create, style, and set a table-widget item."""
        item = QTableWidgetItem(text)
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        item.setForeground(QColor(CLR_TEXT))
        self._table.setItem(row, col, item)
        return item

    # ── Close event ─────────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        """Clean up on window close."""
        if self._capturing:
            self._on_stop_capturing()
        event.accept()


# =============================================================================
# Entry point
# =============================================================================
def main() -> None:
    """Launch the packet-capture composite window."""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    app.setStyleSheet(CSS_APP_GLOBAL.format(
        CLR_BG_0=CLR_BG_0, CLR_BG_1=CLR_BG_1,
        CLR_TEXT=CLR_TEXT, CLR_BORDER_VIS=CLR_BORDER_VIS,
        CLR_BORDER=CLR_BORDER, CLR_SELECTION_BG=CLR_SELECTION_BG,
        CLR_TEXT_MUTED=CLR_TEXT_MUTED,
    ))

    window = PacketCaptureWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
