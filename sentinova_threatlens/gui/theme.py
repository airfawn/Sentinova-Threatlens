from __future__ import annotations

"""Dark security-product visual theme: colors, spacing, and QSS."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase
from PySide6.QtWidgets import QApplication

# ── Palette ────────────────────────────────────────────────────────────────
BG          = "#0B0E13"
SIDE_PANEL  = "#11151D"
CARD        = "#161C25"
CARD_HOVER  = "#1D2530"
CARD_ACTIVE = "#1A2131"
BORDER      = "#232B38"
INPUT_BG    = "#10151D"

TEXT        = "#E7EBF1"
TEXT_MUTED  = "#8C96A8"
TEXT_FAINT  = "#5A6374"

ACCENT      = "#4F8CFF"
ACCENT_HOVER = "#5F97FF"
ACCENT_DIM   = "#33527F"
ACCENT_SOFT  = "rgba(79, 140, 255, 0.14)"

SCANNER_TEAL = "#38B6D8"

SEVERITY_LOW  = "#3FD68B"
SEVERITY_MED  = "#E8B93C"
SEVERITY_HIGH = "#F08A3C"
SEVERITY_CRIT = "#F0435B"

ONLINE  = "#3FD68B"
OFFLINE = "#F0435B"
WARNING = "#E8B93C"

# ── Layout ─────────────────────────────────────────────────────────────────
PAGE_MARGIN      = 28
PAGE_MARGIN_NARROW = 20
CARD_RADIUS      = 18
SIDE_RADIUS      = 20
BUTTON_RADIUS    = 10
INPUT_RADIUS     = 12
MODAL_RADIUS     = 22
TABLE_RADIUS     = 16
BADGE_RADIUS     = 999

_RADIUS = CARD_RADIUS

# ── Icons (subsequent UI sets) ─────────────────────────────────────────────
ACCENT_COLOR = QColor(ACCENT)
BG_COLOR = QColor(BG)


def pick_font_family() -> str:
    """Pick the most modern available sans-serif family."""
    candidates = ["Inter", "IBM Plex Sans", "Segoe UI", "SF Pro Display", "Helvetica Neue"]
    try:
        families = QFontDatabase().families()
        if ".AppleSystemUIFont" in families:
            return QApplication.font().family()
        for fam in candidates:
            if fam in families:
                return fam
    except RuntimeError:
        pass
    return QApplication.font().family()


def apply(app: QApplication) -> None:
    global _QSS
    family = pick_font_family()
    font = QFont(family)
    font.setPointSize(13)
    font.setHintingPreference(QFont.PreferNoHinting)
    app.setFont(font)
    _QSS = f"""
* {{
    font-family: '{family}';
}}

QWidget {{
    color: {TEXT};
    background: transparent;
    font-size: 13px;
    selection-background-color: rgba(79, 140, 255, 0.35);
}}

QMainWindow, #MainRoot {{
    background: {BG};
}}

/* ── Sidebar ─────────────────────────────────────────────── */
#Sidebar {{
    background: {SIDE_PANEL};
    border-radius: {SIDE_RADIUS}px;
}}

#SidebarTitle {{
    color: {TEXT};
    font-size: 17px;
    font-weight: 700;
    letter-spacing: 0.5px;
}}

#SidebarVersion {{
    color: {TEXT_FAINT};
    font-size: 11px;
}}

QPushButton.NavButton {{
    color: {TEXT_MUTED};
    background: transparent;
    border: none;
    border-radius: 12px;
    padding: 11px 14px;
    font-size: 13.5px;
    font-weight: 500;
    text-align: left;
}}
QPushButton.NavButton:hover {{
    color: {TEXT};
    background: rgba(255, 255, 255, 0.045);
}}
QPushButton.NavButton:checked {{
    color: {ACCENT};
    background: {ACCENT_SOFT};
    font-weight: 600;
}}
#SidebarFooter {{
    color: {TEXT_FAINT};
    font-size: 11px;
}}

/* ── Cards ──────────────────────────────────────────────── */
#Card {{
    background: {CARD};
    border: 1px solid {BORDER};
    border-radius: {_RADIUS}px;
}}

#SubCard {{
    background: {CARD};
    border: 1px solid {BORDER};
    border-radius: 14px;
}}

#StackRoot {{
    background: {BG};
}}

/* ── Headers / text ────────────────────────────────────── */
#PageTitle {{
    font-size: 24px;
    font-weight: 700;
    color: {TEXT};
}}
#PageSubtitle {{
    font-size: 13px;
    color: {TEXT_MUTED};
}}
#StatValue {{
    font-size: 26px;
    font-weight: 700;
    color: {TEXT};
}}
#StatLabel {{
    font-size: 12px;
    color: {TEXT_MUTED};
}}
#CardTitle {{
    font-size: 15px;
    font-weight: 600;
    color: {TEXT};
}}
#CardCaption {{
    font-size: 12px;
    color: {TEXT_MUTED};
}}

/* ── Inputs ────────────────────────────────────────────── */
QLineEdit, QComboBox {{
    background: {INPUT_BG};
    border: 1px solid {BORDER};
    border-radius: {INPUT_RADIUS}px;
    padding: 9px 14px;
    color: {TEXT};
    font-size: 13px;
}}
QLineEdit:hover, QComboBox:hover {{
    border-color: #2E3947;
}}
QLineEdit:focus, QComboBox:focus {{
    border-color: {ACCENT_DIM};
}}
QLineEdit::placeholder {{
    color: {TEXT_FAINT};
}}
QComboBox::drop-down {{ border: none; }}
QComboBox QAbstractItemView {{
    background: {CARD};
    border: 1px solid {BORDER};
    border-radius: 10px;
    selection-background-color: {ACCENT_SOFT};
    selection-color: {TEXT};
    padding: 4px;
    outline: none;
}}

/* ── Buttons ───────────────────────────────────────────── */
QPushButton.Primary {{
    background: {ACCENT};
    color: #FFFFFF;
    border: none;
    border-radius: {BUTTON_RADIUS}px;
    padding: 9px 18px;
    font-size: 13px;
    font-weight: 600;
}}
QPushButton.Primary:hover {{ background: {ACCENT_HOVER}; }}
QPushButton.Primary:pressed {{ background: {ACCENT_DIM}; }}

QPushButton.Secondary {{
    background: transparent;
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: {BUTTON_RADIUS}px;
    padding: 9px 18px;
    font-size: 13px;
    font-weight: 500;
}}
QPushButton.Secondary:hover {{
    background: rgba(255, 255, 255, 0.05);
    border-color: #2E3947;
}}
QPushButton.Secondary:pressed {{ background: rgba(255, 255, 255, 0.09); }}

QPushButton.LinkButton {{
    color: {ACCENT};
    background: transparent;
    border: none;
    padding: 6px 8px;
    font-size: 12px;
    font-weight: 600;
    text-align: center;
}}
QPushButton.LinkButton:hover {{ color: {ACCENT_HOVER}; text-decoration: none; }}

/* ── Status pill ───────────────────────────────────────── */
#OnlinePill {{
    color: {ONLINE};
    background: rgba(63, 214, 139, 0.10);
    border: 1px solid rgba(63, 214, 139, 0.35);
    border-radius: 999px;
    padding: 4px 12px;
    font-size: 12px;
    font-weight: 600;
}}

/* ── Progress bar ──────────────────────────────────────── */
QProgressBar {{
    background: rgba(255, 255, 255, 0.07);
    border: none;
    border-radius: 8px;
    height: 12px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                stop:0 {ACCENT}, stop:1 #6FA4FF);
    border-radius: 8px;
}}

/* ── Table ─────────────────────────────────────────────── */
QTableWidget, QTableView {{
    background: {CARD};
    alternate-background-color: rgba(255, 255, 255, 0.016);
    border: none;
    border-radius: {TABLE_RADIUS}px;
    gridline-color: transparent;
    outline: none;
}}
QTableWidget::item, QTableView::item {{
    padding: 2px 12px;
    border: none;
    color: {TEXT};
    background: transparent;
}}
QTableWidget::item:hover, QTableView::item:hover {{ background: rgba(255, 255, 255, 0.04); }}
QTableWidget::item:selected, QTableView::item:selected {{
    background: rgba(79, 140, 255, 0.16);
    color: {TEXT};
}}
QHeaderView::section {{
    background: {CARD};
    color: {TEXT_MUTED};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 13px 12px;
    font-size: 12px;
    font-weight: 600;
}}

/* ── Scrollbars ────────────────────────────────────────── */
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 4px 2px;
}}
QScrollBar::handle:vertical {{
    background: #2A3442;
    border-radius: 5px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: #39465A; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}

QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 2px 4px;
}}
QScrollBar::handle:horizontal {{
    background: #2A3442;
    border-radius: 5px;
    min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{ background: #39465A; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}

QScrollArea {{ border: none; }}
QScrollArea QWidget#qt_scrollarea_viewport {{ background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}

/* ── Dialogs / modal ───────────────────────────────────── */
QDialog {{
    background: {BG};
}}
#ModalCard {{
    background: {CARD};
    border: 1px solid {BORDER};
    border-radius: {MODAL_RADIUS}px;
}}
QTextEdit, QPlainTextEdit {{
    background: #0D1219;
    border: 1px solid {BORDER};
    border-radius: 10px;
    color: {TEXT};
    font-family: 'SF Mono', 'Menlo', 'Monaco', monospace;
    font-size: 12px;
    padding: 12px;
    selection-background-color: rgba(79, 140, 255, 0.35);
}}

/* ── Tooltips ──────────────────────────────────────────── */
QToolTip {{
    background: {CARD_HOVER};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 5px 8px;
    font-size: 12px;
}}

/* ── Empty states ──────────────────────────────────────── */
#EmptyTitle {{
    font-size: 18px;
    font-weight: 600;
    color: {TEXT};
}}
#EmptyCaption {{
    font-size: 13px;
    color: {TEXT_MUTED};
}}

/* ── Search block ──────────────────────────────────────── */
#SearchBox {{
    background: {INPUT_BG};
    border: 1px solid {BORDER};
    border-radius: {INPUT_RADIUS}px;
    padding: 9px 14px 9px 36px;
    color: {TEXT};
}}
#SearchBox:focus {{ border-color: {ACCENT_DIM}; }}
#SearchBox[state="focused"] {{ border-color: {ACCENT_DIM}; }}
"""