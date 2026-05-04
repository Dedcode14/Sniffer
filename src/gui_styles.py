STYLE = """
    QMainWindow, QWidget {
        background-color: #1e1e2e;
        color: #cdd6f4;
        font-family: Arial;
        font-size: 13px;
    }
    QTableWidget {
        background-color: #181825;
        color: #cdd6f4;
        border: 1px solid #313244;
        gridline-color: #313244;
        selection-background-color: #45475a;
    }
    QTableWidget::item:selected {
        background-color: #45475a;
        color: #cdd6f4;
    }
    QHeaderView::section {
        background-color: #313244;
        color: #cdd6f4;
        padding: 6px;
        border: none;
        font-weight: bold;
    }
    QPushButton {
        background-color: #89b4fa;
        color: #1e1e2e;
        border: none;
        padding: 8px 20px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 13px;
    }
    QPushButton:hover {
        background-color: #b4befe;
    }
    QPushButton:disabled {
        background-color: #45475a;
        color: #6c7086;
    }
    QPushButton#btn_stop {
        background-color: #f38ba8;
        color: #1e1e2e;
    }
    QPushButton#btn_stop:hover {
        background-color: #eba0ac;
    }
    QTextEdit {
        background-color: #181825;
        color: #cdd6f4;
        border: 1px solid #313244;
        border-radius: 4px;
        padding: 8px;
        font-family: Consolas, monospace;
        font-size: 12px;
    }
    QLabel#label_title {
        font-size: 18px;
        font-weight: bold;
        color: #89b4fa;
        padding: 8px 0px;
    }
    QLabel#label_status {
        color: #a6e3a1;
        font-size: 12px;
        padding: 4px;
    }
    QLabel#label_detail_title {
        font-size: 14px;
        font-weight: bold;
        color: #cba6f7;
        padding: 4px 0px;
    }
    QFrame#separator {
        background-color: #313244;
    }
"""

PROTO_COLORS = {
    "TCP": "#89b4fa",
    "UDP": "#a6e3a1",
    "ICMP": "#fab387",
}
