import os
import sqlite3
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QComboBox, QPushButton, QLabel, QLineEdit,
    QTextEdit, QTableView, QHeaderView, QAbstractItemView, QMessageBox, QFrame, QSizePolicy
)
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QIcon
from PyQt6.QtCore import Qt
from tower_iq.gui.assets import get_asset_path

# Supported SQL operations for columns
SQL_OPERATIONS = ["", "COUNT", "SUM", "AVG", "MIN", "MAX"]
ORDER_DIRECTIONS = ["ASC", "DESC"]

class ExplorePage(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '../../data/toweriq.sqlite')
        self.db_path = os.path.normpath(self.db_path)
        self.conn = None
        self.db_schema = {}
        self._init_db()
        self._init_state()
        self._init_ui()
        self._update_ui_from_schema()
        self._connect_signals()
        self._generate_and_preview_query()

    def _init_db(self):
        try:
            if not os.path.exists(self.db_path):
                raise FileNotFoundError(f"Database not found at: {self.db_path}")
            self.conn = sqlite3.connect(self.db_path)
            self.db_schema = self._get_db_schema() if self.conn else {}
        except Exception as e:
            QMessageBox.critical(self, "Database Error", str(e))
            self.setDisabled(True)

    def _get_db_schema(self):
        if not self.conn:
            return {}
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        schema = {}
        for table in tables:
            if not table.startswith('sqlite_'):
                cursor.execute(f"PRAGMA table_info('{table}');")
                schema[table] = [row[1] for row in cursor.fetchall()]
        return schema

    def _init_state(self):
        # Each is a list of dicts representing a row in the builder
        self.selected_columns = []  # [{op, col, alias}]
        self.filters = []           # [{col, op, val}]
        self.group_by = []          # [col]
        self.order_by = []          # [{col, dir}]
        self.limit = ""

    def _init_ui(self):
        self.main_layout = QVBoxLayout(self)
        # --- Query Builder Column (Vertical) ---
        self.builder_col = QVBoxLayout()
        self.builder_col.setSpacing(12)
        self.builder_col.setContentsMargins(0, 0, 0, 0)
        # Table selector
        self.table_frame, self.table_layout = self._make_section_frame("Table")
        self.from_combo = QComboBox()
        self.table_layout.addWidget(self.from_combo)
        self.builder_col.addWidget(self.table_frame)
        # Columns/Operations
        self.columns_frame, self.columns_layout = self._make_section_frame("Columns")
        self.columns_rows_layout = QVBoxLayout()
        self.columns_layout.addLayout(self.columns_rows_layout)
        self.add_column_btn = self._make_add_button(self._add_column_row)
        self.columns_layout.addWidget(self.add_column_btn)
        self.builder_col.addWidget(self.columns_frame)
        # Filters (WHERE)
        self.filters_frame, self.filters_layout = self._make_section_frame("Filter")
        self.filters_rows_layout = QVBoxLayout()
        self.filters_layout.addLayout(self.filters_rows_layout)
        self.add_filter_btn = self._make_add_button(self._add_filter_row)
        self.filters_layout.addWidget(self.add_filter_btn)
        self.builder_col.addWidget(self.filters_frame)
        # Group By
        self.groupby_frame, self.groupby_layout = self._make_section_frame("Group By")
        self.groupby_rows_layout = QVBoxLayout()
        self.groupby_layout.addLayout(self.groupby_rows_layout)
        self.add_groupby_btn = self._make_add_button(self._add_groupby_row)
        self.groupby_layout.addWidget(self.add_groupby_btn)
        self.builder_col.addWidget(self.groupby_frame)
        # Order By
        self.orderby_frame, self.orderby_layout = self._make_section_frame("Order By")
        self.orderby_rows_layout = QVBoxLayout()
        self.orderby_layout.addLayout(self.orderby_rows_layout)
        self.add_orderby_btn = self._make_add_button(self._add_orderby_row)
        self.orderby_layout.addWidget(self.add_orderby_btn)
        self.builder_col.addWidget(self.orderby_frame)
        # Limit
        self.limit_frame, self.limit_layout = self._make_section_frame("Limit")
        self.limit_edit = QLineEdit()
        self.limit_edit.setPlaceholderText("e.g., 100")
        self.limit_edit.setMaximumWidth(80)
        self.limit_layout.addWidget(self.limit_edit)
        self.builder_col.addWidget(self.limit_frame)
        # Add builder column to main layout
        self.main_layout.addLayout(self.builder_col)
        # --- SQL Preview ---
        self.main_layout.addWidget(QLabel("Generated SQL Query:"))
        self.sql_preview = QTextEdit()
        self.sql_preview.setReadOnly(True)
        self.sql_preview.setFixedHeight(100)
        self.sql_preview.setStyleSheet("background-color: #f0f0f0; font-family: 'Courier New';")
        self.main_layout.addWidget(self.sql_preview)
        # --- Run Query Button ---
        run_query_button = QPushButton("Run Query")
        run_query_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        run_query_button.clicked.connect(self._run_query)
        self.main_layout.addWidget(run_query_button)
        # --- Results Table ---
        self.main_layout.addWidget(QLabel("Query Results:"))
        self.results_table = QTableView()
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self.results_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_model = QStandardItemModel()
        self.results_table.setModel(self.results_model)
        self.main_layout.addWidget(self.results_table)

    def _make_section_frame(self, title):
        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        frame.setStyleSheet("QFrame { background: #001219; border-radius: 6px; padding: 8px; } QLabel { color: #fff; font-weight: bold; }")
        layout = QVBoxLayout()
        layout.setSpacing(4)
        layout.setContentsMargins(4, 4, 4, 4)
        label = QLabel(title)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)
        frame.setLayout(layout)
        frame.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Maximum)
        return frame, layout

    def _make_add_button(self, callback):
        icon_path = get_asset_path("icons/add.svg")
        btn = QPushButton()
        btn.setIcon(QIcon(icon_path))
        btn.setToolTip('Add')
        btn.setFixedSize(28, 28)
        btn.setStyleSheet('QPushButton { background: transparent; border: none; } QPushButton:hover { background: #2a9b8e; }')
        btn.clicked.connect(callback)
        return btn

    def _make_remove_button(self, callback):
        icon_path = get_asset_path("icons/close.svg")
        btn = QPushButton()
        btn.setIcon(QIcon(icon_path))
        btn.setToolTip('Remove')
        btn.setFixedSize(28, 28)
        btn.setStyleSheet('QPushButton { background: transparent; border: none; } QPushButton:hover { background: #2a9b8e; }')
        btn.clicked.connect(callback)
        return btn

    def _update_ui_from_schema(self):
        self.from_combo.clear()
        self.from_combo.addItems(self.db_schema.keys())
        if self.from_combo.count() > 0:
            self.from_combo.setCurrentIndex(0)
            self._on_table_changed()

    def _connect_signals(self):
        self.from_combo.currentIndexChanged.connect(self._on_table_changed)
        self.limit_edit.textChanged.connect(self._on_limit_changed)

    def _on_table_changed(self):
        # Clear all builder rows
        self.selected_columns.clear()
        self.filters.clear()
        self.group_by.clear()
        self.order_by.clear()
        self.limit = ""
        self._refresh_columns_rows()
        self._refresh_filters_rows()
        self._refresh_groupby_rows()
        self._refresh_orderby_rows()
        self.limit_edit.setText("")
        self._generate_and_preview_query()

    # --- Columns/Operations Section ---
    def _refresh_columns_rows(self):
        # Remove all widgets
        while self.columns_rows_layout.count():
            item = self.columns_rows_layout.takeAt(0)
            w = item.widget() if item is not None else None
            if w is not None:
                w.deleteLater()
        # Add at least one row if empty
        if not self.selected_columns:
            self.selected_columns.append({"op": "", "col": "", "alias": ""})
        for idx, colinfo in enumerate(self.selected_columns):
            row = QHBoxLayout()
            op_combo = QComboBox()
            op_combo.addItems(SQL_OPERATIONS)
            op_combo.setCurrentText(colinfo["op"])
            op_combo.setFixedWidth(70)
            op_combo.currentTextChanged.connect(lambda val, i=idx: self._on_column_op_changed(i, val))
            col_combo = QComboBox()
            table = self.from_combo.currentText()
            columns = self.db_schema.get(table, [])
            col_combo.addItems([""] + columns)
            col_combo.setCurrentText(colinfo["col"])
            col_combo.setFixedWidth(120)
            col_combo.currentTextChanged.connect(lambda val, i=idx: self._on_column_col_changed(i, val))
            alias_edit = QLineEdit()
            alias_edit.setPlaceholderText("Alias")
            alias_edit.setText(colinfo["alias"])
            alias_edit.setFixedWidth(80)
            alias_edit.textChanged.connect(lambda val, i=idx: self._on_column_alias_changed(i, val))
            remove_btn = self._make_remove_button(lambda _, i=idx: self._remove_column_row(i))
            row.addWidget(op_combo)
            row.addWidget(col_combo)
            row.addWidget(alias_edit)
            row.addWidget(remove_btn)
            self.columns_rows_layout.addLayout(row)

    def _add_column_row(self):
        self.selected_columns.append({"op": "", "col": "", "alias": ""})
        self._refresh_columns_rows()
        self._generate_and_preview_query()

    def _remove_column_row(self, idx):
        if len(self.selected_columns) > 1:
            self.selected_columns.pop(idx)
            self._refresh_columns_rows()
            self._generate_and_preview_query()

    def _on_column_op_changed(self, idx, val):
        self.selected_columns[idx]["op"] = val
        self._generate_and_preview_query()

    def _on_column_col_changed(self, idx, val):
        self.selected_columns[idx]["col"] = val
        self._generate_and_preview_query()

    def _on_column_alias_changed(self, idx, val):
        self.selected_columns[idx]["alias"] = val
        self._generate_and_preview_query()

    # --- Filters Section ---
    def _refresh_filters_rows(self):
        while self.filters_rows_layout.count():
            item = self.filters_rows_layout.takeAt(0)
            w = item.widget() if item is not None else None
            if w is not None:
                w.deleteLater()
        if not self.filters:
            self.filters.append({"col": "", "op": "=", "val": ""})
        for idx, filt in enumerate(self.filters):
            row = QHBoxLayout()
            col_combo = QComboBox()
            table = self.from_combo.currentText()
            columns = self.db_schema.get(table, [])
            col_combo.addItems([""] + columns)
            col_combo.setCurrentText(filt["col"])
            col_combo.setFixedWidth(120)
            col_combo.currentTextChanged.connect(lambda val, i=idx: self._on_filter_col_changed(i, val))
            op_combo = QComboBox()
            operators = ['=', '!=', '>', '<', '>=', '<=', 'LIKE', 'IN', 'IS NOT NULL', 'IS NULL']
            op_combo.addItems(operators)
            op_combo.setCurrentText(filt["op"])
            op_combo.setFixedWidth(80)
            op_combo.currentTextChanged.connect(lambda val, i=idx: self._on_filter_op_changed(i, val))
            val_edit = QLineEdit()
            val_edit.setText(filt["val"])
            val_edit.setPlaceholderText("Value")
            val_edit.setFixedWidth(100)
            val_edit.textChanged.connect(lambda val, i=idx: self._on_filter_val_changed(i, val))
            remove_btn = self._make_remove_button(lambda _, i=idx: self._remove_filter_row(i))
            row.addWidget(col_combo)
            row.addWidget(op_combo)
            row.addWidget(val_edit)
            row.addWidget(remove_btn)
            self.filters_rows_layout.addLayout(row)

    def _add_filter_row(self):
        self.filters.append({"col": "", "op": "=", "val": ""})
        self._refresh_filters_rows()
        self._generate_and_preview_query()

    def _remove_filter_row(self, idx):
        if len(self.filters) > 1:
            self.filters.pop(idx)
            self._refresh_filters_rows()
            self._generate_and_preview_query()

    def _on_filter_col_changed(self, idx, val):
        self.filters[idx]["col"] = val
        self._generate_and_preview_query()

    def _on_filter_op_changed(self, idx, val):
        self.filters[idx]["op"] = val
        self._generate_and_preview_query()

    def _on_filter_val_changed(self, idx, val):
        self.filters[idx]["val"] = val
        self._generate_and_preview_query()

    # --- Group By Section ---
    def _refresh_groupby_rows(self):
        while self.groupby_rows_layout.count():
            item = self.groupby_rows_layout.takeAt(0)
            w = item.widget() if item is not None else None
            if w is not None:
                w.deleteLater()
        if not self.group_by:
            self.group_by.append("")
        for idx, col in enumerate(self.group_by):
            row = QHBoxLayout()
            col_combo = QComboBox()
            table = self.from_combo.currentText()
            columns = self.db_schema.get(table, [])
            col_combo.addItems([""] + columns)
            col_combo.setCurrentText(col)
            col_combo.setFixedWidth(120)
            col_combo.currentTextChanged.connect(lambda val, i=idx: self._on_groupby_col_changed(i, val))
            remove_btn = self._make_remove_button(lambda _, i=idx: self._remove_groupby_row(i))
            row.addWidget(col_combo)
            row.addWidget(remove_btn)
            self.groupby_rows_layout.addLayout(row)

    def _add_groupby_row(self):
        self.group_by.append("")
        self._refresh_groupby_rows()
        self._generate_and_preview_query()

    def _remove_groupby_row(self, idx):
        if len(self.group_by) > 1:
            self.group_by.pop(idx)
            self._refresh_groupby_rows()
            self._generate_and_preview_query()

    def _on_groupby_col_changed(self, idx, val):
        self.group_by[idx] = val
        self._generate_and_preview_query()

    # --- Order By Section ---
    def _refresh_orderby_rows(self):
        while self.orderby_rows_layout.count():
            item = self.orderby_rows_layout.takeAt(0)
            w = item.widget() if item is not None else None
            if w is not None:
                w.deleteLater()
        if not self.order_by:
            self.order_by.append({"col": "", "dir": "ASC"})
        for idx, ob in enumerate(self.order_by):
            row = QHBoxLayout()
            col_combo = QComboBox()
            table = self.from_combo.currentText()
            columns = self.db_schema.get(table, [])
            col_combo.addItems([""] + columns)
            col_combo.setCurrentText(ob["col"])
            col_combo.setFixedWidth(120)
            col_combo.currentTextChanged.connect(lambda val, i=idx: self._on_orderby_col_changed(i, val))
            # ASC/DESC icon buttons
            up_icon_path = get_asset_path("icons/up_alt.svg")
            down_icon_path = get_asset_path("icons/down_alt.svg")
            asc_btn = QPushButton()
            asc_btn.setIcon(QIcon(up_icon_path))
            asc_btn.setCheckable(True)
            asc_btn.setChecked(ob["dir"] == "ASC")
            asc_btn.setFixedSize(32, 32)
            asc_btn.setStyleSheet('QPushButton { background: #f5f5f5; border: 1px solid #ccc; border-radius: 4px; margin-right: 2px; } QPushButton:checked { background: #2a9b8e; color: #fff; border: 1px solid #2a9b8e; }')
            asc_btn.clicked.connect(lambda checked, i=idx: self._on_orderby_dir_icon_clicked(i, "ASC"))
            desc_btn = QPushButton()
            desc_btn.setIcon(QIcon(down_icon_path))
            desc_btn.setCheckable(True)
            desc_btn.setChecked(ob["dir"] == "DESC")
            desc_btn.setFixedSize(32, 32)
            desc_btn.setStyleSheet('QPushButton { background: #f5f5f5; border: 1px solid #ccc; border-radius: 4px; margin-left: 2px; } QPushButton:checked { background: #2a9b8e; color: #fff; border: 1px solid #2a9b8e; }')
            desc_btn.clicked.connect(lambda checked, i=idx: self._on_orderby_dir_icon_clicked(i, "DESC"))
            remove_btn = self._make_remove_button(lambda _, i=idx: self._remove_orderby_row(i))
            row.addWidget(col_combo)
            row.addWidget(asc_btn)
            row.addWidget(desc_btn)
            row.addWidget(remove_btn)
            self.orderby_rows_layout.addLayout(row)

    def _add_orderby_row(self):
        self.order_by.append({"col": "", "dir": "ASC"})
        self._refresh_orderby_rows()
        self._generate_and_preview_query()

    def _remove_orderby_row(self, idx):
        if len(self.order_by) > 1:
            self.order_by.pop(idx)
            self._refresh_orderby_rows()
            self._generate_and_preview_query()

    def _on_orderby_col_changed(self, idx, val):
        self.order_by[idx]["col"] = val
        self._refresh_orderby_rows()
        self._generate_and_preview_query()

    def _on_orderby_dir_icon_clicked(self, idx, direction):
        self.order_by[idx]["dir"] = direction
        self._refresh_orderby_rows()
        self._generate_and_preview_query()

    # --- Limit Section ---
    def _on_limit_changed(self, val):
        self.limit = val
        self._generate_and_preview_query()

    # --- SQL Generation ---
    def _generate_and_preview_query(self):
        table = self.from_combo.currentText()
        if not table:
            self.sql_preview.setText("-- Please select a table --")
            return
        # SELECT clause
        select_clauses = []
        for colinfo in self.selected_columns:
            col = colinfo["col"]
            op = colinfo["op"]
            alias = colinfo["alias"]
            if not col:
                continue
            expr = f'{op}({col})' if op else col
            if alias:
                expr += f' AS {alias}'
            select_clauses.append(expr)
        select_str = ', '.join(select_clauses) if select_clauses else '*'
        query = f"SELECT {select_str}\nFROM {table}"
        # WHERE
        where_clauses = []
        for filt in self.filters:
            col, op, val = filt["col"], filt["op"], filt["val"]
            if not col or not op:
                continue
            if op in ('IS NOT NULL', 'IS NULL'):
                where_clauses.append(f"{col} {op}")
            elif val:
                if op == 'IN':
                    val_str = f"({val})"
                else:
                    try:
                        float(val)
                        val_str = val
                    except ValueError:
                        val_str = "'" + val.replace("'", "''") + "'"
                where_clauses.append(f"{col} {op} {val_str}")
        if where_clauses:
            query += "\nWHERE " + "\n  AND ".join(where_clauses)
        # GROUP BY
        groupby_cols = [col for col in self.group_by if col]
        if groupby_cols:
            query += f"\nGROUP BY {', '.join(groupby_cols)}"
        # ORDER BY
        orderby_clauses = [f'{ob["col"]} {ob["dir"]}' for ob in self.order_by if ob["col"]]
        if orderby_clauses:
            query += f"\nORDER BY {', '.join(orderby_clauses)}"
        # LIMIT
        if self.limit.strip().isdigit():
            query += f"\nLIMIT {self.limit.strip()}"
        self.sql_preview.setText(query)

    def _run_query(self):
        query = self.sql_preview.toPlainText()
        if not query or "--" in query or not self.conn:
            return
        self.results_model.clear()
        try:
            cursor = self.conn.cursor()
            cursor.execute(query)
            if cursor.description:
                headers = [desc[0] for desc in cursor.description]
                self.results_model.setHorizontalHeaderLabels(headers)
            else:
                self.results_model.setHorizontalHeaderLabels(["Status"])
            for row_data in cursor.fetchall():
                row_items = [QStandardItem(str(item)) for item in row_data]
                self.results_model.appendRow(row_items)
            header_item = self.results_model.horizontalHeaderItem(0)
            if self.results_model.rowCount() == 0:
                if self.results_model.columnCount() == 1 and header_item is not None and header_item.text() == "Status":
                    self.results_model.appendRow([QStandardItem("Query executed successfully, no data returned.")])
        except Exception as e:
            self.results_model.clear()
            self.results_model.setHorizontalHeaderLabels(["Error"])
            error_item = QStandardItem(f"An error occurred:\n{e}")
            self.results_model.appendRow([error_item])
            print(f"Query Error: {e}")

    def closeEvent(self, event):
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
        super().closeEvent(event) 