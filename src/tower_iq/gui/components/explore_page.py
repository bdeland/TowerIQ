import os
import sqlite3
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QComboBox, QPushButton, QLabel, QLineEdit,
    QTextEdit, QTableView, QHeaderView, QAbstractItemView, QMessageBox, QScrollArea, QFrame
)
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QIcon
from PyQt6.QtCore import Qt
from tower_iq.gui.assets import get_asset_path

class ExplorePage(QWidget):
    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '../../data/toweriq.sqlite')
        self.db_path = os.path.normpath(self.db_path)
        self.conn = None
        self.db_schema = {}
        self.where_clause_widgets = []
        self._init_db()
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

    def _init_ui(self):
        self.main_layout = QVBoxLayout(self)
        builder_layout = QFormLayout()
        builder_layout.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        self.from_combo = QComboBox()
        builder_layout.addRow(QLabel("FROM:"), self.from_combo)
        # SELECT area: dynamic buttons for columns
        self.select_buttons_layout = QHBoxLayout()
        self.select_buttons_frame = QFrame()
        self.select_buttons_frame.setLayout(self.select_buttons_layout)
        self.select_buttons_frame.setStyleSheet("background: #001219; border-radius: 5px; padding: 4px;")
        builder_layout.addRow(QLabel("SELECT:"), self.select_buttons_frame)
        self.selected_columns = set()
        # WHERE area: header + add button + group
        self.where_layout = QVBoxLayout()
        where_label = QLabel("WHERE")
        where_label.setStyleSheet("color: #fff; font-weight: bold; font-size: 15px;")
        where_header_layout = QHBoxLayout()
        where_header_layout.addWidget(where_label)
        where_header_layout.addStretch()
        self.where_layout.addLayout(where_header_layout)
        self.where_clauses_group = QVBoxLayout()
        self.where_layout.addLayout(self.where_clauses_group)
        # Add button below WHERE header, initially
        icon_path = get_asset_path("icons/add.svg")
        self.add_where_button = QPushButton()
        self.add_where_button.setIcon(QIcon(icon_path))
        self.add_where_button.setToolTip('Add WHERE Clause')
        self.add_where_button.setFixedSize(28, 28)
        self.add_where_button.setStyleSheet('QPushButton { background: transparent; border: none; } QPushButton:hover { background: #2a9b8e; }')
        self.add_where_button.clicked.connect(self._add_where_clause)
        self.where_layout.addWidget(self.add_where_button)
        builder_layout.addRow(self.where_layout)
        # GROUP BY area: dynamic buttons
        self.groupby_buttons_layout = QHBoxLayout()
        self.groupby_buttons_frame = QFrame()
        self.groupby_buttons_frame.setLayout(self.groupby_buttons_layout)
        self.groupby_buttons_frame.setStyleSheet("background: #001219; border-radius: 5px; padding: 4px;")
        builder_layout.addRow(QLabel("GROUP BY:"), self.groupby_buttons_frame)
        self.selected_groupby = set()
        # ORDER BY area: dynamic buttons
        self.orderby_buttons_layout = QHBoxLayout()
        self.orderby_buttons_frame = QFrame()
        self.orderby_buttons_frame.setLayout(self.orderby_buttons_layout)
        self.orderby_buttons_frame.setStyleSheet("background: #001219; border-radius: 5px; padding: 4px;")
        builder_layout.addRow(QLabel("ORDER BY:"), self.orderby_buttons_frame)
        self.selected_orderby = set()
        self.limit_edit = QLineEdit()
        self.limit_edit.setPlaceholderText("e.g., 100")
        builder_layout.addRow(QLabel("LIMIT:"), self.limit_edit)
        self.main_layout.addLayout(builder_layout)
        self.main_layout.addWidget(QLabel("Generated SQL Query:"))
        self.sql_preview = QTextEdit()
        self.sql_preview.setReadOnly(True)
        self.sql_preview.setFixedHeight(100)
        self.sql_preview.setStyleSheet("background-color: #f0f0f0; font-family: 'Courier New';")
        self.main_layout.addWidget(self.sql_preview)
        run_query_button = QPushButton("Run Query")
        run_query_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        run_query_button.clicked.connect(self._run_query)
        self.main_layout.addWidget(run_query_button)
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

    def _update_ui_from_schema(self):
        self.from_combo.clear()
        self.from_combo.addItems(self.db_schema.keys())
        if self.from_combo.count() > 0:
            self._on_table_changed()

    def _connect_signals(self):
        self.from_combo.currentIndexChanged.connect(self._on_table_changed)

    def _on_table_changed(self):
        self._clear_all_where_clauses()
        self._populate_select_buttons()
        self._generate_and_preview_query()

    def _populate_select_buttons(self):
        # Remove old buttons
        while self.select_buttons_layout.count():
            item = self.select_buttons_layout.takeAt(0)
            if item is not None:
                btn = item.widget()
                if btn:
                    btn.deleteLater()
        self.selected_columns.clear()
        # Remove old group by buttons
        while self.groupby_buttons_layout.count():
            item = self.groupby_buttons_layout.takeAt(0)
            if item is not None:
                btn = item.widget()
                if btn:
                    btn.deleteLater()
        self.selected_groupby.clear()
        # Remove old order by buttons
        while self.orderby_buttons_layout.count():
            item = self.orderby_buttons_layout.takeAt(0)
            if item is not None:
                btn = item.widget()
                if btn:
                    btn.deleteLater()
        self.selected_orderby.clear()
        table = self.from_combo.currentText()
        columns = self.db_schema.get(table, [])
        button_style = (
            "QPushButton { background: #00303d; color: #fff; border: 1px solid #2a9b8e; border-radius: 4px; margin: 2px; padding: 4px 8px; } "
            "QPushButton:checked { background: #2a9b8e; color: #fff; border: 1px solid #fff; } "
            "QPushButton:hover { background: #014f5c; }"
        )
        # Add 'All' button
        self._select_all_btn = QPushButton('All')
        self._select_all_btn.setCheckable(True)
        self._select_all_btn.setStyleSheet(button_style)
        self._select_all_btn.clicked.connect(self._on_select_all_toggled)
        self.select_buttons_layout.addWidget(self._select_all_btn)
        self._select_column_btns = {}
        for col in columns:
            btn = QPushButton(col)
            btn.setCheckable(True)
            btn.setStyleSheet(button_style)
            btn.clicked.connect(lambda checked, c=col: self._on_select_column_toggled(c, checked))
            self.select_buttons_layout.addWidget(btn)
            self._select_column_btns[col] = btn
        self.select_buttons_layout.addStretch()
        self._update_select_all_btn_state()
        self._update_where_column_options()

    def _on_select_all_toggled(self, checked):
        # If checked, select all columns; if unchecked, deselect all
        for col, btn in self._select_column_btns.items():
            btn.blockSignals(True)
            btn.setChecked(checked)
            btn.blockSignals(False)
            if checked:
                self.selected_columns.add(col)
            else:
                self.selected_columns.discard(col)
        self._update_select_all_btn_state()
        self._update_where_column_options()
        self._generate_and_preview_query()

    def _on_select_column_toggled(self, column, checked):
        if checked:
            self.selected_columns.add(column)
        else:
            self.selected_columns.discard(column)
        self._update_select_all_btn_state()
        self._update_where_column_options()
        self._generate_and_preview_query()

    def _update_select_all_btn_state(self):
        # Set the 'All' button checked if all columns are selected, unchecked otherwise
        all_selected = len(self.selected_columns) == len(self._select_column_btns)
        self._select_all_btn.blockSignals(True)
        self._select_all_btn.setChecked(all_selected)
        self._select_all_btn.blockSignals(False)

    def _on_groupby_column_toggled(self, column, checked):
        if checked:
            self.selected_groupby.add(column)
        else:
            self.selected_groupby.discard(column)
        self._generate_and_preview_query()

    def _on_orderby_column_toggled(self, column, checked):
        if checked:
            self.selected_orderby.add(column)
        else:
            self.selected_orderby.discard(column)
        self._generate_and_preview_query()

    def _add_where_clause(self):
        table = self.from_combo.currentText()
        # Only allow columns currently selected in SELECT, or all if SELECT is *
        if self.selected_columns:
            available_columns = list(self.selected_columns)
        else:
            available_columns = self.db_schema.get(table, [])
        if not table or not available_columns:
            return
        clause_layout = QHBoxLayout()
        # Always use the close (remove) icon for remove button
        remove_icon_path = get_asset_path("icons/close.svg")
        remove_button = QPushButton()
        remove_button.setIcon(QIcon(remove_icon_path))
        remove_button.setToolTip('Remove')
        remove_button.setFixedSize(28, 28)
        remove_button.setStyleSheet('QPushButton { background: transparent; border: none; } QPushButton:hover { background: #2a9b8e; }')
        column_combo = QComboBox()
        column_combo.addItems(available_columns)
        operator_combo = QComboBox()
        operators = ['=', '!=', '>', '<', '>=', '<=', 'LIKE', 'IN', 'IS NOT NULL', 'IS NULL']
        operator_combo.addItems(operators)
        value_edit = QLineEdit()
        clause_widgets = {
            "layout": clause_layout,
            "column": column_combo,
            "operator": operator_combo,
            "value": value_edit,
            "remove_button": remove_button,
            "add_button": None,
            "add_row": None
        }
        self.where_clause_widgets.append(clause_widgets)
        column_combo.currentIndexChanged.connect(self._generate_and_preview_query)
        operator_combo.currentIndexChanged.connect(self._generate_and_preview_query)
        value_edit.textChanged.connect(self._generate_and_preview_query)
        remove_button.clicked.connect(lambda: self._remove_where_clause(clause_widgets))
        clause_layout.addWidget(remove_button)
        clause_layout.addWidget(column_combo)
        clause_layout.addWidget(operator_combo)
        clause_layout.addWidget(value_edit)
        self.where_clauses_group.addLayout(clause_layout)
        self._update_where_add_buttons()
        self._generate_and_preview_query()

    def _remove_where_clause(self, clause_to_remove):
        if clause_to_remove in self.where_clause_widgets:
            for i in range(clause_to_remove["layout"].count()):
                widget = clause_to_remove["layout"].itemAt(i).widget()
                if widget:
                    widget.deleteLater()
            # Remove add_row if present
            if "add_row" in clause_to_remove and clause_to_remove["add_row"] is not None:
                self.where_clauses_group.removeItem(clause_to_remove["add_row"])
                clause_to_remove["add_row"] = None
            self.where_clauses_group.removeItem(clause_to_remove["layout"])
            clause_to_remove["layout"].deleteLater()
            self.where_clause_widgets.remove(clause_to_remove)
            self._update_where_add_buttons()
            self._generate_and_preview_query()

    def _clear_all_where_clauses(self):
        for clause in reversed(self.where_clause_widgets):
            self._remove_where_clause(clause)

    def _generate_and_preview_query(self):
        table = self.from_combo.currentText()
        if not table:
            self.sql_preview.setText("-- Please select a table --")
            return
        # SELECT clause from selected columns
        if self.selected_columns:
            select_cols = ', '.join(self.selected_columns)
        else:
            select_cols = '*'
        query = f"SELECT {select_cols}\nFROM {table}"
        where_clauses = []
        for clause in self.where_clause_widgets:
            col = clause["column"].currentText()
            op = clause["operator"].currentText()
            val = clause["value"].text()
            if not col or not op: continue
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
        # GROUP BY clause
        if self.selected_groupby:
            query += f"\nGROUP BY {', '.join(self.selected_groupby)}"
        # ORDER BY clause
        if self.selected_orderby:
            query += f"\nORDER BY {', '.join(self.selected_orderby)}"
        if self.limit_edit.text().strip().isdigit():
            query += f"\nLIMIT {self.limit_edit.text().strip()}"
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

    def _update_where_column_options(self):
        # Update all WHERE column dropdowns to only show currently selected columns (or all if SELECT is *)
        table = self.from_combo.currentText()
        if self.selected_columns:
            available_columns = list(self.selected_columns)
        else:
            available_columns = self.db_schema.get(table, [])
        for clause in self.where_clause_widgets:
            current = clause["column"].currentText()
            clause["column"].blockSignals(True)
            clause["column"].clear()
            clause["column"].addItems(available_columns)
            # If the previously selected column is still available, keep it selected
            if current in available_columns:
                clause["column"].setCurrentText(current)
            else:
                clause["column"].setCurrentIndex(0)
            clause["column"].blockSignals(False)

    def _update_where_add_buttons(self):
        # Remove the add_where_button from its current parent/layout if present
        self.add_where_button.setParent(None)
        # Remove any lingering add_row layouts from clause widgets
        for clause in self.where_clause_widgets:
            if clause["add_row"] is not None:
                self.where_clauses_group.removeItem(clause["add_row"])
                clause["add_row"] = None
            clause["add_button"] = None
        # Place the add_where_button after the last WHERE clause, or below header if none
        if self.where_clause_widgets:
            # Add a new row (QHBoxLayout) after the last clause, containing the add_where_button
            last_clause = self.where_clause_widgets[-1]
            add_row = QHBoxLayout()
            add_row.setContentsMargins(0, 0, 0, 0)
            add_row.setSpacing(0)
            add_row.addWidget(self.add_where_button)
            add_row.addStretch()
            self.where_clauses_group.addLayout(add_row)
            last_clause["add_row"] = add_row
            last_clause["add_button"] = self.add_where_button
        else:
            # Add the add_where_button below the WHERE header (at the end of where_layout)
            self.where_layout.addWidget(self.add_where_button)

    def closeEvent(self, event):
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
        super().closeEvent(event) 