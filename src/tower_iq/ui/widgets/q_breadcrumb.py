from PyQt6.QtWidgets import QWidget, QHBoxLayout, QPushButton, QLabel, QSpacerItem, QSizePolicy
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import pyqtSignal, QSize, Qt

class QBreadCrumb(QWidget):
    crumb_clicked = pyqtSignal(str)

    def __init__(self, parent=None, separator_type: str = 'text', separator_value: str = '>'):
        super().__init__(parent)
        self._separator_type = separator_type
        self._separator_value = separator_value
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(8)
        self._spacer = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        self._layout.addSpacerItem(self._spacer)

    def set_path(self, path_segments):
        # Remove all widgets except the spacer
        while self._layout.count() > 1:
            item = self._layout.takeAt(0)
            if item is not None and hasattr(item, 'widget'):
                widget = item.widget()
                if widget is not None:
                    widget.deleteLater()
            # If it's not a widget (e.g., a spacer), just continue
        
        for i, segment in enumerate(path_segments):
            if i > 0:
                separator = QLabel()
                if self._separator_type == 'icon':
                    pixmap = QPixmap(self._separator_value)
                    if not pixmap.isNull():
                        separator.setPixmap(pixmap.scaled(QSize(16, 16), Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
                else:
                    separator.setText(self._separator_value)
                separator.setObjectName("breadcrumbSeparator")
                self._layout.insertWidget(self._layout.count() - 1, separator)

            text, identifier, crumb_type = segment
            if crumb_type == 'link':
                crumb_widget = QPushButton(text)
                crumb_widget.setFlat(True)
                crumb_widget.setObjectName("breadcrumbLink")
                if identifier is not None:
                    crumb_widget.clicked.connect(lambda checked, ident=identifier: self.crumb_clicked.emit(ident))
            elif crumb_type == 'button':
                crumb_widget = QPushButton(text)
                crumb_widget.setObjectName("breadcrumbButton")
                if identifier is not None:
                    crumb_widget.clicked.connect(lambda checked, ident=identifier: self.crumb_clicked.emit(ident))
            else:
                crumb_widget = QLabel(text)
                crumb_widget.setObjectName("currentCrumb")
            self._layout.insertWidget(self._layout.count() - 1, crumb_widget) 