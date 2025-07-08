from PyQt6.QtWidgets import QFrame, QWidget, QLabel, QHBoxLayout
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon

class SidebarFrame(QFrame):
    pass

class SidebarNavButton(QWidget):
    def __init__(self, icon: QIcon, text: str, parent=None):
        super().__init__(parent)
        self.icon_label = QLabel()
        self.icon_label.setPixmap(icon.pixmap(28, 28))
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        self.text_label = QLabel(text)
        self.text_label.setStyleSheet("color: #fff; font-size: 14px; padding-left: 12px;")
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(12, 0, 0, 0)  # Fixed left margin for icon
        self._layout.setSpacing(0)
        self._layout.addWidget(self.icon_label, 0, Qt.AlignmentFlag.AlignLeft)
        # Do not add text_label yet; will be managed by update_state
        self.setFixedSize(48, 48)
        self.setStyleSheet("background: transparent; border-radius: 5px;")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self._checked = False
        self._collapsed = True
        self.button_group = None  # Will be set by NavButtonGroup
        self._text = text  # Store for re-adding
        self.update_state()
    def setChecked(self, checked: bool):
        self._checked = checked
        self.update_state()
    def isChecked(self):
        return self._checked
    def setCollapsed(self, collapsed: bool):
        self._collapsed = collapsed
        self.update_state()
    def update_state(self):
        # Remove text_label from layout if present
        if self.text_label.parent() is self:
            self._layout.removeWidget(self.text_label)
            self.text_label.hide()
        if self._collapsed:
            self.setFixedSize(48, 48)
            self.icon_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            if self._checked:
                self.setStyleSheet("background: #2a9b8e; border-radius: 5px;")
            else:
                self.setStyleSheet("background: transparent; border-radius: 5px;")
        else:
            # Add text_label to layout if not present
            if self.text_label.parent() is not self:
                self.text_label.setParent(self)
            self._layout.addWidget(self.text_label, 1)
            self.text_label.show()
            self.setMinimumWidth(160)
            self.setMaximumWidth(16777215)
            self.setFixedHeight(48)
            self.icon_label.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            if self._checked:
                self.setStyleSheet("background: #2a9b8e; border-radius: 5px;")
            else:
                self.setStyleSheet("background: transparent; border-radius: 5px;")
    def mousePressEvent(self, event):
        self.setChecked(True)
        if self.button_group is not None:
            self.button_group.buttonClicked.emit(self)
        super().mousePressEvent(event) 