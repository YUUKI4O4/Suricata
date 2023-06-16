# -*- coding:utf-8 -*-
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QLineEdit, QPushButton, QComboBox, QTextEdit
from PyQt5.QtGui import QClipboard  # 导入QClipboard模块，用于复制文本到剪贴板

def generate_suricata_rule():
    sid = sid_entry.text()
    reference = reference_entry.text()
    level = level_combo.currentText()  # 修正变量名为 level_combo
    sugg = sugg_entry.text()
    influence = influence_entry.text()
    cve = cve_entry.text()
    desc = desc_entry.text()

    rule_json = f'"{sid}": {{\n        "reference": "{reference}",\n        "level": "{level}",\n        "sugg": "{sugg}",\n        "influence": "{influence}",\n        "cve": "{cve}",\n        "desc": "{desc}"\n    }},'
    result_text.setPlainText(rule_json)  # 修正变量名为 rule_json

def copy_rule():
    clipboard = QApplication.clipboard()  # 获取剪贴板对象
    clipboard.setText(result_text.toPlainText())  # 将结果文本框中的内容复制到剪贴板中

app = QApplication([])  # 创建应用程序对象
window = QWidget()  # 创建窗口对象
window.setWindowTitle("Suricata Rule Generator")  # 设置窗口标题

layout = QVBoxLayout()  # 创建垂直布局对象

sid_label = QLabel("规则ID: ")
layout.addWidget(sid_label)
sid_entry = QLineEdit()
layout.addWidget(sid_entry)

reference_label = QLabel("参考链接: ")
layout.addWidget(reference_label)
reference_entry = QLineEdit()
layout.addWidget(reference_entry)

level_label = QLabel("威胁等级: ")
layout.addWidget(level_label)
level_combo = QComboBox()
level_combo.addItems(["高危", "中危", "低危"])
layout.addWidget(level_combo)

sugg_label = QLabel("处置意见: ")
layout.addWidget(sugg_label)
sugg_entry = QLineEdit()
layout.addWidget(sugg_entry)

influence_label = QLabel("影响版本: ")
layout.addWidget(influence_label)
influence_entry = QLineEdit()
layout.addWidget(influence_entry)

cve_label = QLabel("CVE编号: ")
layout.addWidget(cve_label)
cve_entry = QLineEdit()
layout.addWidget(cve_entry)

desc_label = QLabel("漏洞描述: ")
layout.addWidget(desc_label)
desc_entry = QLineEdit()
layout.addWidget(desc_entry)

generate_button = QPushButton("生成规则json")  # 创建按钮对象
generate_button.clicked.connect(generate_suricata_rule)  # 将按钮的点击事件连接到生成规则函数
layout.addWidget(generate_button)  # 将按钮添加到布局中

copy_button = QPushButton("复制规则json")  # 创建按钮对象
copy_button.clicked.connect(copy_rule)  # 将按钮的点击事件连接到复制规则函数
layout.addWidget(copy_button)  # 将按钮添加到布局中

result_text = QTextEdit()  # 创建多行文本框对象
result_text.setReadOnly(True)  # 设置文本框为只读模式
layout.addWidget(result_text)  # 将文本框添加到布局中

window.setLayout(layout)
window.show()
app.exec_()
