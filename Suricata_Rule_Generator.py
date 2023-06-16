# -*- coding:utf-8 -*-
from datetime import datetime  # 导入datetime模块，用于获取当前时间
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QLineEdit, QPushButton, QComboBox, QTextEdit
from PyQt5.QtGui import QClipboard  # 导入QClipboard模块，用于复制文本到剪贴板

def generate_suricata_rule():
    protocol = protocol_combo.currentText()  # 获取协议下拉列表的选中项
    msg = msg_entry.text()  # 获取规则描述信息文本框的内容
    flow = flow_combo.currentText()  # 获取流量方向下拉列表的选中项
    a = flowbits_entry.text()  # 获取flowbits文本框的内容
    flowbits = "flowbits:"+a+";" if a.strip() else ""  # 根据flowbits是否为空，生成相应的字符串
    b = reference_url_entry.text()  # 获取参考链接文本框的内容
    reference_url = "reference:url,"+b+"; " if b.strip() else ""  # 根据参考链接是否为空，生成相应的字符串
    c = reference_cve_entry.text()  # 获取CVE编号文本框的内容
    reference_cve = "reference:cve,"+c+"; " if c.strip() else ""  # 根据CVE编号是否为空，生成相应的字符串
    classtype = classtype_combo.currentText()  # 获取规则分类下拉列表的选中项
    attack_result = attack_result_combo.currentText()  # 获取攻击成功判定下拉列表的选中项
    affected_product = affected_product_entry.text()  # 获取受影响的产品文本框的内容
    severity = severity_combo.currentText()  # 获取威胁等级下拉列表的选中项
    d = default_disable_combo.currentText()  # 获取是否设置默认关闭下拉列表的选中项
    default_disabl = ",default_disable=YUUKI4O4 " if d == "1" else ""  # 根据是否设置默认关闭生成相应的字符串
    sid = sid_entry.text()  # 获取SID（规则ID）文本框的内容

    current_datetime = datetime.now()  # 获取当前时间
    year = current_datetime.year  # 获取当前年份
    month = current_datetime.month  # 获取当前月份
    day = current_datetime.day  # 获取当前日期

    rule = f"alert {protocol} any any -> any any (msg:\"{msg}\"; flow:established,{flow}; {flowbits} \n\n# ... 此处添加需要检测的特征字段 ...\n\n{reference_url}{reference_cve}classtype:{classtype}; metadata:attack_result={attack_result},affected_product={affected_product},victim=dst_ip,attacker=src_ip,severity={severity},created_at {year}-{month:02d}-{day:02d}, updated_at {year}-{month:02d}-{day:02d},creater:YUUKI4O4 {default_disabl}; sid:{sid}; rev:1;)"
    result_text.setPlainText(rule)  # 在结果文本框中显示生成的规则

def copy_rule():
    clipboard = QApplication.clipboard()  # 获取剪贴板对象
    clipboard.setText(result_text.toPlainText())  # 将结果文本框中的内容复制到剪贴板中

app = QApplication([])  # 创建应用程序对象
window = QWidget()  # 创建窗口对象
window.setWindowTitle("Suricata Rule Generator")  # 设置窗口标题

layout = QVBoxLayout()  # 创建垂直布局对象
# ... 添加控件和布局 ...
protocol_label = QLabel("协议:")  # 创建标签对象
layout.addWidget(protocol_label)  # 将标签添加到布局中
protocol_combo = QComboBox()  # 创建下拉列表对象
protocol_combo.addItems(["http", "tcp", "udp", "icmp", "dns", "smb"])  # 添加选项到下拉列表
layout.addWidget(protocol_combo)  # 将下拉列表添加到布局中

msg_label = QLabel("规则描述信息:")
layout.addWidget(msg_label)
msg_entry = QLineEdit()
layout.addWidget(msg_entry)

flow_label = QLabel("流量方向:")
layout.addWidget(flow_label)
flow_combo = QComboBox()  # 使用下拉列表 QComboBox
flow_combo.addItems(["to_server", "from_server"])
layout.addWidget(flow_combo)

flowbits_label = QLabel("是否使用flowbits，如有请输入前置规则标识（如set,XXXX;noalert或isset,XXXX: ）")
layout.addWidget(flowbits_label)
flowbits_entry = QLineEdit()
layout.addWidget(flowbits_entry)

reference_url_label = QLabel("是否有参考链接，如有请输入参考链接:")
layout.addWidget(reference_url_label)
reference_url_entry = QLineEdit()
layout.addWidget(reference_url_entry)

reference_cve_label = QLabel("是否有CVE编号，如有请输入CVE编号:")
layout.addWidget(reference_cve_label)
reference_cve_entry = QLineEdit()
layout.addWidget(reference_cve_entry)

classtype_label = QLabel("威胁分类:")
layout.addWidget(classtype_label)
classtype_combo = QComboBox()
classtype_combo.addItems(["apt", "shellcode", "web-attack", "cve-exploit", "scan", "dos", "bad-unknown", "attempted-recon", "successful-recon-limited", "attempted-user", "unsuccessful-user", "successful-user", "attempted-admin", "successful-admin"])
layout.addWidget(classtype_combo)

attack_result_label = QLabel("攻击状态判定:")
layout.addWidget(attack_result_label)
attack_result_combo = QComboBox()
attack_result_combo.addItems(["success", "possible success"])
layout.addWidget(attack_result_combo)

affected_product_label = QLabel("受影响的产品:")
layout.addWidget(affected_product_label)
affected_product_entry = QLineEdit()
layout.addWidget(affected_product_entry)

severity_label = QLabel("威胁等级:")
layout.addWidget(severity_label)
severity_combo = QComboBox()
severity_combo.addItems(["high", "middle", "low"])
layout.addWidget(severity_combo)

default_disable_label = QLabel("是否设置默认关闭:")
layout.addWidget(default_disable_label)
default_disable_combo = QComboBox()
default_disable_combo.addItems(["1", "0"])
layout.addWidget(default_disable_combo)

sid_label = QLabel("SID（规则ID）:")
layout.addWidget(sid_label)
sid_entry = QLineEdit()
layout.addWidget(sid_entry)

generate_button = QPushButton("生成规则")  # 创建按钮对象
generate_button.clicked.connect(generate_suricata_rule)  # 将按钮的点击事件连接到生成规则函数
layout.addWidget(generate_button)  # 将按钮添加到布局中

copy_button = QPushButton("复制规则")  # 创建按钮对象
copy_button.clicked.connect(copy_rule)  # 将按钮的点击事件连接到复制规则函数
layout.addWidget(copy_button)  # 将按钮添加到布局中

result_text = QTextEdit()  # 创建多行文本框对象
result_text.setReadOnly(True)  # 设置文本框为只读模式
layout.addWidget(result_text)  # 将文本框添加到布局中

window.setLayout(layout)  # 设置窗口的布局
window.show()  # 显示窗口
app.exec_()  # 启动应用程序的主循环
