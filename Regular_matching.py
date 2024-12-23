# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IContextMenuFactory
from javax.swing import JMenuItem, JPanel, JTextField, JButton, BoxLayout
from burp import ITab
import re
import os

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = callbacks.getStdout()

        # 设置扩展名
        callbacks.setExtensionName("Regex Response Extractor")

        # 注册右键菜单
        callbacks.registerContextMenuFactory(self)

        # 默认保存路径和文件名
        self.save_path = "extracted_responses.txt"

        # 默认正则表达式
        self.regex = r"your_regular_expression_here"

        # 创建设置正则表达式和保存路径的UI组件
        self.create_regex_ui(callbacks)

    def createMenuItems(self, invocation):
        menu_items = []

        # 创建右键菜单项
        item = JMenuItem("Save Matching Strings", actionPerformed=lambda x: self.save_matching_strings(invocation))
        menu_items.append(item)

        return menu_items

    def save_matching_strings(self, invocation):
        # 获取响应信息
        response = invocation.getSelectedMessages()[0].getResponse()

        # 使用正则匹配所有字符
        matches = re.findall(self.regex, self._helpers.bytesToString(response))

        # 将匹配的字符保存到文件
        if matches:
            with open(self.save_path, 'a') as f:
                for match in matches:
                    f.write(match + "\n")

            self._stdout.write("Saved {} matches to {}\n".format(len(matches), self.save_path))
        else:
            self._stdout.write("No matches found\n")

    def create_regex_ui(self, callbacks):
        # 创建一个面板来显示正则表达式的输入框
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        # 创建文本框来输入正则表达式
        self.regex_input = JTextField(self.regex, 20)
        panel.add(self.regex_input)

        # 创建按钮来更新正则表达式
        regex_button = JButton("Update Regex", actionPerformed=self.update_regex)
        panel.add(regex_button)

        # 创建文本框来输入保存路径
        self.save_path_input = JTextField(self.save_path, 20)
        panel.add(self.save_path_input)

        # 创建按钮来更新保存路径
        path_button = JButton("Update Path", actionPerformed=self.update_save_path)
        panel.add(path_button)

        # 将面板添加到 Burp Suite 窗口的 UI
        callbacks.addSuiteTab(RegexTab(panel))

    def update_regex(self, event):
        # 获取并转义正则表达式
        raw_regex = self.regex_input.getText()
        self.regex = self.escape_special_characters(raw_regex)
        self._stdout.write("Regex updated to: {}\n".format(self.regex))

    def escape_special_characters(self, raw_regex):
        # 转义特殊字符
        special_chars = ["'", '"']
        for char in special_chars:
            raw_regex = raw_regex.replace(char, '\\' + char)
        return raw_regex

    def update_save_path(self, event):
        # 更新保存路径
        new_path = self.save_path_input.getText()

        # 确保文件夹存在
        folder = os.path.dirname(new_path)
        if folder and not os.path.exists(folder):
            os.makedirs(folder)

        self.save_path = new_path
        self.save_path_input.setText(self.save_path)
        self._stdout.write("Save path updated to: {}\n".format(self.save_path))


class RegexTab(ITab):
    def __init__(self, panel):
        self.panel = panel

    def getTabCaption(self):
        return "Regex Settings"

    def getUiComponent(self):
        return self.panel
