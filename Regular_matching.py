# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IContextMenuFactory
from javax.swing import JMenuItem, JPanel, JTextField, JButton, BoxLayout, JTextArea, JScrollPane, JSplitPane
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

        # 匹配结果初始化
        self.matches = []
        self.raw_response = ""

    def createMenuItems(self, invocation):
        menu_items = []

        # 创建右键菜单项
        item = JMenuItem("Save Matching Strings", actionPerformed=lambda x: self.show_matching_strings(invocation))
        menu_items.append(item)

        item = JMenuItem("Show Full Response", actionPerformed=lambda x: self.show_full_response(invocation))
        menu_items.append(item)

        return menu_items

    def show_matching_strings(self, invocation):
        # 获取响应信息
        response = invocation.getSelectedMessages()[0].getResponse()

        # 使用正则匹配所有字符
        raw_response = self._helpers.bytesToString(response)
        self.matches = re.findall(self.regex, raw_response)

        # 将匹配结果显示到UI中
        self.update_ui_with_matches()

    def show_full_response(self, invocation):
        # 获取响应信息
        response = invocation.getSelectedMessages()[0].getResponse()

        # 提取原始响应内容
        self.raw_response = self._helpers.bytesToString(response)

        # 将原始响应内容显示到UI中
        self.update_ui_with_full_response()

    def update_ui_with_matches(self):
        # 将匹配结果显示在界面上
        if self.matches:
            matches_text = "\n".join(self.matches)
            self.matching_result_text_area.setText(matches_text)
        else:
            self.matching_result_text_area.setText("No matches found.")

    def update_ui_with_full_response(self):
        # 将完整的响应内容显示到界面上
        self.full_response_text_area.setText(self.raw_response)

    def save_matching_strings(self, event):
        # 将匹配的字符保存到文件
        if self.matches:
            with open(self.save_path, 'a') as f:
                for match in self.matches:
                    f.write(match + "\n")

            self._stdout.write("Saved {} matches to {}\n".format(len(self.matches), self.save_path))
        else:
            self._stdout.write("No matches to save.\n")

    def create_regex_ui(self, callbacks):
        # 创建一个主面板
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))  # 横向布局

        # 创建一个面板来放置按钮（Update Regex 和 Update Path）
        left_panel = JPanel()
        left_panel.setLayout(BoxLayout(left_panel, BoxLayout.Y_AXIS))  # 垂直布局

        # 创建按钮来更新正则表达式
        self.regex_input = JTextField(self.regex, 20)
        left_panel.add(self.regex_input)

        # 创建按钮来更新正则表达式
        regex_button = JButton("Update Regex", actionPerformed=self.update_regex)
        left_panel.add(regex_button)

        # 创建文本框来输入保存路径
        self.save_path_input = JTextField(self.save_path, 20)
        left_panel.add(self.save_path_input)

        # 创建按钮来更新保存路径
        path_button = JButton("Update Path", actionPerformed=self.update_save_path)
        left_panel.add(path_button)

        # 创建一个分割面板，左边为按钮区域，右边为显示区域
        right_panel = JPanel()
        right_panel.setLayout(BoxLayout(right_panel, BoxLayout.Y_AXIS))  # 垂直布局

        # 创建文本区域来显示响应的原始内容
        self.full_response_text_area = JTextArea(10, 20)
        self.full_response_text_area.setEditable(False)
        scroll_pane_full_response = JScrollPane(self.full_response_text_area)
        right_panel.add(scroll_pane_full_response)

        # 在响应内容文本框下方增加一个新的功能按钮
        additional_button = JButton("Clear Response", actionPerformed=self.clear_response)
        right_panel.add(additional_button)

        # 新增一个按钮，用来执行正则匹配分析
        execute_button = JButton("Execute Regex Match", actionPerformed=self.execute_regex_match)
        right_panel.add(execute_button)

        # 创建文本区域来显示匹配的字符串
        self.matching_result_text_area = JTextArea(10, 20)
        self.matching_result_text_area.setEditable(False)
        scroll_pane_matches = JScrollPane(self.matching_result_text_area)
        right_panel.add(scroll_pane_matches)


        # 创建保存按钮
        save_button = JButton("Save Matches", actionPerformed=self.save_matching_strings)
        right_panel.add(save_button)

        # 使用分割面板来显示左右区域
        split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left_panel, right_panel)
        split_pane.setDividerLocation(300)  # 设置分割条位置

        # 将面板添加到 Burp Suite 窗口的 UI
        callbacks.addSuiteTab(RegexTab(split_pane))

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

    def clear_response(self, event):
        # 清空响应内容文本框
        self.full_response_text_area.setText("")
        self._stdout.write("Response cleared.\n")

    def execute_regex_match(self, event):
        # 执行正则匹配分析
        if self.raw_response:
            self.matches = re.findall(self.regex, self.raw_response)
            # 更新匹配结果显示
            self.update_ui_with_matches()
        else:
            self._stdout.write("No response to analyze.\n")

class RegexTab(ITab):
    def __init__(self, panel):
        self.panel = panel

    def getTabCaption(self):
        return "Regex Settings"

    def getUiComponent(self):
        return self.panel
