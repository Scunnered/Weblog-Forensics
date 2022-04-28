import re
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from pyqt_line_number_widget import LineNumberWidget
from PyQt5.QtGui import QPalette, QColor
import sys
from UI import Ui_MainWindow

class Worker(QObject):
    finished = pyqtSignal()
    emitLine = pyqtSignal(str)

    def __init__(self, fileName):
        super().__init__()
        self.fileName = fileName

    def run(self):
        with open(self.fileName, "r") as fh:
            fstring=fh.readlines()
        for line in fstring:
            self.emitLine.emit(line)
        # print("thread finished")
        self.finished.emit()

class SyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent):
        super(SyntaxHighlighter, self).__init__(parent)
        self._highlight_lines = dict()

    def highlight_line(self, line, fmt):
        if isinstance(line, int) and line >= 0 and isinstance(fmt, QTextCharFormat):
            self._highlight_lines[line] = fmt
            tb = self.document().findBlockByLineNumber(line)
            self.rehighlightBlock(tb)

    def clear_highlight(self):
        self._highlight_lines = dict()
        self.rehighlight()

    def highlightBlock(self, text):
        line = self.currentBlock().blockNumber()
        fmt = self._highlight_lines.get(line)
        if fmt is not None:
            self.setFormat(0, len(text), fmt)

class Window(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.stackedWidget.setCurrentIndex(0)
        ### If deploying comment out
        self.startingCode()
        self.loadedFile = 'Server_Log.txt'
        self.outputLog()
        ###

        self._highlighter = SyntaxHighlighter(self.ui.userSubmitLog.document())

        self.ui.submitResponseButton.clicked.connect(self.initialChoices)
        self.ui.clearButton.clicked.connect(self.clearOutput)
        self.ui.uploadButton.clicked.connect(self.openFileNameDialog)
        self.ui.optionsButton.clicked.connect(self.moveToOptions)
        self.ui.backButton.clicked.connect(self.moveToHome)
        self.ui.actionExit.triggered.connect(self.actionExit)
        self.lineWidget = LineNumberWidget(self.ui.userSubmitLog)
        self.ui.horizontalLayout_5.addWidget(self.lineWidget)
        self.ui.horizontalLayout_5.setAlignment(Qt.AlignTop)
        self.setOptionsText()
    
    def changeHighlight(self, line):
        # print("Highlighting line : " + str(line))
        fmt = QTextCharFormat()
        fmt.setBackground(QColor("yellow"))
        self._highlighter.highlight_line(line, fmt)
    
    def setOptionsText(self):
        self.ui.optionsText.setText("Welcome to the OWASP top ten forensic tool created by Ross Morrison under the supervision of Dr Hatem Ahriz. This project was my RGU end of year project.\nTo search your own weblog, press the upload button on the main GUI. The current weblog presented is an example. \n\nThe weblog needs to be in a .txt format. \n(Some logs may take time to display due to size, multithreading is utilized on program execution which allows for multiple threads to be created.) \nOnce uploaded, the program will display the log on the left side panel. \n\nOn the right side panel, options for OWASP attacks are listed. Type in the corresponding command and press the ""Submit"" button.\nFor instance, if you type “A03-SQL” and hit submit, results will be displayed on the feed regarding the results.\nThe program will return the line and IP address of the suspected log line. \nMultiple checks can be done on the same log if needed.\n\n\nFeatures to add:\nDark mode\nMulti-Language support\nAccept more log file types\nAusterity rating ranking danger\nAlongside reporting\nSteps towards detecting log4J instances are being implmented, will need further testing\nProvide detection for OWASP 2017")
    
    def actionExit(self):
        QCoreApplication.exit(0)
    
    def moveToOptions(self):
        self.ui.stackedWidget.setCurrentIndex(1)

    def moveToHome(self):
        self.ui.stackedWidget.setCurrentIndex(0)

    def changeLines(self):
        if self.lineWidget:
            n = int(self.ui.userSubmitLog.document().lineCount())
            self.lineWidget.changeLineCount(n)

    def openFileNameDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,"Choose a log file", "","Text Files (*.txt);;All Files (*)", options=options)
        if fileName:
            self.loadedFile = fileName
            self.newLogLoaded()

    def newLogLoaded(self):
        self.clearOutput()
        self.ui.userSubmitLog.clear()
        self.outputLog()
        self.startingCode()

    def clearOutput(self):
        self.ui.AppDataLog.clear()

    def outputLog(self):
        self.thread = QThread()
        self.worker = Worker(self.loadedFile)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.finished.connect(self.changeLines)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.emitLine.connect(self.updateUI)
        self.thread.start()

    def updateUI(self, line):
        self.ui.userSubmitLog.append(line.strip("\n").strip('"'))

    def search_function(self, stringtosearch):
        with open(self.loadedFile, "r") as fh:
            fstring=fh.readlines()
        linenumber=0
        extractword=[]
        for line in fstring:
            linenumber=linenumber+1
            word = re.search(stringtosearch, line)
            if(word):
                i=fstring[linenumber-1]
                extractword.append(i)
        ip=[]
        for i in extractword:
            words = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', i)
            ip.append(words.group())
        dictOfElements = dict()
        for element in ip:
            if element in dictOfElements:
                dictOfElements[element] += 1
            else:
                dictOfElements[element] = 1
        dictOfElements = {key: value for key, value in dictOfElements.items() if value > 0}
        for key, value in dictOfElements.items():
            self.ui.AppDataLog.append(str(key) + ' :: ' + str(value))
            self.changeHighlight(value-1)

    def loadFile(self):
        with open(self.loadedFile, "r") as fh:
            fstring=fh.readlines()
        lst=[]
        for line in fstring:
            word = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            word=word.group()
            lst.append(word)
        dictOfElems = dict()
        for elem in lst:
            if elem in dictOfElems:
                dictOfElems[elem] += 1
            else:
                dictOfElems[elem] = 1
        dictOfElems = {key: value for key, value in dictOfElems.items() if value > 0}
        total=0
        for key, value in dictOfElems.items():
            total=total+value
        for key, value in dictOfElems.items():  
            per=value/total
            self.ui.AppDataLog.append(str(key) + ' :: ' + str(value) + ' : ' + str(per*100))

    def initialChoices(self):
        self._highlighter.clear_highlight()
        choice = self.ui.userInput.text()
        if("A01" in choice):
            self.ui.AppDataLog.append("\nInstances of Broken Access Control Forced Browsing:\n")
            #self.search_function(".com/admin")
            #self.search_function("ADMIN")
            #self.ui.AppDataLog.append("\nInstances of Broken Access Control Insecure ID:\n")
            #self.search_function("profile?")
            #self.search_function("id")
            #self.search_function("ID")
            #self.ui.AppDataLog.append("\nInstances of Broken Access Control Directory Traversal:\n")
            #self.search_function("../../../")
            #self.search_function("../../")
            #self.search_function("passwd")
            #self.ui.userInput.clear()

        elif("A01-FB" in choice):
            self.ui.AppDataLog.append("\nInstances of Broken Access Control Forced Browsing:\n")
            self.search_function(".com/admin")
            self.search_function("ADMIN")
            self.ui.userInput.clear()

        elif("A01-ID" in choice):
            self.ui.AppDataLog.append("\nInstances of Broken Access Control Insecure ID:\n")
            self.search_function("profile?")
            self.search_function("id")
            self.search_function("ID")
            self.ui.userInput.clear()

        elif("A01-DT" in choice):
            self.ui.AppDataLog.append("\nInstances of Broken Access Control Directory Traversal:\n")
            self.search_function("../../../")
            self.search_function("../../")
            self.search_function("passwd")
            self.ui.userInput.clear()

        elif("A02" in choice):
            self.ui.AppDataLog.append("\nNot applicable please refer to the OWASP: Instances of Crytographic Failure:\n")

        elif("A03" in choice):
            self.ui.AppDataLog.append("Instances of SQL Injection:")
            self.ui.AppDataLog.append("sleep based attacks")
            self.search_function("sleep")
            self.ui.AppDataLog.append("select based attacks")
            self.search_function("select")
            self.ui.AppDataLog.append("\nInstances of Cross Site Scripting:\n")
            self.ui.AppDataLog.append("Alert based XSS")
            self.search_function("alert")
            self.ui.AppDataLog.append("Prompt based XSS")
            self.search_function("prompt")

        elif("A03-SQL" in choice):
            self.ui.AppDataLog.append("Instances of SQL Injection:")
            self.ui.AppDataLog.append("sleep based attacks")
            self.search_function("sleep")
            self.ui.AppDataLog.append("select based attacks")
            self.search_function("select")

        elif("A03-XSS" in choice):
            self.ui.AppDataLog.append("\nInstances of Cross Site Scripting:\n")
            self.ui.AppDataLog.append("Alert based XSS")
            self.search_function("alert")
            self.ui.AppDataLog.append("Prompt based XSS")
            self.search_function("prompt")
            
        elif("A04" in choice):
            self.ui.AppDataLog.append("\nNot applicable please refer to the OWASP: Insecure Design\n")

        elif("A05" in choice):
            self.ui.AppDataLog.append("\nNot applicable please refer to the OWASP: Security Misconfiguration\n")

        elif("A06" in choice):
            self.ui.AppDataLog.append("\nNot applicable please refer to the OWASP: Vulnerable and Outdated Components")

        elif("A07" in choice):
            self.ui.AppDataLog.append("\nInstances of Identification and Authentication Failures:\n")
            #self.search_function("etc/passwd")
            #self.search_function("123456")
            #self.search_function("123456789")
            #self.search_function("12345")
            self.search_function("qwerty")
            #self.search_function("password")
            #self.search_function("12345678")
            #self.search_function("111111")
            #self.search_function("123123")
            #self.search_function("1234567890")
            #self.search_function("1234567")
            #self.search_function("qwerty123")
            #self.search_function("oooooo")
            #self.search_function("1q2w3e")
            #self.search_function("aa12345678")
            #self.search_function("abc123")
            #self.search_function("password1")
            #self.search_function("1234")
            #self.search_function("qwertyuiop")
            #self.search_function("123321")
            #self.search_function("password123")
            #self.search_function("888888")
            #self.search_function("princess")
            #self.search_function("dragon")
            #self.search_function("password1")
            #self.search_function("123qweworst")
            #self.search_function("monkey")
            #self.search_function("football")
            #self.search_function("letmein")
            #self.search_function("baseball")
            #self.search_function("trustno1")
            #self.search_function("adobe123")
            #self.search_function("iloveyou")
            #self.search_function("master")
            #self.search_function("photoshop")
            #self.search_function("sunshine")
            #self.search_function("1qaz2wsx")
            #self.search_function("ashley")
            #self.search_function("bailey")
            #self.search_function("welcome")
            #self.search_function("access")
            #self.search_function("mustang")
            #self.search_function("121212")
            #self.search_function("flower")
            #self.search_function("passw0rd")
            #self.search_function("michael")
            #self.search_function("superman")
            #self.search_function("jesus")
            #self.search_function("654321")
            #self.search_function("696969")
            #self.search_function("ninja")
            #self.search_function("azerty")
            #self.search_function("solo")
            #self.search_function("zaq1zaq1")
            #self.search_function("starwars")
            #self.search_function("etc/passwd")
            #self.search_function("123456")
            #self.search_function("123456789")
            #self.search_function("12345")
            #self.search_function("Qwerty")
            #self.search_function("Password")
            #self.search_function("12345678")
            #self.search_function("Qwerty123")
            #self.search_function("Oooooo")
            #self.search_function("Aa12345678")
            #self.search_function("Abc123")
            #self.search_function("Password1")
            #self.search_function("Qwertyuiop")
            #self.search_function("Password123")
            #self.search_function("Princess")
            #self.search_function("Dragon")
            #self.search_function("Password1")
            #self.search_function("123Qweworst")
            #self.search_function("Monkey")
            #self.search_function("Football")
            #self.search_function("Letmein")
            #self.search_function("Baseball")
            #self.search_function("Trustno1")
            #self.search_function("Adobe123")
            #self.search_function("Iloveyou")
            #self.search_function("Master")
            #self.search_function("Photoshop")
            #self.search_function("Sunshine")
            #self.search_function("1qaz2wsx")
            #self.search_function("Ashley")
            #self.search_function("Bailey")
            #self.search_function("Welcome")
            #self.search_function("Access")
            #self.search_function("Mustang")
            #self.search_function("Flower")
            #self.search_function("Passw0rd")
            #self.search_function("Michael")
            #self.search_function("Superman")
            #self.search_function("Jesus")
            #self.search_function("Ninja")
            #self.search_function("Azerty")
            #self.search_function("Solo")
            #self.search_function("Zaq1zaq1")
            #self.search_function("Starwars")

        elif("A08" in choice):
            self.ui.AppDataLog.append("\nInstances of Software and Data Integrity Failures, Vulnerable Functions:\n")
            self.search_function("CVE-565")
            self.search_function("CVE-426")
            self.search_function("CVE-784")
            self.search_function("CVE-915")
            self.search_function("CVE-829")
            self.search_function("CVE-830")
            self.search_function("CVE-494")
            self.search_function("CVE-502")
            self.search_function("CVE-345")
            self.search_function("CVE-353")
            self.ui.AppDataLog.append("\nInstances of Software and Data Integrity Failures, Disreputable CWE Numbers:\n")
            self.search_function("admin_init")

        
        elif("A08-CVE" in choice):
            self.ui.AppDataLog.append("\nInstances of Software and Data Integrity Failures, Disreputable CWE Numbers:\n")
            self.search_function("CVE-565")
            self.search_function("CVE-426")
            self.search_function("CVE-784")
            self.search_function("CVE-915")
            self.search_function("CVE-829")
            self.search_function("CVE-830")
            self.search_function("CVE-494")
            self.search_function("CVE-502")
            self.search_function("CVE-345")
            self.search_function("CVE-353")

        elif("A08-INI" in choice):
            self.ui.AppDataLog.append("\nInstances of Software and Data Integrity Failures, Vulnerable Functions:\n")
            self.search_function("admin_init")
                        
        elif("A09" in choice):
            self.ui.AppDataLog.append("\nNot applicable please refer to the OWASP: Security logging and monitoring failures site")
            
        elif("A10" in choice):
            self.ui.AppDataLog.append("\nInstances of Server-Side Request Forgery (SSRF):\n")
            self.search_function(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'"/admin")
            self.ui.AppDataLog.append("\nInstances of Server-Side Request Forgery, SSRF Whitelisted Input Filters:\n")
            self.search_function("-host@")
            self.search_function("-host#")

        elif("A10-BE" in choice):
            self.ui.AppDataLog.append("\nInstances of Server-Side Request Forgery, Back End SSRF:\n")
            self.search_function(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'"/admin")

        elif("A10-IF" in choice):
            self.ui.AppDataLog.append("\nInstances of Server-Side Request Forgery, SSRF Whitelisted Input Filters:\n")
            self.search_function("-host@")
            self.search_function("-host#")
            
        #elif("KONAMI" in choice):
            #self.ui.AppDataLog.append("Ah, you've found a wee secret. Guess I will try and scan for Log4j")
            #self.search_function("CVE-2021-45046")
            #self.search_function("CVE-2021-44228")
            #self.search_function("CVE-2021-4104")
            #self.search_function("CVE-2021-45105")
            #self.search_function("CVE-2021-44832")
            #self.search_function("CVE-2020-9488")
            #self.search_function("CVE-2020-9493")
            #self.search_function("CVE-2022-23302")
            #self.search_function("CVE-2022-23305")
            #self.search_function("CVE-2022-23307")
            #self.ui.userInput.clear()
        
    def startingCode(self):
        self.ui.AppDataLog.append("OWASP Top Ten Forensic Tool")
        self.ui.AppDataLog.append("\nEnter a command above to return the results.\nFor example ""A03-XSS"" will disaply a XSS vulnrability found in the pre-uploaded log.\n")
        self.ui.AppDataLog.append("A01 : All Instances of Broken Access Control")
        self.ui.AppDataLog.append("A01-FB : Broken Access Control, Forced Browsing")
        self.ui.AppDataLog.append("A01-ID : Broken Access Control, Insecure ID")
        self.ui.AppDataLog.append("A01-DT : Broken Access Control, Directory Traversal\n")
        self.ui.AppDataLog.append("A02 : Crytographic Failures\n")
        self.ui.AppDataLog.append("A03 : All Instances of Injection")
        self.ui.AppDataLog.append("A03-XSS : Injection, Cross site scripting (XSS)")
        self.ui.AppDataLog.append("A03-SQL : Injection, SQL Injection\n")
        self.ui.AppDataLog.append("A04 : Insecure Design\n")
        self.ui.AppDataLog.append("A05 : Security Misconfiguration\n")
        self.ui.AppDataLog.append("A06 : Vulnerable and Outdated Components\n")        
        self.ui.AppDataLog.append("A07 : Identification and Authentication\n")
        self.ui.AppDataLog.append("A08 : All instances of Software and Data Integrity Failures")
        self.ui.AppDataLog.append("A08-CVE : Disreputable CVE Numbers")
        self.ui.AppDataLog.append("A08-INI : Vulnerable Functions\n")
        self.ui.AppDataLog.append("A09 : Security Logging and Monitoring Failures\n")
        self.ui.AppDataLog.append("A10 : Server-Side Request Forgery (SSRF)")
        self.ui.AppDataLog.append("A10-BE : Back End SSRF")
        self.ui.AppDataLog.append("A10-IF : SSRF Whitelisted Input Filters")
        

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Window()
    win.show()
    sys.exit(app.exec())

    #palette = QPalette()
    #palette.setColor(QPalette.Window, QColor(53, 53, 53))
    #palette.setColor(QPalette.WindowText, Qt.white)
    #palette.setColor(QPalette.Base, QColor(25, 25, 25))
    #palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    #palette.setColor(QPalette.ToolTipBase, Qt.black)
    #palette.setColor(QPalette.ToolTipText, Qt.white)
    #palette.setColor(QPalette.Text, Qt.white)
    #palette.setColor(QPalette.Button, QColor(53, 53, 53))
    #palette.setColor(QPalette.ButtonText, Qt.white)
    #palette.setColor(QPalette.BrightText, Qt.red)
    #palette.setColor(QPalette.Link, QColor(42, 130, 218))
    #palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    #palette.setColor(QPalette.HighlightedText, Qt.black)
    #app.setPalette(palette)
