import sys

from PyQt5.QtWidgets import QWidget
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import QDesktopWidget
from PyQt5.QtWidgets import QPushButton
from PyQt5.QtWidgets import QMainWindow
from PyQt5.QtWidgets import QGridLayout
from PyQt5.QtWidgets import QLineEdit
from PyQt5.QtWidgets import QTextEdit
from PyQt5.QtWidgets import QLabel
from PyQt5.QtWidgets import QComboBox
from PyQt5.QtWidgets import QFileDialog

from pathspider.cmd.measure import plugins

def pluginCombo():
    c = QComboBox()
    for p in plugins:
        c.addItem(p.name)
    return c

def inputFileBox():
    l = QLineEdit()
    b = QPushButton("Open")
    def selectFile():
        l.setText(QFileDialog.getOpenFileName()[0])
    b.clicked.connect(selectFile)
    return l, b

def outputFileBox():
    l = QLineEdit()
    b = QPushButton("Save")
    def selectFile():
        l.setText(QFileDialog.getSaveFileName()[0])
    b.clicked.connect(selectFile)
    return l, b


class QtSpiderWizard(QMainWindow):

    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):           
        self.center()
    
        self.setWindowTitle('PATHspider Measurement Wizard')

        self.makeOptionsWidget(self.makeRunMeasurement())

        self.statusBar().showMessage('Ready')
        self.setCentralWidget(self.optionsWidget)

        self.show()

    def makeRunMeasurement(self):
        def run_measurement():
            print(self.pluginEdit.currentText())
        return run_measurement

    def makeOptionsWidget(self, runMeasurement):
        self.optionsWidget = QWidget()

        measureButton = QPushButton("Spider!")
        measureButton.clicked.connect(runMeasurement)

        plugin = QLabel('Plugin')
        self.pluginEdit = pluginCombo()
    
        inputFile = QLabel('Input File')
        self.inputFileEdit, inputFileButton = inputFileBox()
    
        outputFile = QLabel('Output File')
        self.outputFileEdit, outputFileButton = outputFileBox()
    
        grid = QGridLayout()
        grid.setSpacing(10)
    
        grid.addWidget(plugin, 1, 0)
        grid.addWidget(self.pluginEdit, 1, 1, 1, 2)
    
        grid.addWidget(inputFile, 2, 0)
        grid.addWidget(self.inputFileEdit, 2, 1)
        grid.addWidget(inputFileButton, 2, 2)
    
        grid.addWidget(outputFile, 3, 0)
        grid.addWidget(self.outputFileEdit, 3, 1)
        grid.addWidget(outputFileButton, 3, 2)
    
        grid.addWidget(measureButton, 6, 1)
        
        self.optionsWidget.setLayout(grid)
    
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Message',
            "Are you sure to quit?", QMessageBox.Yes | 
            QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()    
    
def run_measurement_gui(args):
    app = QApplication(sys.argv)
    wizard = QtSpiderWizard()
    sys.exit(app.exec_())

def register_args(subparsers):
    parser = subparsers.add_parser(name='wizard',
                                   help='Graphical PATHspider Wizard')
    parser.set_defaults(cmd=run_measurement_gui)
