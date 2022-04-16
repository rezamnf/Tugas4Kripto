import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDial, QDialog, QApplication, QStackedWidget, QFileDialog, QMessageBox
from hashlib import sha1
from RSA import *

# ---------------------------------UTILITIES---------------------------------
def goBack():
    # widget.setCurrentIndex(widget.currentIndex() - 1)
    widget.removeWidget(widget.currentWidget())


# ---------------------------------HOME---------------------------------
class HomeScreen(QDialog):
    def __init__(self):
        super(HomeScreen, self).__init__()
        loadUi("UI/main.ui", self)

        self.Keygen.clicked.connect(self.goToKeygen)
        self.sign.clicked.connect(self.goToSign)
        self.verify.clicked.connect(self.goToVerify)

    def goToKeygen(self):
        keygen = KeyGenScreen()
        widget.addWidget(keygen)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def goToSign(self):
        sign = signScreen()
        widget.addWidget(sign)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def goToVerify(self):
        verify = verifyScreen()
        widget.addWidget(verify)
        widget.setCurrentIndex(widget.currentIndex()+1)

# ---------------------------------Key Generator---------------------------------
class KeyGenScreen(QDialog):
    def __init__(self):
        super(KeyGenScreen, self).__init__()
        loadUi("UI/Keygen.ui", self)
        self.RSA = RSA()

        self.generateKeyButton.clicked.connect(self.generate_key)
        self.saveKeyButton.clicked.connect(self.save_key)
        self.loadEKey.clicked.connect(self.load_public_key)
        self.loadDKey.clicked.connect(self.load_private_key)
        self.backButton.clicked.connect(goBack)

    def warning_msg(self,title, msg):
        temp = msg
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setText(str(title))
        msg.setInformativeText(temp)
        msg.exec_()

    def generate_key(self):
        self.RSA.generate_key()
        self.nKey.setText(str(self.RSA.n))
        self.eKey.setText(str(self.RSA.e))
        self.dKey.setText(str(self.RSA.d))
    
    def load_public_key(self):
        fname = QFileDialog().getOpenFileName(None, "Load Public Key", "Key/", "PublicKey (*.pub)")
        if(fname[0] == ''):
            self.warning_msg("Error","Pilih File Key")
        else:
            f = open(fname[0], "r")
            key = f.read().split(" ")
            f.close()
            self.nKey.setText(key[1])
            self.eKey.setText(key[0])

    def load_private_key(self):
        fname = QFileDialog().getOpenFileName(None, "Load Private Key", "Key/", "PrivateKey (*.pri)")
        if(fname[0] == ''):
            self.warning_msg("Error","Pilih File Key")
        else:
            f = open(fname[0], "r")
            key = f.read().split(" ")
            f.close()
            self.nKey.setText(key[1])
            self.dKey.setText(key[0])

    def save_key(self):
        try:
            n = int(self.nKey.toPlainText())
            e = int(self.eKey.toPlainText())
            d = int(self.dKey.toPlainText())
            name = QFileDialog.getSaveFileName(self, 'Save File', "Key/")
            self.RSA.save_key(name[0], e, n, d)
        except:
            self.warning_msg("Wrong Key!", "Key must be integer")

# ---------------------------------Sign---------------------------------
class signScreen(QDialog):
    def __init__(self):
        super(signScreen, self).__init__()
        loadUi("UI/Sign.ui", self)
        self.mode = "sign"
        self.message = ""
        self.outputPath = ""
        self.key = ""
        self.curve = ""
        self.keyboard = False
        self.infile = False
        self.RSA = RSA() 
        # self.enableOutputField = False

        # actions
        self.fileRadio.toggled.connect(self.togglefileRadio)
        self.keyboardRadio.toggled.connect(self.togglekeyboardRadio)
        self.SeparateFile.toggled.connect(self.toggleSeparateFile)
        self.InsideFile.toggled.connect(self.toggleInsideFile)
        self.messageFileButton.clicked.connect(self.browseInput)
        self.goButton.clicked.connect(self.runSign)
        self.loadDKey.clicked.connect(self.load_private_key)
        self.backButton.clicked.connect(goBack)
        self.nKey.setReadOnly(False)
        self.dKey.setReadOnly(False)

    def warning_msg(self,title, msg):
        temp = msg
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setText(str(title))
        msg.setInformativeText(temp)
        msg.exec_()

    def browseInput(self):
        f = QFileDialog.getOpenFileName(
            self, 'Open file', '~/Faisal Helmi/Desktop')
        self.inputFileField.setText(f[0])

    def load_private_key(self):
        fname = QFileDialog().getOpenFileName(None, "Load Private Key", "Key/", "PrivateKey (*.pri)")
        if(fname[0] == ''):
            self.warning_msg("Error","Pilih File Key")
        else:
            f = open(fname[0], "r")
            key = f.read().split(" ")
            f.close()
            self.nKey.setText(key[1])
            self.dKey.setText(key[0])
            self.nKey.setReadOnly(True)
            self.dKey.setReadOnly(True)

    def togglefileRadio(self): self.btnInputState(self.fileRadio)

    def togglekeyboardRadio(self): self.btnInputState(self.keyboardRadio)

    def toggleSeparateFile(self): self.btnInputState2(self.SeparateFile)

    def toggleInsideFile(self): self.btnInputState2(self.InsideFile)

    def btnInputState(self, b):
        if b.text() == "File":
            if b.isChecked():
                self.inputKeyboardField.setReadOnly(True)
                self.messageFileButton.setEnabled(True)
                self.fileInputMethod = "File"
                self.inputKeyboardField.setText("")
                self.keyboard = False
                if self.infile == False:
                    self.outputFileField.setReadOnly(False)
                
        elif b.text() == "Keyboard":
            if b.isChecked():
                self.inputKeyboardField.setReadOnly(False)
                self.messageFileButton.setEnabled(False)
                self.fileInputMethod = "Keyboard"
                self.inputFileField.setText("")
                self.keyboard = True
                self.outputFileField.setReadOnly(False)
                

    def btnInputState2(self, b):
        if b.text() == "Separate File":
            if b.isChecked():
                self.signatureLocation = "Separate File"
                self.infile = False
                self.outputFileField.setReadOnly(False)
        elif b.text() == "Inside File":
            if b.isChecked():
                self.signatureLocation = "Inside File"
                self.infile = True
                if self.keyboard == False:
                    self.outputFileField.setReadOnly(True)

    def getMessage(self):
        if (self.fileInputMethod == "File"):
            path = self.inputFileField.text()
            self.message = self.RSA.readfile_bin(path)
        else:
            self.message = self.inputKeyboardField.text()
        self.message = self.message

    def getKey(self):
        self.key = (
            int(self.nKey.text()),
            int(self.dKey.text())
        )

    def getOutputPath(self):
        self.outputPath = "Output/" + self.outputFileField.text() + "-signed.txt"
        self.outputMsgPath = "Output/" + self.outputFileField.text() + "-message.txt"

    def runSign(self):
        self.getMessage()
        self.getKey()
        self.getOutputPath()
        hashing = ''.join(x for x in self.message)
        hashed = int(sha1(hashing.encode()).hexdigest(), 16)

        signature = self.RSA.rsa_sign(hashed, self.key[1], self.key[0])

        if self.fileInputMethod == 'Keyboard':
            with open(self.outputMsgPath, "w") as f:
                f.write(self.message + '\n')
            f.close()

            if (self.signatureLocation == "Inside File"):
                self.RSA.save_eof(signature, self.outputMsgPath)
            elif (self.signatureLocation == "Separate File"):
                self.RSA.save_nf(signature, self.outputPath)
        else:
            if (self.signatureLocation == "Inside File"):
                self.RSA.save_eof(signature, self.inputFileField.text())
            elif (self.signatureLocation == "Separate File"):
                self.RSA.save_nf(signature, self.outputPath)

        self.Status.setText('Signing Success!')


class verifyScreen(QDialog):
    def __init__(self):
        super(verifyScreen, self).__init__()
        loadUi("UI/Verify.ui", self)
        self.mode = "verify"
        self.message = ""
        self.outputPath = ""
        self.key = ""
        self.RSA = RSA()

        # actions
        self.SeparateFile.toggled.connect(self.toggleSeparateFile)
        self.InsideFile.toggled.connect(self.toggleInsideFile)
        self.messageFileButton.clicked.connect(self.browseInputMessage)
        self.signatureFileButton.clicked.connect(self.browseInputSignature)
        self.goButton.clicked.connect(self.runVerify)
        self.loadEKey.clicked.connect(self.load_public_key)
        self.backButton.clicked.connect(goBack)
        self.nKey.setReadOnly(False)
        self.eKey.setReadOnly(False)

    def toggleSeparateFile(self): self.btnInputState(self.SeparateFile)

    def toggleInsideFile(self): self.btnInputState(self.InsideFile)

    def warning_msg(self,title, msg):
        temp = msg
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setText(str(title))
        msg.setInformativeText(temp)
        msg.exec_()

    def browseInputMessage(self):
        f = QFileDialog.getOpenFileName(self, 'Open File', 'Output/')
        self.messageField.setText(f[0])

    def load_public_key(self):
        fname = QFileDialog().getOpenFileName(None, "Load Public Key", "Key/", "PublicKey (*.pub)")
        if(fname[0] == ''):
            self.warning_msg("Error","Pilih File Key")
        else:
            f = open(fname[0], "r")
            key = f.read().split(" ")
            f.close()
            self.nKey.setText(key[1])
            self.eKey.setText(key[0])
            self.nKey.setReadOnly(True)
            self.eKey.setReadOnly(True)

    def browseInputSignature(self):
        f = QFileDialog.getOpenFileName(
            self, 'Open file', '~/Faisal Helmi/Desktop')
        self.signatureFileField.setText(f[0])

    def btnInputState(self, b):
        if b.text() == "Separate File":
            if b.isChecked():
                self.messageFileButton.setEnabled(True)
                self.signatureFileButton.setEnabled(True)
                self.signatureLocation = "Separate File"
        elif b.text() == "Inside File":
            if b.isChecked():
                self.messageFileButton.setEnabled(True)
                self.signatureFileButton.setEnabled(False)
                self.signatureLocation = "Inside File"
                self.signatureFileField.setText("")

    def getMessage(self):
        if self.signatureLocation == "Separate File":
            self.message, self.signature = self.RSA.read_nf(self.messageField.text(), self.signatureFileField.text())
        elif self.signatureLocation == "Inside File":
            self.message, self.signature = self.RSA.read_eof(self.messageField.text())

    def getKey(self):
        self.key = (
            int(self.nKey.text()),
            int(self.eKey.text())
        )

    def runVerify(self):
        self.getMessage()
        self.getKey()

        hashed = int(sha1(self.message.encode()).hexdigest(), 16)

        if (self.nKey.text() != "" and self.eKey.text() != ""):
            print(self.signature)
            print()
            verify = self.RSA.rsa_verify(self.signature, self.key[1], self.key[0], hashed)

            if verify:
                self.Status.setText('Verified!')
            else:
                self.Status.setText('Unverified!')
        else:
            self.Status.setText('Signature not found!')


# main
app = QApplication(sys.argv)
widget = QStackedWidget()

home = HomeScreen()

widget.addWidget(home)
widget.setFixedWidth(1000)
widget.setFixedHeight(720)
widget.show()
try:
    sys.exit(app.exec_())
except:
    print("Exiting")