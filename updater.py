#!/usr/bin/env python3
# PluginInstaller.py, Copyright(c) 2021 Martin S. Merkli
# version: 1.2
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


import os
import sys
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from hashlib import pbkdf2_hmac
from hashlib import sha512
from hashlib import sha256


main_project = b'#!/usr/bin/env python3\n# FileEncryption.py, Copyright(c) 2021 Martin S. Merkli\n# version: 1.2\n#\n# This program is free software: you can redistribute it and/or modify\n# it under the terms of the GNU General Public License as published by\n# the Free Software Foundation, either version 3 of the License, or\n# (at your option) any later version.\n#\n# This program is distributed in the hope that it will be useful,\n# but WITHOUT ANY WARRANTY; without even the implied warranty of\n# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n# GNU General Public License for more details.\n#\n# You should have received a copy of the GNU General Public License\n# along with this program.  If not, see <https://www.gnu.org/licenses/>.\n\nfrom tkinter import *\nfrom hashlib import pbkdf2_hmac\nfrom hashlib import sha512\nfrom random import randrange\nimport os\nfrom tkinter import filedialog\nfrom tkinter import messagebox\nfrom time import time\n\n\ndebug = False\nfileselected = \'none\'\nfilename = \'none\'\nlanguage = []\n\n\ndef xor(x: bytes, y: bytes) -> bytes:\n    return bytes([_a ^ _b for _a, _b in zip(x, y)])\n\n\ndef secure_hash(data: bytes, mode: int = 1, length: int = 64) -> bytes:\n    hashed = pbkdf2_hmac(\'sha512\', data, sha512(data).digest(), (mode + 10) * 1000, length)\n    return hashed\n\n\ndef hashpassword2(password: str, minlength: int) -> bytes:\n    pbkdf2_hmac_hashed = secure_hash(password.encode(), 4, 1024)\n    hashed = pbkdf2_hmac_hashed\n    while len(hashed) < minlength:\n        hashed += hashed\n    printdebug(\'hashed password\')\n    return hashed\n\n\ndef hashpassword1p0(password: str, minlength: int) -> bytes:\n    sha512hashed = sha512(password.encode()).digest()\n    hashed = sha512hashed\n    while len(hashed) < minlength:\n        hashed += hashed\n    printdebug(\'hashed password\')\n    return hashed\n\n\ndef randomprime(length: int = 16) -> int:\n    length -= 1\n    testnumber = randrange((10 ** length) + 1, (9 * (10 ** length)) + 9)\n    if testnumber % 2 == 0:\n        testnumber += 1\n    while not rabinmillerprime(testnumber):\n        testnumber += 2\n    printdebug(\'prime found\')\n    return testnumber\n\n\ndef rabinmillerprime(number: int, rounds: int = 64) -> bool:\n    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]\n    if number < 2:\n        return False\n    for p in small_primes:\n        if number < p * p:\n            return True\n        if number % p == 0:\n            return False\n    r, s = 0, number - 1\n    while s % 2 == 0:\n        r += 1\n        s //= 2\n    for _ in range(rounds):\n        a = randrange(2, number - 1)\n        x = pow(a, s, number)\n        if x == 1 or x == number - 1:\n            continue\n        for _ in range(r - 1):\n            x = pow(x, 2, number)\n            if x == number - 1:\n                break\n        else:\n            return False\n    return True\n\n\ndef modinverse(e: int, phin: int) -> int:\n    try:\n        modinv = pow(e, -1, phin)\n        printdebug(\'modinverse 3.8+ used\')\n        return modinv\n    except:\n        printdebug(\'using old modinverse\')\n\n        def egdc(a, b):\n            if a == 0:\n                return b, 0, 1\n            else:\n                gb, yb, xb = egdc(b % a, a)\n                return gb, xb - (b // a) * yb, yb\n\n        g, x, y = egdc(e, phin)\n        if g != 1:\n            raise Exception(\'modular inverse does not exist\')\n        else:\n            return x % phin\n\n\ndef generatersakeys(base10length: int = 320) -> list:\n    p = randomprime(base10length // 2)\n    q = randomprime(base10length // 2)\n    while p == q:\n        printdebug(\'p=q\')\n        q = randomprime(base10length // 2)\n    n = p * q\n    phin = (p - 1) * (q - 1)\n    e = randomprime(base10length // 2)\n    while n % e == 2 or phin % e == 2 or q == e or p == e:\n        e = randomprime(base10length // 2)\n    d = modinverse(e, phin)\n    del p\n    del q\n    printdebug(\'generated RSA keys\')\n    return [[e, n], [d, n]]\n\n\ndef rsaencrypt(file: bytes, publickeys: list) -> bytes:\n    filekey = int(os.urandom(64).hex(), 16)\n    key = pow(filekey, publickeys[0], publickeys[1])\n    hashed = hashpassword2(str(filekey), len(file))\n    normalcipher = xor(file, hashed)\n    cipher = b\'\\x02RSA\'\n    cipher += bytes([len(str(key).encode()) // 256])\n    cipher += bytes([len(str(key).encode()) % 256])\n    cipher += str(key).encode()\n    cipher += normalcipher\n    printdebug(\'encrypted content with rsa\')\n    return cipher\n\n\ndef rsadecrypt(cipher: bytes, privatekeys: list) -> bytes:\n    if cipher[0] == 1:\n        printdebug(\'RSA-version: v1\')\n        return rsadecrypt1(cipher, privatekeys)\n    elif cipher[0] == 2:\n        printdebug(\'RSA-version: v2\')\n        return rsadecrypt2(cipher, privatekeys)\n    else:\n        printdebug(\'unknown rsa-version\')\n        askwin = Tk()\n        askwin.title(text(10) + \' - \' + text(1))\n        a1 = Label(askwin, text=text(11) + \'\\n\' + text(12))\n        options = [text(13), \'v1\', \'v2\']\n        clicked = StringVar()\n        clicked.set(text(13))\n        a2 = OptionMenu(askwin, clicked, *options)\n        a3 = Button(askwin, text=text(14), command=askwin.quit)\n        a1.grid(row=0, column=0)\n        a2.grid(row=1, column=0)\n        a3.grid(row=2, column=0)\n        askwin.mainloop()\n        selected = clicked.get()\n        if selected == text(13):\n            printdebug(\'version canceled\')\n            return b\'__cancel__\'\n        elif selected == \'v1\':\n            printdebug(\'v1 selected\')\n            return rsadecrypt1(cipher, privatekeys)\n        elif selected == \'v2\':\n            printdebug(\'v2 selected\')\n            return rsadecrypt2(cipher, privatekeys)\n\n\ndef rsadecrypt1(cipher: bytes, privatekeys: list) -> bytes:\n    keylength = (cipher[4] * 256) + (cipher[5]) + 6\n    cryptkey = int(cipher[6:keylength].decode())\n    key = pow(cryptkey, privatekeys[0], privatekeys[1])\n    cipherfile = cipher[keylength:]\n    hashed = hashpassword1p0(str(key), len(cipherfile))\n    return xor(cipherfile, hashed)\n\n\ndef rsadecrypt2(cipher: bytes, privatekeys: list) -> bytes:\n    keylength = (cipher[4] * 256) + (cipher[5]) + 6\n    cryptkey = int(cipher[6:keylength].decode())\n    key = pow(cryptkey, privatekeys[0], privatekeys[1])\n    cipherfile = cipher[keylength:]\n    hashed = hashpassword2(str(key), len(cipherfile))\n    return xor(cipherfile, hashed)\n\n\ndef inttobytes(number: int) -> bytes:\n    bstring = b\'\'\n    new = number\n    while new > 0:\n        bstring = bytes([new % 256]) + bstring\n        new //= 256\n    printdebug(\'Turned integer to bytes\')\n    return bstring\n\n\ndef bytestoint(data: bytes) -> int:\n    return int.from_bytes(data, \'big\')\n\n\ndef printdebug(message: str) -> None:\n    global debug\n    if debug:\n        print(str(time()) + \' - \' + message)\n    else:\n        pass\n\n\ndef getrsapublic() -> str:\n    try:\n        with open(\'rsa.txt\', \'r\') as keyfile:\n            lines = keyfile.readlines()\n            one = hex(int(lines[0]))[2:]\n            two = hex(int(lines[2]))[2:]\n        output = \'01g\' + one + \'g\' + two\n    except ValueError:\n        printdebug(\'ERROR: getrsa didnt work\')\n        output = \'__ERROR__\'\n    return output\n\n\ndef selectfile(label: Label) -> None:\n    global fileselected\n    fileselectedtmp = filedialog.askopenfilename(initialdir=os.getcwd(), title=text(34))\n    global filename\n    if fileselectedtmp == ():\n        fileselected = \'none\'\n    else:\n        fileselected = fileselectedtmp\n    if fileselected == \'none\':\n        filename = \'none\'\n    else:\n        filename = fileselected.split(\'/\')[-1]\n    label.config(text=filename)\n    printdebug(\'selected file\')\n\n\ndef selectfilename():\n    global fileselected\n    global filename\n    filename = fileselected.split(\'/\')[-1]\n\n\ndef isrsakey(potentialkey: str) -> bool:\n    split = potentialkey.split(\'g\')\n    for part in split:\n        part.replace(\'g\', \'\')\n    if len(split) == 3 and split[0] == \'01\':\n        printdebug(\'is rsa key\')\n        return True\n    else:\n        printdebug(\'is not rsa key\')\n        return False\n\n\ndef encryptfile(passwordentry: Entry, filedirectory: str) -> None:\n    password = passwordentry.get()\n    if password == \'password\':\n        printdebug(\'unsecure password\')\n        if messagebox.askyesnocancel(text(15) + \' - \' + text(1), text(16) + text(17)):\n            pass\n        else:\n            return None\n    if filedirectory == \'none\':\n        printdebug(\'no file selected\')\n        messagebox.showerror(text(18) + \' - \' + text(1), text(19))\n        return None\n    with open(filedirectory, \'rb\') as originalfile:\n        with open(filedirectory + \'.enc\', \'wb\') as encfile:\n            originalcontent = originalfile.read()\n            hashedpassword = hashpassword2(password, len(originalcontent))\n            encfile.write(b\'\\x02ENC\')\n            encfile.write(xor(originalcontent, hashedpassword))\n            messagebox.showinfo(text(20) + \' - \' + text(1), text(21) + "\'" + password + "\'. \\n" + text(22))\n\n\ndef decryptfile1(cipher: bytes, password: str) -> bytes:\n    hashed = hashpassword1p0(password, len(cipher))\n    content = xor(cipher[4:], hashed)\n    return content\n\n\ndef decryptfile2(cipher: bytes, password: str) -> bytes:\n    hashed = hashpassword2(password, len(cipher))\n    content = xor(cipher[4:], hashed)\n    return content\n\n\ndef decryptfile(passwordentry: Entry, filedirectory: str) -> None:\n    try:\n        password = passwordentry.get()\n        with open(filedirectory, \'rb\') as encfile:\n            with open(filedirectory[:-4], \'wb\') as newfile:\n                cipher = encfile.read()\n                if cipher[0] == 1:\n                    content = decryptfile1(cipher, password)\n                    printdebug(\'decrypted with v1\')\n                elif cipher[0] == 2:\n                    content = decryptfile2(cipher, password)\n                    printdebug(\'decrypted with v2\')\n                else:\n                    printdebug(\'unknown encryption version\')\n                    askwin = Tk()\n                    askwin.title(text(10) + \' - \' + text(1))\n                    a1 = Label(askwin, text=text(11) + \'\\n\' + text(12))\n                    options = [text(13), \'v1\']\n                    clicked = StringVar()\n                    clicked.set(text(13))\n                    a2 = OptionMenu(askwin, clicked, *options)\n                    a3 = Button(askwin, text=text(14), command=askwin.quit)\n                    a1.grid(row=0, column=0)\n                    a2.grid(row=1, column=0)\n                    a3.grid(row=2, column=0)\n                    askwin.mainloop()\n                    selected = clicked.get()\n                    if selected == text(13):\n                        printdebug(\'version canceled\')\n                        return None\n                    elif selected == \'v1\':\n                        printdebug(\'v1 selected\')\n                        content = decryptfile1(cipher, password)\n                newfile.write(content)\n                messagebox.showinfo(text(20) + \' - \' + text(1), text(23))\n    except:\n        messagebox.showerror(text(18) + \' - \' + text(1), text(25))\n\n\ndef receiversa(passwordentry: Entry, filedirectory: str) -> None:\n    if filedirectory == \'none\':\n        return None\n    with open(\'rsa.txt\', \'r\') as encryptedkeysfile:\n        with open(filedirectory, \'rb\') as originalfile:\n            with open(filedirectory[:-4], \'wb\') as newfile:\n                passwordint = int(secure_hash(passwordentry.get().encode(), 3, 32).hex(), 16)\n                try:\n                    lines = encryptedkeysfile.readlines()\n                    if int(lines[1]) % passwordint == 0:\n                        cipher = originalfile.read()\n                        content = rsadecrypt(cipher, [int(lines[1]) // passwordint, int(lines[2])])\n                        if content != b\'__ERROR__\' and b\'__cancel__\':\n                            newfile.write(content)\n                            messagebox.showinfo(text(20) + \' - \' + text(1), text(26))\n                        else:\n                            messagebox.showerror(text(18) + \' - \' + text(1), text(25))\n                            return None\n                    else:\n                        messagebox.showerror(text(25) + \' - \' + text(1), text(27))\n                except:\n                    messagebox.showerror(text(18) + \' - \' + text(1), text(24) + \'\\n\' + text(28))\n\n\ndef sendrsa(passwordentry: Entry, filedirectory: str) -> None:\n    key = passwordentry.get()\n    if isrsakey(key):\n        with open(filedirectory, \'rb\') as originalfile:\n            with open(filedirectory + \'.rsa\', \'wb\') as rsafile:\n                splited = key.split(\'g\')\n                keyone = int(splited[1].replace(\'g\', \'\'), 16)\n                keytwo = int(splited[2].replace(\'g\', \'\'), 16)\n                publickeys = [keyone, keytwo]\n                rsafile.write(rsaencrypt(originalfile.read(), publickeys))\n                messagebox.showinfo(text(20) + \' - \' + text(1), text(29) + \'\\n\' + text(30))\n    else:\n        messagebox.showerror(text(18) + \' - \' + text(1), text(31))\n\n\ndef copypublic(window: Tk) -> None:\n    key = getrsapublic()\n    if key != \'__ERROR__\':\n        window.clipboard_clear()\n        window.clipboard_append(getrsapublic())\n        window.update()\n        messagebox.showinfo(text(20) + \' - \' + text(1), text(33))\n    else:\n        messagebox.showerror(text(18) + \' - \' + text(1), text(32) + \'\\n\' + text(28))\n\n\ndef openabout() -> None:\n    messagebox.showinfo(text(9) +  \' - \' + text(1),\n                        text(35) + \'\\n\' + text(36) + \'\\n\' + text(37) + \'\\n\' + text(38) + \'1.2\')\n\n\ndef languageinit() -> None:\n    global language\n    supported_languages = [\'EN\', \'DE\']\n    for supported_language in supported_languages:\n        try:\n            with open(supported_language + \'.txt\', \'r\') as language_file:\n                words = language_file.readlines()\n                language = []\n                for word in words:\n                    language.append(word.replace(\'\\n\', \'\'))\n            return None\n        except FileNotFoundError:\n            pass\n    language = []\n\n\ndef text(index: int) -> str:\n    global language\n    if index > 0:\n        index -= 1\n    else:\n        return \'\'\n    if len(language) > index:\n        return language[index]\n    else:\n        return \'\'\n\n\ndef startgui() -> None:\n    global fileselected\n    fileselected = \'none\'\n    root = Tk()\n    root.title(text(1))\n    a1 = Button(root, text=text(2), command=lambda: selectfile(a2), width=16)\n    a2 = Label(root, text=filename)\n    b = Entry(root, width=38, show=\'*\')\n    c1 = Button(root, text=text(4), command=lambda: encryptfile(b, fileselected), width=16)\n    c2 = Button(root, text=text(5), command=lambda: decryptfile(b, fileselected), width=16)\n    d1 = Button(root, text=text(6), command=lambda: sendrsa(b, fileselected), width=16)\n    d2 = Button(root, text=text(7), command=lambda: receiversa(b, fileselected), width=16)\n    e1 = Button(root, text=text(8), command=lambda: copypublic(root), width=16)\n    e2 = Button(root, text=text(9), command=openabout, width=16)\n    a1.grid(row=0, column=0)\n    a2.grid(row=0, column=1)\n    b.grid(row=1, column=0, columnspan=2)\n    c1.grid(row=2, column=0)\n    c2.grid(row=2, column=1)\n    d1.grid(row=3, column=0)\n    d2.grid(row=3, column=1)\n    e1.grid(row=4, column=0)\n    e2.grid(row=4, column=1)\n    root.mainloop()\n\n\nif __name__ == \'__main__\':\n    languageinit()\n    startgui()\n'
location = os.getcwd()
if location[-1] not in ['/', '\\']:
    location += '/'
supported_languages = ['EN', 'DE']
EN = b'FileEncryption\nSelect file\nnone\nencrypt\ndecrypt\nsend\nreceive\ncopy public key\nAbout\nUnknown version\nThe version of the rsa encrypted file is unknown.\nPlease select a version or cancel.\ncancel\nSelect\nWarning\n\'password\' is one of the worst passwords!\nDo you really want to continue?\nError\nError: No file selected.\nSuccess\nThe file was successfully encrypted with the following password:\nThe original file still exists. You can delete it.\nThe file was decrypted, but the password could be wrong.\nAn unexpected error accrued.\nWrong password\nThe file was successfully decrypted.\nThe entered password is incorrect. Please try again.\nThe file with your RSA keys is probably corrupted.\nThe file was successfully encrypted.\nThe original file still exists. You can delete it.\nError: input is not a valid RSA-key.\nError: couldn\'t get your public key.\nYour public key was copied to the clipboard. Paste it before closing this window.\nSelect a file\nCopyright(c) 2021 Martin S. Merkli\nThis program is free and open-source software and is licensed under the GNU GPL3. Visit https://www.gnu.org/licenses/ for more information.\nYou can read more about this project in the documentation.\nVersion:\n'
DE = b'DateiVerschl\xc3\xbcsselung\nW\xc3\xa4hlen Sie eine Datei aus.\nnone\nverschl\xc3\xbcsseln\nentschl\xc3\xbcsseln\nsenden\nerhalten\n\xc3\xb6ffentlicher Schl\xc3\xbcssel kopieren\n\xc3\x9cber\nunbekannte Version\nDie RSA-Version der Datei ist unbekannt.\nBitte w\xc3\xa4hlen Sie eine Version aus oder brechen Sie ab.\nAbbrechen\nAusw\xc3\xa4hlen\nWarnung\n\'password\' ist eines der schlechtesten Passw\xc3\xb6rter!\nM\xc3\xb6chten Sie wirklich fortfahren?\nFehler\nFehler: keine Datei ausgew\xc3\xa4hlt.\nErfolg\nDie Datei wurde erfolgreich verschl\xc3\xbcsselt mit dem folgenden Passwort:\nDie Orginaldatei existiert noch. Sie k\xc3\xb6nnen sie l\xc3\xb6schen.\nDie Datei wurde entschl\xc3\xbcsselt, aber das Passwort k\xc3\xb6nnte falsch sein.\nEin unerwarter Fehler ist aufgetreten.\nFalsches Passwort\nDie Datei wurde erfolgreich entschl\xc3\xbcsselt.\nDas eingegebene Passwort ist falsch. Bitte versuchen Sie es erneut.\nDie Datei mit Ihren RSA-Schl\xc3\xbcsseln ist vermutlich besch\xc3\xa4digt.\nDie Datei wurde erfolgreich verschl\xc3\xbcsselt\nDie Orginaldatei existiert noch. Sie k\xc3\xb6nnen sie l\xc3\xb6schen.\nFehler: Eingabe ist kein g\xc3\xbcltiger RSA-Schl\xc3\xbcssel\nFehler: Ihr \xc3\xb6ffentlicher Schl\xc3\xbcssel wurde nicht gefunden.\nIhr \xc3\xb6ffentlicher RSA-Schl\xc3\xbcssel wurde in die Zwischenablage kopiert. F\xc3\xbcgen Sie ihn ein, bevor Sie dieses Fenster schliessen.\nW\xc3\xa4hlen Sie eine Datei aus.\nCopyright(c) 2021 Martin S. Merkli\nDieses Programm ist freie (bezogen auf Freiheit), Open-Source Software und lizensiert unter der GNU GPL v3. Besuchen Sie <https://www.gnu.org/licenses/> f\xc3\xbcr mehr Informationen.\nSie k\xc3\xb6nnen mehr \xc3\xbcber dieses Projekt in der Dokumentation erfahren.\nVersion:\n'


def secure_hash(data: bytes, mode: int = 1, length: int = 64) -> bytes:
    hashed = pbkdf2_hmac('sha512', data, sha512(data).digest(), (mode + 10) * 1000, length)
    return hashed


def select_location() -> None:
    global location
    directory = filedialog.askdirectory()
    location = directory


def main() -> None:
    global main_project
    global location
    root = tk.Tk()
    root.title('Update - FileEncryption')
    button_a = tk.Button(root, text='Select directory of FileEncryption.py', command=select_location)
    label_b = tk.Label(root, text=location)
    label_c = tk.Label(root, text='Enter your password for the RSA-keys:')
    entry_d = tk.Entry(root, show='*')
    label_e = tk.Label(root, text='')
    selected = tk.StringVar()
    selected.set('EN')
    options = supported_languages
    selector_f = tk.OptionMenu(root, selected, *options)
    pressed_g = tk.BooleanVar(False)
    button_g = tk.Button(root, text='Update', command=lambda: pressed_g.set(True))
    button_a.grid(row=0, column=0)
    label_b.grid(row=1, column=0)
    label_c.grid(row=2, column=0)
    entry_d.grid(row=3, column=0)
    label_e.grid(row=4, column=0)
    selector_f.grid(row=5, column=0)
    button_g.grid(row=6, column=0)
    loop = True
    while loop:
        try:
            root.update()
        except tk.TclError:
            sys.exit(0)
        continue_available = True
        if location[-1] not in ['/', '\\']:
            location += '/'
        if os.path.exists(location + 'rsa.txt'):
            with open(location + 'rsa.txt', 'r') as original_rsa_file:
                original_rsa = original_rsa_file.readlines()
                try:
                    if int(original_rsa[1]) % int(sha256(entry_d.get().encode()).hexdigest(), 16) == 0:
                        label_e.config(text='correct password')
                    else:
                        label_e.config(text='wrong password')
                        continue_available = False
                except TypeError:
                    label_e.config(text='error')
                    continue_available = False
        else:
            label_e.config(text='error: rsa file not found')
            continue_available = False
        if os.path.exists(location + 'FileEncryption.py') or os.path.exists(location + 'DateiVerschlüsselung.py'):
            pass
        else:
            continue_available = False
        if continue_available:
            button_g.config(state=tk.NORMAL)
        else:
            button_g.config(state=tk.DISABLED)
        if pressed_g.get():
            loop = False
        label_b.config(text=location)
    with open(location + 'rsa.txt', 'r') as original_rsa_file:
        original_rsa = original_rsa_file.readlines()
    with open(location + 'rsa.txt', 'w') as new_rsa_file:
        original_rsa[1] = str(int(secure_hash(entry_d.get().encode(), 3, 32).hex(), 16) *
                              (int(original_rsa[1]) // int(sha256(entry_d.get().encode()).hexdigest(), 16)))
        new_rsa_file.writelines(original_rsa)
    if os.path.exists(location + 'FileEncryption.py') or os.path.exists(location + 'DateiVerschlüsselung.py'):
        with open(location + 'FileEncryption.py', 'wb') as new_main_file:
            new_main_file.write(main_project)
        if os.path.exists(location + 'DateiVerschlüsselung.py'):
            os.remove(location + 'DateiVerschlüsselung.py')
    else:
        messagebox.showerror('Error - FileEncryption', 'An unknown error accrued')
        sys.exit(1)
    if selected.get() == 'EN':
        with open(location + 'EN.txt', 'wb') as language_file:
            language_file.write(EN)
    elif selected.get() == 'DE':
        with open(location + 'DE.txt', 'wb') as language_file:
            language_file.write(DE)
    else:
        messagebox.showerror('Error - FileEncryption', 'An unknown error accrued')
        sys.exit(1)
    messagebox.showinfo('Success - FileEncryption', 'Install successful: delete this updater')


if __name__ == '__main__':
    main()
