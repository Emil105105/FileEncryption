#!/usr/bin/env python3
# FileEncryption.py, Copyright(c) 2021 Martin S. Merkli
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

from tkinter import *
from hashlib import pbkdf2_hmac
from hashlib import sha512
from random import randrange
import os
from tkinter import filedialog
from tkinter import messagebox
from time import time


debug = False
fileselected = 'none'
filename = 'none'
language = []


def xor(x: bytes, y: bytes) -> bytes:
    return bytes([_a ^ _b for _a, _b in zip(x, y)])


def secure_hash(data: bytes, mode: int = 1, length: int = 64) -> bytes:
    hashed = pbkdf2_hmac('sha512', data, sha512(data).digest(), (mode + 10) * 1000, length)
    return hashed


def hashpassword2(password: str, minlength: int) -> bytes:
    pbkdf2_hmac_hashed = secure_hash(password.encode(), 4, 1024)
    hashed = pbkdf2_hmac_hashed
    while len(hashed) < minlength:
        hashed += hashed
    printdebug('hashed password')
    return hashed


def hashpassword1p0(password: str, minlength: int) -> bytes:
    sha512hashed = sha512(password.encode()).digest()
    hashed = sha512hashed
    while len(hashed) < minlength:
        hashed += hashed
    printdebug('hashed password')
    return hashed


def randomprime(length: int = 16) -> int:
    length -= 1
    testnumber = randrange((10 ** length) + 1, (9 * (10 ** length)) + 9)
    if testnumber % 2 == 0:
        testnumber += 1
    while not rabinmillerprime(testnumber):
        testnumber += 2
    printdebug('prime found')
    return testnumber


def rabinmillerprime(number: int, rounds: int = 64) -> bool:
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    if number < 2:
        return False
    for p in small_primes:
        if number < p * p:
            return True
        if number % p == 0:
            return False
    r, s = 0, number - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(rounds):
        a = randrange(2, number - 1)
        x = pow(a, s, number)
        if x == 1 or x == number - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, number)
            if x == number - 1:
                break
        else:
            return False
    return True


def modinverse(e: int, phin: int) -> int:
    try:
        modinv = pow(e, -1, phin)
        printdebug('modinverse 3.8+ used')
        return modinv
    except:
        printdebug('using old modinverse')

        def egdc(a, b):
            if a == 0:
                return b, 0, 1
            else:
                gb, yb, xb = egdc(b % a, a)
                return gb, xb - (b // a) * yb, yb

        g, x, y = egdc(e, phin)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % phin


def generatersakeys(base10length: int = 320) -> list:
    p = randomprime(base10length // 2)
    q = randomprime(base10length // 2)
    while p == q:
        printdebug('p=q')
        q = randomprime(base10length // 2)
    n = p * q
    phin = (p - 1) * (q - 1)
    e = randomprime(base10length // 2)
    while n % e == 2 or phin % e == 2 or q == e or p == e:
        e = randomprime(base10length // 2)
    d = modinverse(e, phin)
    del p
    del q
    printdebug('generated RSA keys')
    return [[e, n], [d, n]]


def rsaencrypt(file: bytes, publickeys: list) -> bytes:
    filekey = int(os.urandom(64).hex(), 16)
    key = pow(filekey, publickeys[0], publickeys[1])
    hashed = hashpassword2(str(filekey), len(file))
    normalcipher = xor(file, hashed)
    cipher = b'\x02RSA'
    cipher += bytes([len(str(key).encode()) // 256])
    cipher += bytes([len(str(key).encode()) % 256])
    cipher += str(key).encode()
    cipher += normalcipher
    printdebug('encrypted content with rsa')
    return cipher


def rsadecrypt(cipher: bytes, privatekeys: list) -> bytes:
    if cipher[0] == 1:
        printdebug('RSA-version: v1')
        return rsadecrypt1(cipher, privatekeys)
    elif cipher[0] == 2:
        printdebug('RSA-version: v2')
        return rsadecrypt2(cipher, privatekeys)
    else:
        printdebug('unknown rsa-version')
        askwin = Tk()
        askwin.title(text(10) + ' - ' + text(1))
        a1 = Label(askwin, text=text(11) + '\n' + text(12))
        options = [text(13), 'v1', 'v2']
        clicked = StringVar()
        clicked.set(text(13))
        a2 = OptionMenu(askwin, clicked, *options)
        a3 = Button(askwin, text=text(14), command=askwin.quit)
        a1.grid(row=0, column=0)
        a2.grid(row=1, column=0)
        a3.grid(row=2, column=0)
        askwin.mainloop()
        selected = clicked.get()
        if selected == text(13):
            printdebug('version canceled')
            return b'__cancel__'
        elif selected == 'v1':
            printdebug('v1 selected')
            return rsadecrypt1(cipher, privatekeys)
        elif selected == 'v2':
            printdebug('v2 selected')
            return rsadecrypt2(cipher, privatekeys)


def rsadecrypt1(cipher: bytes, privatekeys: list) -> bytes:
    keylength = (cipher[4] * 256) + (cipher[5]) + 6
    cryptkey = int(cipher[6:keylength].decode())
    key = pow(cryptkey, privatekeys[0], privatekeys[1])
    cipherfile = cipher[keylength:]
    hashed = hashpassword1p0(str(key), len(cipherfile))
    return xor(cipherfile, hashed)


def rsadecrypt2(cipher: bytes, privatekeys: list) -> bytes:
    keylength = (cipher[4] * 256) + (cipher[5]) + 6
    cryptkey = int(cipher[6:keylength].decode())
    key = pow(cryptkey, privatekeys[0], privatekeys[1])
    cipherfile = cipher[keylength:]
    hashed = hashpassword2(str(key), len(cipherfile))
    return xor(cipherfile, hashed)


def inttobytes(number: int) -> bytes:
    bstring = b''
    new = number
    while new > 0:
        bstring = bytes([new % 256]) + bstring
        new //= 256
    printdebug('Turned integer to bytes')
    return bstring


def bytestoint(data: bytes) -> int:
    return int.from_bytes(data, 'big')


def printdebug(message: str) -> None:
    global debug
    if debug:
        print(str(time()) + ' - ' + message)
    else:
        pass


def getrsapublic() -> str:
    try:
        with open('rsa.txt', 'r') as keyfile:
            lines = keyfile.readlines()
            one = hex(int(lines[0]))[2:]
            two = hex(int(lines[2]))[2:]
        output = '01g' + one + 'g' + two
    except ValueError:
        printdebug('ERROR: getrsa didnt work')
        output = '__ERROR__'
    return output


def selectfile(label: Label) -> None:
    global fileselected
    fileselectedtmp = filedialog.askopenfilename(initialdir=os.getcwd(), title=text(34))
    global filename
    if fileselectedtmp == ():
        fileselected = 'none'
    else:
        fileselected = fileselectedtmp
    if fileselected == 'none':
        filename = 'none'
    else:
        filename = fileselected.split('/')[-1]
    label.config(text=filename)
    printdebug('selected file')


def selectfilename():
    global fileselected
    global filename
    filename = fileselected.split('/')[-1]


def isrsakey(potentialkey: str) -> bool:
    split = potentialkey.split('g')
    for part in split:
        part.replace('g', '')
    if len(split) == 3 and split[0] == '01':
        printdebug('is rsa key')
        return True
    else:
        printdebug('is not rsa key')
        return False


def encryptfile(passwordentry: Entry, filedirectory: str) -> None:
    password = passwordentry.get()
    if password == 'password':
        printdebug('unsecure password')
        if messagebox.askyesnocancel(text(15) + ' - ' + text(1), text(16) + text(17)):
            pass
        else:
            return None
    if filedirectory == 'none':
        printdebug('no file selected')
        messagebox.showerror(text(18) + ' - ' + text(1), text(19))
        return None
    with open(filedirectory, 'rb') as originalfile:
        with open(filedirectory + '.enc', 'wb') as encfile:
            originalcontent = originalfile.read()
            hashedpassword = hashpassword2(password, len(originalcontent))
            encfile.write(b'\x02ENC')
            encfile.write(xor(originalcontent, hashedpassword))
            messagebox.showinfo(text(20) + ' - ' + text(1), text(21) + "'" + password + "'. \n" + text(22))


def decryptfile1(cipher: bytes, password: str) -> bytes:
    hashed = hashpassword1p0(password, len(cipher))
    content = xor(cipher[4:], hashed)
    return content


def decryptfile2(cipher: bytes, password: str) -> bytes:
    hashed = hashpassword2(password, len(cipher))
    content = xor(cipher[4:], hashed)
    return content


def decryptfile(passwordentry: Entry, filedirectory: str) -> None:
    try:
        password = passwordentry.get()
        with open(filedirectory, 'rb') as encfile:
            with open(filedirectory[:-4], 'wb') as newfile:
                cipher = encfile.read()
                if cipher[0] == 1:
                    content = decryptfile1(cipher, password)
                    printdebug('decrypted with v1')
                elif cipher[0] == 2:
                    content = decryptfile2(cipher, password)
                    printdebug('decrypted with v2')
                else:
                    printdebug('unknown encryption version')
                    askwin = Tk()
                    askwin.title(text(10) + ' - ' + text(1))
                    a1 = Label(askwin, text=text(11) + '\n' + text(12))
                    options = [text(13), 'v1']
                    clicked = StringVar()
                    clicked.set(text(13))
                    a2 = OptionMenu(askwin, clicked, *options)
                    a3 = Button(askwin, text=text(14), command=askwin.quit)
                    a1.grid(row=0, column=0)
                    a2.grid(row=1, column=0)
                    a3.grid(row=2, column=0)
                    askwin.mainloop()
                    selected = clicked.get()
                    if selected == text(13):
                        printdebug('version canceled')
                        return None
                    elif selected == 'v1':
                        printdebug('v1 selected')
                        content = decryptfile1(cipher, password)
                newfile.write(content)
                messagebox.showinfo(text(20) + ' - ' + text(1), text(23))
    except:
        messagebox.showerror(text(18) + ' - ' + text(1), text(25))


def receiversa(passwordentry: Entry, filedirectory: str) -> None:
    if filedirectory == 'none':
        return None
    with open('rsa.txt', 'r') as encryptedkeysfile:
        with open(filedirectory, 'rb') as originalfile:
            with open(filedirectory[:-4], 'wb') as newfile:
                passwordint = int(secure_hash(passwordentry.get().encode(), 3, 32).hex(), 16)
                try:
                    lines = encryptedkeysfile.readlines()
                    if int(lines[1]) % passwordint == 0:
                        cipher = originalfile.read()
                        content = rsadecrypt(cipher, [int(lines[1]) // passwordint, int(lines[2])])
                        if content != b'__ERROR__' and b'__cancel__':
                            newfile.write(content)
                            messagebox.showinfo(text(20) + ' - ' + text(1), text(26))
                        else:
                            messagebox.showerror(text(18) + ' - ' + text(1), text(25))
                            return None
                    else:
                        messagebox.showerror(text(25) + ' - ' + text(1), text(27))
                except:
                    messagebox.showerror(text(18) + ' - ' + text(1), text(24) + '\n' + text(28))


def sendrsa(passwordentry: Entry, filedirectory: str) -> None:
    key = passwordentry.get()
    if isrsakey(key):
        with open(filedirectory, 'rb') as originalfile:
            with open(filedirectory + '.rsa', 'wb') as rsafile:
                splited = key.split('g')
                keyone = int(splited[1].replace('g', ''), 16)
                keytwo = int(splited[2].replace('g', ''), 16)
                publickeys = [keyone, keytwo]
                rsafile.write(rsaencrypt(originalfile.read(), publickeys))
                messagebox.showinfo(text(20) + ' - ' + text(1), text(29) + '\n' + text(30))
    else:
        messagebox.showerror(text(18) + ' - ' + text(1), text(31))


def copypublic(window: Tk) -> None:
    key = getrsapublic()
    if key != '__ERROR__':
        window.clipboard_clear()
        window.clipboard_append(getrsapublic())
        window.update()
        messagebox.showinfo(text(20) + ' - ' + text(1), text(33))
    else:
        messagebox.showerror(text(18) + ' - ' + text(1), text(32) + '\n' + text(28))


def openabout() -> None:
    messagebox.showinfo(text(9) +  ' - ' + text(1),
                        text(35) + '\n' + text(36) + '\n' + text(37) + '\n' + text(38) + '1.2')


def languageinit() -> None:
    global language
    supported_languages = ['EN', 'DE']
    for supported_language in supported_languages:
        try:
            with open(supported_language + '.txt', 'r') as language_file:
                words = language_file.readlines()
                language = []
                for word in words:
                    language.append(word.replace('\n', ''))
            return None
        except FileNotFoundError:
            pass
    language = []


def text(index: int) -> str:
    global language
    if index > 0:
        index -= 1
    else:
        return ''
    if len(language) > index:
        return language[index]
    else:
        return ''


def startgui() -> None:
    global fileselected
    fileselected = 'none'
    root = Tk()
    root.title(text(1))
    a1 = Button(root, text=text(2), command=lambda: selectfile(a2), width=16)
    a2 = Label(root, text=filename)
    b = Entry(root, width=38, show='*')
    c1 = Button(root, text=text(4), command=lambda: encryptfile(b, fileselected), width=16)
    c2 = Button(root, text=text(5), command=lambda: decryptfile(b, fileselected), width=16)
    d1 = Button(root, text=text(6), command=lambda: sendrsa(b, fileselected), width=16)
    d2 = Button(root, text=text(7), command=lambda: receiversa(b, fileselected), width=16)
    e1 = Button(root, text=text(8), command=lambda: copypublic(root), width=16)
    e2 = Button(root, text=text(9), command=openabout, width=16)
    a1.grid(row=0, column=0)
    a2.grid(row=0, column=1)
    b.grid(row=1, column=0, columnspan=2)
    c1.grid(row=2, column=0)
    c2.grid(row=2, column=1)
    d1.grid(row=3, column=0)
    d2.grid(row=3, column=1)
    e1.grid(row=4, column=0)
    e2.grid(row=4, column=1)
    root.mainloop()


if __name__ == '__main__':
    languageinit()
    startgui()
