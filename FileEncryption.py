# FileEncryption.py, Copyright(c) 2021 Martin S. Merkli
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
from hashlib import sha512 as sha
from hashlib import sha256
from random import randrange
import os
from tkinter import filedialog
from tkinter import messagebox
from time import time
from math import sqrt

debug = False
fileselected = 'none'
filename = 'none'


def xor(x: bytes, y: bytes) -> bytes:
    return bytes([_a ^ _b for _a, _b in zip(x, y)])


def hashpassword(password: str, minlength: int) -> bytes:
    sha512hashed = sha(password.encode()).digest()
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
    filekey = int(os.urandom(32).hex(), 16)
    key = pow(filekey, publickeys[0], publickeys[1])
    hashed = hashpassword(str(filekey), len(file))
    normalcipher = xor(file, hashed)
    cipher = b'\x01RSA'
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
    else:
        printdebug('unknown rsa-version')
        askwin = Tk()
        askwin.title('Unknown version - FileEncryption')
        a1 = Label(askwin, text='The version of the rsa encrypted file is unknown.\nPlease select a version or cancel.')
        options = ['cancel', 'v1']
        clicked = StringVar()
        clicked.set('cancel')
        a2 = OptionMenu(askwin, clicked, *options)
        a3 = Button(askwin, text='Select', command=askwin.quit)
        a1.grid(row=0, column=0)
        a2.grid(row=1, column=0)
        a3.grid(row=2, column=0)
        askwin.mainloop()
        selected = clicked.get()
        if selected == 'cancel':
            printdebug('version canceled')
            return b'__cancel__'
        elif selected == 'v1':
            printdebug('v1 selected')
            return rsadecrypt1(cipher, privatekeys)


def rsadecrypt1(cipher: bytes, privatekeys: list) -> bytes:
    keylength = (cipher[4] * 256) + (cipher[5]) + 6
    cryptkey = int(cipher[6:keylength].decode())
    key = pow(cryptkey, privatekeys[0], privatekeys[1])
    cipherfile = cipher[keylength:]
    hashed = hashpassword(str(key), len(cipherfile))
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


def selectfile(label: Label):
    global fileselected
    fileselectedtmp = filedialog.askopenfilename(initialdir=os.getcwd(), title='Select a file')
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


def encryptfile(passwordentry: Entry, filedirectory: str):
    password = passwordentry.get()
    if password == 'password':
        printdebug('unsecure password')
        if messagebox.askyesnocancel('Warning - FileEncryption', "'password' is one of the worst passwords!"
                                                                 " Do you really want to continue?"):
            pass
        else:
            return None
    if filedirectory == 'none':
        printdebug('no file selected')
        messagebox.showerror('Error - FileEncryption', 'Error: No file selected.')
        return None
    with open(filedirectory, 'rb') as originalfile:
        with open(filedirectory + '.enc', 'wb') as encfile:
            originalcontent = originalfile.read()
            hashedpassword = hashpassword(password, len(originalcontent))
            encfile.write(b'\x01ENC')
            encfile.write(xor(originalcontent, hashedpassword))
            messagebox.showinfo('Success - FileEncryption', "The file was successfully encrypted with the following"
                                                            " password: '" + password + "'. \nThe original file still"
                                                                                        " exists. You can delete it.")


def decryptfile1(cipher: bytes, password: str) -> bytes:
    hashed = hashpassword(password, len(cipher))
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
                else:
                    printdebug('unknown encryption version')
                    askwin = Tk()
                    askwin.title('Unknown version - FileEncryption')
                    a1 = Label(askwin,
                               text='The version of the encrypted file is unknown.\nPlease select a version or cancel.')
                    options = ['cancel', 'v1']
                    clicked = StringVar()
                    clicked.set('cancel')
                    a2 = OptionMenu(askwin, clicked, *options)
                    a3 = Button(askwin, text='Select', command=askwin.quit)
                    a1.grid(row=0, column=0)
                    a2.grid(row=1, column=0)
                    a3.grid(row=2, column=0)
                    askwin.mainloop()
                    selected = clicked.get()
                    if selected == 'cancel':
                        printdebug('version canceled')
                        return None
                    elif selected == 'v1':
                        printdebug('v1 selected')
                        content = decryptfile1(cipher, password)
                newfile.write(content)
                messagebox.showinfo('Success - FileEncryption', 'The file was decrypted, '
                                                                'but the password could be wrong.')
    except:
        messagebox.showerror('Error - FileEncryption', 'An unexpected error accrued.')


def receiversa(passwordentry: Entry, filedirectory: str):
    with open('rsa.txt', 'r') as encryptedkeysfile:
        with open(filedirectory, 'rb') as originalfile:
            with open(filedirectory[:-4], 'wb') as newfile:
                passwordint = int(sha256(passwordentry.get().encode()).hexdigest(), 16)
                try:
                    lines = encryptedkeysfile.readlines()
                    if int(lines[1]) % passwordint == 0:
                        cipher = originalfile.read()
                        content = rsadecrypt(cipher, [int(lines[1]) // passwordint, int(lines[2])])
                        if content != b'__ERROR__' and b'__cancel__':
                            newfile.write(content)
                            messagebox.showinfo('Success - FileEncryption', 'The file was successfully decrypted.')
                        else:
                            messagebox.showerror('Error - FileEncryption', 'An unexpected error accrued.')
                            return None
                    else:
                        messagebox.showerror('Wrong password - FileEncryption', 'The entered password is incorrect. '
                                                                                'Please try again.')
                except:
                    messagebox.showerror('Error - FileEncryption', 'An unexpected error accrued.\nThe file with your '
                                                                   'RSA keys is probably corrupted')


def sendrsa(passwordentry: Entry, filedirectory: str):
    key = passwordentry.get()
    if isrsakey(key):
        with open(filedirectory, 'rb') as originalfile:
            with open(filedirectory + '.rsa', 'wb') as rsafile:
                splited = key.split('g')
                keyone = int(splited[1].replace('g', ''), 16)
                keytwo = int(splited[2].replace('g', ''), 16)
                publickeys = [keyone, keytwo]
                rsafile.write(rsaencrypt(originalfile.read(), publickeys))
                messagebox.showinfo('Success - FileEncryption', "The file was successfully encrypted.\nThe original"
                                                                " file still exists. You can delete it.")
    else:
        messagebox.showerror('Error - FileEncryption', 'Error: input is not a valid RSA-key.')


def copypublic(window: Tk) -> None:
    key = getrsapublic()
    if key != '__ERROR__':
        window.clipboard_clear()
        window.clipboard_append(getrsapublic())
        window.update()
        messagebox.showinfo('Success - FileEncryption', 'Your private key was copied to the clipboard.'
                                                        ' Paste it before closing this window')
    else:
        messagebox.showerror('Error - FileEncryption', "Error: couldn't get your public key.\nThe file with your "
                                                       'RSA keys is probably corrupted')


def openabout():
    messagebox.showinfo('About - FileEncryption', 'Copyright(c) 2021 Martin S. Merkli\nThis program is free and'
                                                  ' open-source software and is licensed under the GNU GPL3.'
                                                  ' Visit https://www.gnu.org/licenses/ for more information.'
                                                  '\nYou can read more about this project in the documentation.')


def startgui():
    global fileselected
    fileselected = 'none'
    root = Tk()
    root.title('FileEncryption')
    a1 = Button(root, text='Select file', command=lambda: selectfile(a2), width=16)
    a2 = Label(root, text=filename)
    b = Entry(root, width=38, show='*')
    c1 = Button(root, text='encrypt', command=lambda: encryptfile(b, fileselected), width=16)
    c2 = Button(root, text='decrypt', command=lambda: decryptfile(b, fileselected), width=16)
    d1 = Button(root, text='send', command=lambda: sendrsa(b, fileselected), width=16)
    d2 = Button(root, text='receive', command=lambda: receiversa(b, fileselected), width=16)
    e1 = Button(root, text='copy public key', command=lambda: copypublic(root), width=16)
    e2 = Button(root, text='About', command=openabout, width=16)
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
    startgui()
