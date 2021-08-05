#!/usr/bin/env python3
# updater(1-2to1-3).py, Copyright(c) 2021 Martin S. Merkli
# version: 1.3
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

location = os.getcwd()
if location[-1] not in ['/', '\\']:
    location += '/'

def select_location():
    global location
    directory = filedialog.askdirectory()
    location = directory

def main():
    global location
    root = tk.Tk()
    root.title('Update - FileEncryption')
    button_a = tk.Button(root, text='Select directory of FileEncryption.py', command=select_location)
    label_b = tk.Label(root, text=location)
    pressed_c = tk.BooleanVar(False)
    button_c = tk.Button(root, text='Update', command=lambda: pressed_c.set(True))
    button_a.grid(row=0, column=0)
    label_b.grid(row=1, column=0)
    button_c.grid(row=2, column=0)
    loop = True
    while loop:
        try:
            root.update()
            if location[-1] not in ['/', '\\']:
            	location += '/'
            if os.path.exists(location + 'FileEncryption.py'):
            	continue_available = True
            else:
            	continue_available = False
            if continue_available:
            	button_c.config(state=tk.NORMAL)
            else:
            	button_c.config(state=tk.DISABLED)
            if pressed_c.get():
            	loop = False
            	with open(location + 'FileEncryption.py', 'rb') as old_file:
                    old_content = old_file.read()
            	with open(location + 'FileEncryption.py', 'wb') as new_file:
            	    new_file.write(old_content.replace(b'os.urandom(64)', b'os.urandom(500)'))
            	messagebox.showinfo('Success - FileEncryption', 'Install successful: delete this updater')
            label_b.config(text=location)
        except tk.TclError:
            sys.exit(0)

if __name__ == '__main__':
    main()

