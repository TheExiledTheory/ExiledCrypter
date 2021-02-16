#Coded by Mark Cuccarese 

# /$$$$$$$$ /$$   /$$ /$$ /$$                 /$$  /$$$$$$                                  /$$                        
#| $$_____/| $$  / $$|__/| $$                | $$ /$$__  $$                                | $$                        
#| $$      |  $$/ $$/ /$$| $$  /$$$$$$   /$$$$$$$| $$  \__/  /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$ 
#| $$$$$    \  $$$$/ | $$| $$ /$$__  $$ /$$__  $$| $$       /$$__  $$| $$  | $$ /$$__  $$|_  $$_/   /$$__  $$ /$$__  $$
#| $$__/     >$$  $$ | $$| $$| $$$$$$$$| $$  | $$| $$      | $$  \__/| $$  | $$| $$  \ $$  | $$    | $$$$$$$$| $$  \__/
#| $$       /$$/\  $$| $$| $$| $$_____/| $$  | $$| $$    $$| $$      | $$  | $$| $$  | $$  | $$ /$$| $$_____/| $$      
#| $$$$$$$$| $$  \ $$| $$| $$|  $$$$$$$|  $$$$$$$|  $$$$$$/| $$      |  $$$$$$$| $$$$$$$/  |  $$$$/|  $$$$$$$| $$      
#|________/|__/  |__/|__/|__/ \_______/ \_______/ \______/ |__/       \____  $$| $$____/    \___/   \_______/|__/      
#                                                                     /$$  | $$| $$                                    
#                                                                    |  $$$$$$/| $$                                    
#                                                                     \______/ |__/                                    


'''
Add support for these file types 

".3g2", ".3gp", ".asf", ".asx", ".avi", ".flv", 
".m2ts", ".mkv", ".mov", ".mp4", ".mpg", ".mpeg",
".rm", ".swf", ".vob", ".wmv" ".docx", ".pdf",".rar",
".jpg", ".jpeg", ".png", ".tiff", ".zip", ".7z", ".exe", 
".tar.gz", ".tar", ".mp3", ".sh", ".c", ".cpp", ".h", 
".gif", ".txt", ".py", ".pyc", ".jar", ".sql", ".bundle",
".sqlite3", ".html", ".php", ".log", ".bak", ".deb"
'''
#################---Imports---################## 
import datetime
import os 
import os.path
import random
import base64
import struct
import string 
import smtplib
import traceback 
import inspect 
import _thread  
import time 
import re
import urllib3

from tkinter import *
from tkinter import filedialog 
from tkinter.ttk import Progressbar
from tkinter import ttk 
from tkinter import messagebox
from tkinter.font import Font
from PIL import Image
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from multiprocessing import Pool
from cryptography.fernet import Fernet  #Authenticated cryptography which doesnt allow for file modification without key 
from threading import Thread
#################---Imports---##################

#################---Globals---################## 
mainFrame = None
emailTF = False 
prevdir = None
#################---Globals---##################

def generateFolders():    #Global function that generates our folders 

	folder1 = os.path.isdir('Encryption')
	folder2 = os.path.isdir('Keys')
	folder3 = os.path.isdir('Decryption')

	if (folder1 == False):
		try: 
			#Generate directories
			os.mkdir('Encryption')
		except:
			time.sleep(1) 
			return 
	elif (folder2 == False):
		try: 
			#Generate directories
			os.mkdir('Keys')
		except:
			time.sleep(1) 
			return 
	elif (folder3 == False):
		try: 
			#Generate directories
			os.mkdir('Decryption')
		except:
			time.sleep(1) 
			return 

#end_def


#MAIN THREADING CLASS  
class Multithreading(): 

	#Call this class first 
	#From this class, call the main application module 
	None 


#MAIN GUI CLASS - FUNCTIONALITY IS ALSO INCLUDED IN THIS CLASS  
class MainApplication():

	#Class vairables 
	dic = [(0, "Encrypt"), (1, "Decrypt"), (2, "Not Ready!")] #List options for radio buttons                                          
	messageBox = None          #Was having trouble with this, so just made it class var 
	fileList = []              #Hold files 
	scrolly = None             #Holds the scrollbar for text window 
	chosen = None              #Holds the variable for radio buttons 
	value = None               #Holds the updater for the progress bar 
	email = None               #Holds the email if there is one 
	prevdir = os.getcwd()	   #Holds the '/' directory 

	#Constructor 
	def __init__(self, master, *args, **kwargs):

		#Renaming the root 
		self.master = master
		
		#Setting initial value of radio buttons to "Not Ready!"
		choice = IntVar()
		choice.set(2)   
		self.chosen = choice

		#Setting initual value of the progress bar 
		value = IntVar()
		value.set(0)
		self.value = value 
	
		#Defining application container
		self.master.title('ExiledCrypter')                         
		self.master.geometry('768x432')                         
		self.master.resizable(height = False, width = False)   

		#Set the font for the welcome message
		myFont = Font(family = 'Times New Roman', size = 20)

		#Initial welcome message
		self.master.welcomeLabel = Label(self.master, text = "Welcome user!", 
										anchor = CENTER, bg = 'black', fg = "green",
										font = myFont, height = 2, width = 12).place(relx = .40, rely = .015 )

		#Creating a window for loaded files to be visible 
		fileWindow = Text(mainFrame, relief = RAISED, wrap = WORD, state = DISABLED)
		fileWindow.place(relx = .30, rely = 0.6, relwidth = 0.50, relheight = 0.3, anchor = 'n')
		self.messageBox = fileWindow

		#Adding a scrollbar to the loaded file window 
		self.scrolly = Scrollbar(self.messageBox, orient = VERTICAL, command = self.messageBox.yview)
		self.scrolly.pack(side = RIGHT, fill = 'y')

		#Configure both widgets to support dynamic scrolling 
		self.messageBox.configure(yscrollcommand = self.scrolly.set)    
		self.scrolly.configure(command = self.messageBox.yview)

		#This button will open browser and retrieve a file to encrypt 
		self.master.selectFiles = Button(self.master, text = "Select file(s)",
											width = None, 
											height = None, 
											fg = "green",
											bg = "black",
											font = ("arial", 10, "bold"),
											activebackground = 'green', 
											command = lambda: self.browseFiles())
		self.master.selectFiles.place(relx = 0.1, rely = 0.3, relwidth = 0.2, relheight = 0.1)

		Label(self.master,bg = "black", fg = "green", 
			text = "Files currently loaded:",
			font = ("arial", 10, "bold")).place(relx = 0.2, rely = 0.5, relwidth = 0.2, relheight = 0.09, anchor = 'n')

		self.master.clear = Button(self.master, text = "Clear",
									fg = "green", 
									bg = "black", 
									width = 16, 
									font = ("arial", 10, "bold"),
									command = self.clear)
		self.master.clear.place(relx = 0.59, rely = 0.9)

		#This button closes the program 
		self.master.exitButton = Button(self.master, text = "Exit", 
										fg = "green", 
										bg = "black",
										width = 16, 
										font = ("arial", 10, "bold"),
										command = self.quit)
		self.master.exitButton.place(relx = 0.8, rely = 0.9)
		
		#This field is used to take in the users email 
		self.master.email = Entry(self.master, text = "Enter Email", width = 30, state = DISABLED)
		self.master.email.place(x = 480, y = 360)#relx = 0.5, rely = 0.4)

		Label(self.master,bg = "black", fg = "green", font = ("arial", 10, "bold"), text = "Email to recieve key:").place(x = 480, y = 330, width = 185, height = 20)

		#This field is used to take in the users email 
		self.master.decKey = Entry(self.master, text = "Enter Key", width = 30, state = DISABLED)
		self.master.decKey.place(x = 480, y = 290)#relx = 0.5, rely = 0.4)

		Label(self.master,bg = "black", fg = "green", font = ("arial", 10, "bold"), text = "Decryption key:").place(x = 480, y = 260, width = 185, height = 20)


		style = ttk.Style() 
		style.theme_use('default')
		style.configure("grey.Horizontal.TProgressbar", background = 'green')

		#Setting the progress bar 
		self.master.progress_bar = Progressbar(self.master, orient = "horizontal", 
												mode = "determinate", 
												variable = self.value, 
												length = 400,
												maximum = 100,
												style='grey.Horizontal.TProgressbar')
		self.master.progress_bar.place(x = 38, y = 400)

		#This button is used to encrypt the list of files 
		self.master.encryptButton = Button(self.master, text = "Encrypt file(s)!", 
											fg = "green",
											bg = "black",
											activebackground = 'green',
											state = DISABLED, 
											font = ("arial", 12, "bold"),
											command = lambda: self.encryptLogic())
		self.master.encryptButton.place(x = 540, y = 130, width = 200, height = 50)

		#This button is used to decrypt the list of files 
		self.master.decryptButton = Button(self.master, text = "Decrypt file(s)!", 
											fg = "green", 
											bg = "black",
											activebackground = 'green',
											state = DISABLED, 
											font = ("arial", 12, "bold"),
											command = lambda: self.decryptLogic())
		self.master.decryptButton.place(x = 540, y = 200, width = 200, height = 50)
	
		#Setup for the radio buttons 
		self.master.chosenLabel = Label(self.master, text = "Select an option:", 
										fg = "green", 
										bg = "black",
										height = 2, 
										width = 14,
										font = ("arial", 10, "bold")).place(x = 325, y = 100)
		
		#NotReady radio button
		self.master.r1 = Radiobutton(self.master, text = self.dic[2][1], 
									variable = self.chosen, 
									value = self.dic[2][0], 
									bg = "black",
									fg = "green", 
									activebackground = 'green',
									font = ("arial", 10, "bold"),
									command = lambda: self.Choose(0)).place(x = 325, y = 150)
		#Encrypt radio button
		self.master.r2 = Radiobutton(self.master, text = self.dic[0][1], 
									variable = self.chosen, 
									value = self.dic[0][0], 
									bg = "black",
									fg = "green",
									activebackground = 'green',
									font = ("arial", 10, "bold"), 
									command = lambda: self.Choose(1)).place(x = 325, y = 180)
		#Decrypt radio button
		self.master.r3 = Radiobutton(self.master, text = self.dic[1][1], 
									variable = self.chosen, 
									value = self.dic[1][0], 
									bg = "black",
									fg = "green", 
									activebackground = 'green',
									font = ("arial", 10, "bold"),
									command = lambda: self.Choose(2)).place(x = 325, y = 210)

	#end_CONSTRUCTOR



##########################################################################
#      _                                _   _               _      
#  ___| | __ _ ___ ___   _ __ ___   ___| |_| |__   ___   __| |___  
# / __| |/ _` / __/ __| | '_ ` _ \ / _ \ __| '_ \ / _ \ / _` / __| 
#| (__| | (_| \__ \__ \ | | | | | |  __/ |_| | | | (_) | (_| \__ \ 
# \___|_|\__,_|___/___/ |_| |_| |_|\___|\__|_| |_|\___/ \__,_|___/                                      
##########################################################################



	def status_bar(self):   #Responsible for updating our status bar

		#Start the progress bar display 
		self.master.progress_bar.start()

		#Step the progress bar to 100 
		while (self.value.get() != 100):
			self.master.progress_bar.step(100)
			self.value.set(100)

		#Once the progress bar is full stop it 
		self.master.progress_bar.stop()

		#Display a success message 
		messagebox.showinfo("Message!", "All operations successful!")

		#Reset the variables 
		self.value.set(0)

	#end_def

	def Choose(self, x):   #Alters available buttons based on choice 

		#Guarantee no issues with operation
		generateFolders()
		self.focus()

		if (x == 1):
		#Enable the encrypt button, disable decrypt 
			self.master.encryptButton.configure(state = NORMAL)
			self.master.decryptButton.configure(state = DISABLED)
			self.master.email.configure(state = NORMAL)
			self.master.decKey.configure(state = DISABLED)

		elif (x == 2):
			#Enable the decrypt button, disable encrypt 
			self.master.encryptButton.configure(state = DISABLED)
			self.master.decryptButton.configure(state = NORMAL)
			self.master.email.configure(state = DISABLED)
			self.master.decKey.configure(state = NORMAL)

		else: 
			#Disable both buttons by default 
			self.master.encryptButton.configure(state = DISABLED)
			self.master.decryptButton.configure(state = DISABLED)
			self.master.email.configure(state = DISABLED)
			self.master.decKey.configure(state = DISABLED)

		return 
	#end_def


	def focus(self):    
		#This is used by every button controller function 
		#To take the cursor out of focus of any text box 
		self.master.focus_set()
	#end_def

	def encryptLogic(self):    #Primary logic to handle the encryption 

		self.focus()

		path = 'Encryption'
		pathkey = 'Keys'
		iter1 = 0
		filename = ""
		largest = 0
		newdir = None 
		prevdir = None 

		#Check to make sure that the fileList is not empty 
		if (len(self.fileList) > 0): 
				
			#Check to verify that an encryption folder exists 
			if (os.path.isdir(path) == True):

				#Check to verify that a key folder exists 
				if (os.path.isdir(pathkey) == True):

					#Encrypt each file in the list 
					while (iter1 != len(self.fileList)):

						#Grab the name of each file in the list 
						head_tail = os.path.split(self.fileList[iter1])
						
						#Save the currentdir to back track later 
						prevdir = os.getcwd()

						#CD into the 'Encryption' folder
						os.chdir(path)

						#Take the name with .txt extention and make it .exile 
						evalName = head_tail[1].replace('.txt', '.exile')

						#Check to see if a pre crypted file exists 
						if (os.path.isfile(evalName) == True):

							#LOOP THROUGH THE DIRECTORY TO FIND EACH FILE in 'Encryption'
							for filename in os.listdir(newdir):
								
								#Reset the specific file counter 
								number = 0

								#Get the number of the last file 
								for i in filename: 

									#Add each digit to a counter 
									if i.isdigit():
										number = number + int(i)
									else: 
										pass

								#A sort of bubble sort to get us to the latests file number 
								if number >= largest:
									largest = number 

							#Set the new file name to be generated 
							var = head_tail[1].replace(".txt", "")
							newFileName = var + (str(largest + 1)) + ".exile"

							#Create our process pool
							#pool = Pool(processes = 4)
							#pool.map(funcall, file)

							#Send file and new filename to encryption method 
							key = self.crypty(self.fileList[iter1], newFileName)

						else: #There is no previous encryption file
							
							#Set the new file name 
							newFileName = (head_tail[1].replace(".txt", ".exile"))

							#Send file and new filename to encryption method 
							key = self.crypty(self.fileList[iter1], newFileName)

						#CD out of the 'Encryption' folder 
						os.chdir(prevdir)

						#Check to see if an email is entered
						if (self.getEmail() == False):

							#CD into the 'Keys' folder  
							os.chdir(pathkey)

							#Reset our file counter 
							largest = 0 

							var = head_tail[1].replace(".txt", "key.txt")

							#Check if there is a pre-existing key file 
							if (os.path.isfile(var) == True):
								
								#LOOP THROUGH THE DIRECTORY TO FIND EACH FILE in 'Encryption'
								for filename in os.listdir(newdir):

									#Reset the specific file counter 
									number = 0

									#Get the number of the last file 
									for i in filename: 

										#Add each digit to a counter 
										if i.isdigit():
											number = number + int(i)
										else: 
											pass

									#A sort of bubble sort to get us to the latests file number 
									if number >= largest:
										largest = number 

								#Set the new file name to be generated 
								var = head_tail[1].replace(".txt", "")
								newFileName = var + "key" + (str(largest + 1)) + ".txt"

								#Create file and write key 
								fileGEN = open(newFileName, "w")
								fileGEN.write(key)
								fileGEN.close()


							else: #There is no previous key file 
								
								#Set the new file name to be generated 
								var = head_tail[1].replace(".txt", "key.txt")

								#Create file and write key 
								fileGEN = open(var, "w")
								fileGEN.write(key)
								fileGEN.close()
						else:
							#Check for a valid connection 
							if self.checkinternet(): 
								#If we have an email send it 
								if self.SMTP_me(self.email, key):
									messagebox.showinfo("Message!", "Email with key may have been sent!")
								else:
									messagebox.showerror("Warning!", "\tEmail with key not sent!\nYou must configure SMTP settings in source code")
							else: 
								messagebox.showerror("Warning!", "Connection issue, Email with key not sent!")

						#CD out of the 'Keys' folder 
						os.chdir(prevdir)
						iter1 = iter1 + 1

				#'Keys' path not valid 
				else:
					messagebox.showerror("Warning!", " 'Keys' directory is missing!")
					return None 

			#'Encryption' path not valid 
			else:
				messagebox.showerror("Warning!", " 'Encryption' directory is missing!")
				return None 

		#No files selected
		else: 
			messagebox.showerror("Warning!", " Please first select files to encypt")
			return None 

		self.status_bar() 
	#end_def


	def crypty(self, encFileName, genFileName, chunksize = 64*1024):       #This is the function that actuall encrypts the file 

		#Generate the key 
		key = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(32))
		#key = RSA.generate(2048)

		#Setup initialization vector 
		iv = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(16))

		#Create AES_CBC cipher 
		cipher = AES.new(key.encode("utf8"), AES.MODE_CBC, iv.encode("utf8"))
		filesize = os.path.getsize(encFileName)

		#Open both file to read and write from 
		with open(encFileName, 'rb') as infile:
			with open(genFileName, 'wb') as outfile:

				#Setup (filesize and iv) for decryption
				outfile.write(struct.pack("<Q", filesize))
				outfile.write(iv.encode("utf8"))

				while True:
					#Read current data and check padding 
					chunk = infile.read(chunksize)
					if len(chunk) == 0:
						break
					elif len(chunk) % 16 != 0:
						#character * blocksize - len(chunk) % blocksize
						chunk += bytes((' ' * (16 - len(chunk) % 16)), encoding = 'utf8')

					#Generate actual encryption to file 
					outfile.write(cipher.encrypt(chunk))
		return key 
	#end_def

	def decryptLogic(self):     #Primary logic to handle the decryption

		self.focus()

		path = 'Decryption'
		encpath = 'Encryption'
		keypath = 'Keys'
		prevdir = os.getcwd()
		iter1 = 0
		key = None

		#Make sure that files are selected 
		if (len(self.fileList) > 0):

			#Make sure that the Decryption folder is valid
			if (os.path.isdir(path)):

				#Make sure that the Encryption folder is valid 
				if (os.path.isdir(encpath)):

					#Make sure that the Keys folder is valid 
					if (os.path.isdir(keypath)):
						
						#Move through each file in the list 
						while (iter1 < len(self.fileList)):

							largest = 0

							#Get the name of the file 
							head_tail = os.path.split(self.fileList[iter1])
							
							#Navigate to 'Encryption' folder
							os.chdir(encpath)

							#Make sure the encrypted file is there 
							if (os.path.isfile(head_tail[1]) == True):

								#Check for previous decrypts of this filename
								evalName = head_tail[1].replace(".exile", ".txt")
								
								os.chdir(prevdir)# '/''
								os.chdir(path)# 'Decryption'

								#This file has been decrypted
								if (os.path.isfile(evalName) == True): 

									#LOOP THROUGH THE DIRECTORY TO FIND EACH FILE in 'Decryption'
									for filename in os.listdir():

										#Reset the specific file counter 
										number = 0

										#Get the number of the last file 
										for i in filename:

											#Add each digit to a counter 
											if i.isdigit():
												number = number + int(i)
											else: 
												pass

										#A sort of bubble sort to get us to the latests file number 
										if number >= largest:
											largest = number 

									#Set the new file name to be generated 
									var = head_tail[1].replace(".exile", "")
									newFileName = var + (str(largest + 1)) + ".txt"

								else:
									newFileName = head_tail[1].replace(".exile", ".txt")

								key = self.master.decKey.get()

								#A key was provided
								if (len(key) > 0):

									#start from home
									os.chdir(prevdir)

									#Send file to decryption
									self.decrypty(key, head_tail[1], newFileName, prevdir)

									#Go back to / directory
									os.chdir(prevdir)

								#Key field left empty so we will look for one 
								else:
									#messagebox.showinfo("Message!", "No key present, checking Keys folder for corresponding key")

									#Rearagne needed file
									var = head_tail[1].replace(".exile", "")
									var = var + "key.txt"

									
									#CD into 'Keys' folder
									os.chdir(prevdir)
									os.chdir(keypath)

									#Check for an existing key 
									if var in os.listdir():

										#Open found file
										with open(var, 'r') as infile:
											
											key = infile.read()
											messagebox.showinfo("Message!", "Successfully found a key file for\n" + head_tail[1])
											
											#start from home
											os.chdir(prevdir)

											#Send file to decryption
											self.decrypty(key, head_tail[1], newFileName, prevdir)

											#Go back to / directory
											os.chdir(prevdir)
									
									else:
										messagebox.showerror("Warning!", "Pre-exising key not found for\n" + head_tail[1])

							#The file is not in 'Encryption'
							else:
								messagebox.showerror("Warning!", "This file is not valid\n" + head_tail[1])
								return None 

							os.chdir(prevdir)
							iter1 += 1    
					else: 
						messagebox.showerror("Warning!", " 'Keys' directory is missing!")
						return None
				else: 
					messagebox.showerror("Warning!", " 'Encryption' directory is missing!")
					return None
			#'Decryption' path not valid 
			else: 
				messagebox.showerror("Warning!", " 'Decryption' directory is missing!")
				return None
		#No files selected
		else: 
			messagebox.showerror("Warning!", " Please first select files to encypt")
			return None 
			
		self.status_bar()
	#end_def



	def decrypty(self, key, encryptedFile, decryptedFile, prevdir, chunksize = 24*1024):      #This is the function that handles all the actual decryption 
		
		#Change to bytes 
		key = str.encode(key)

		os.chdir(prevdir)	# /
		os.chdir('Encryption')	# 'Encryption'

		#Open the encrypted file 
		with open(encryptedFile, 'rb') as infile:

			#Get the original size of the file from first 8 bytes
			originalSize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
			
			#Get the vector from first 16 bytes 
			iv = infile.read(16)

			#Create decryptor object     
			decrypt = AES.new(key, AES.MODE_CBC, iv)

			#Go to / 
			os.chdir(prevdir)

			#Go to 'Decryption' to generate output file 
			os.chdir('Decryption')

			#Open the decrypted file 
			with open (decryptedFile, 'wb') as outfile: 
				
				while True:

					#Break up by chunks
					chunk = infile.read(chunksize)
					
					#Base case 
					if len(chunk) == 0:
						break
					#Decrypt the chunk
					outfile.write(decrypt.decrypt(chunk))

				#By truncation, we eliminate padding 
				outfile.truncate(originalSize)
		return None
	#end_def


	def getEmail(self):     #Method to check whether the user entered an email 

		#Take the text from the field 
		string = (self.master.email.get())
		string = string.replace(' ', '')

		#Set the expected regular expression 
		pattern = r"([\w\.-]+)@([\w\.-]+)(\.[\w\.]+)"

		#Check the field for a string 
		if (string != ""): 

			#Checking if that pattern is in our email 
			match = re.search(pattern, string)

			if match: #Email verified!

				self.email = string
				emailTF = True
				return emailTF
			else:   #String entered but not an email!

				#Generate a warning message 
				messagebox.showerror("Warning!", " Text entered but did not evaluate to a valid email!\n [email@domain.com]")
				emailTF = False
				self.email = "" 
				return emailTF 

		else: 
			#Generate an alert that keys will be stored locally 
			#messagebox.showinfo("Message!", "Email not entered, encryption/decryption key will be stored locally.")
			self.email = ""
			emailTF = False 
			return emailTF
	#end_def

	def updateFileMessageBox(self):    #Pointless auxillary meth to call another method to change text 

		#If we have a file selected 
		if self.fileList:

			#Display this file into text box 
			self.setTextInput(self.fileList)
	#end_def

	def setTextInput(self, listy):      #Set the text in the window 

		#Make textBox editable, set, re-disable 
		self.messageBox.configure(state = NORMAL)
		self.messageBox.delete(1.0, "end")
		self.messageBox.insert(1.0, listy)
		self.messageBox.configure(state = DISABLED)
	#end_def

	def browseFiles(self):      #This method spawns the os browser and selects files 

		self.focus()

		#Get the directory of the current file
		dir = os.path.dirname(os.path.realpath(__file__))

		#Command to open file explorer
		self.file = filedialog.askopenfilename(initialdir = dir, 
										title = "Select a file", 
										filetypes = (("Text files", "*.txt*"), ("All files", "*.*")))
		
		#If user doesnt select a file - do nothing 
		if (self.file == ""):
			return None 

		#If the fileList is empty just input it 
		if (len(self.fileList) == 0):
			self.fileList.append(self.file)
			self.updateFileMessageBox()

		#Loop through and check if element exists 
		for x in self.fileList:

			#Check to see if the selected files does not exists 
			if self.file not in self.fileList:
				
				#Set the file into the list 
				self.fileList.append(self.file)
				self.updateFileMessageBox()
			else: 
				pass
		return None
	#end_def

	def quit(self):     #End mainloop() and exit program 
		self.master.destroy()
		sys.exit(0)
	#end_def

	def trace(self):    #Print the stack trace 
		print(inspect.stack())

	#end_def 

	def Thredder():     #Thread manager 
		None
	#end_def

	def checkforKeyFile(): #Verify that the user has a valid license from DB
		None
	#end_def
 
	def clear(self):	#This will reset all fields and variables 
		
		self.focus()

		#Make textBox editable, clear, re-disable 
		self.messageBox.configure(state = NORMAL)
		self.messageBox.delete(1.0, "end")
		self.messageBox.configure(state = DISABLED)

		#Reset class variables 
		self.email = ""
		self.fileList = []
		self.value.set(0)
		self.chosen.set(2)

		os.chdir(self.prevdir)
		os.chdir('Encryption')
		
		#Find files/folders that dont belong and remove
		for file in os.listdir():
			if file.endswith(".txt") or os.path.isdir(file):  

				try:
					os.remove(file)
				except:
					os.rmdir(file)

		os.chdir(self.prevdir)
		os.chdir('Decryption')

		#Find files/folders that dont belong and remove
		for file in os.listdir():
			if file.endswith(".exile") or os.path.isdir(file):  
				
				try:
					os.remove(file)
				except:
					os.rmdir(file)

		os.chdir(self.prevdir)
		os.chdir('Keys')

		#Find files/folders that dont belong and remove
		for file in os.listdir():
			if file.endswith(".exile") or os.path.isdir(file):  
				try:
					os.remove(file)
				except:
					os.rmdir(file)

		os.chdir(self.prevdir)

		messagebox.showinfo("Message!", "All clear!")
	#end_def

	def checkinternet(self): #Check for an active internet connection 
		try:
			#Setting up a pool to make a request to google 
			http = urllib3.PoolManager()
			resp = http.request('GET', 'https://www.google.com/')
			
			#For success we should have 200 
			if resp.status == 200:
				return True
			else: 
				return False 
		except:
			return False
	 #end_def 

	def SMTP_me(self, email, key):    #Initialize the SMTP connection and email key 

		#Getting the current time to include in the email
		time = datetime.datetime.now()

		#Setup connection details 
		SERVER = 'smtp_server'      #Server ip 
		PORT = 'smtp_port'          #Server port 
		USER = 'smtp_address'       #Server username
		PASS = 'smtp_password'      #Server password 
		FROM = USER
		TO = 'User_input_addy'
		SUBJECT = 'Key'
		MESSAGE = '' + key + "\n" + str(time)


		try:
			#Start SMTP connection
			start = smtplib.SMTP()
			start.connect(SERVER, PORT)
			start.starttls()
			start.login(USER, PASS)
			start.send_message(MESSAGE)
			start.quit()

		except:     
			None
			
	#end_def


def main():

	#Check for valid key 

	#Create parent root window 
	root = Tk()   

	#Setup the background layout 
	background_img = PhotoImage(file = 'ilum.png')
	root.background = Label(root, image = background_img).pack(fill = BOTH, expand = YES)

	#Setup the app icon
	icon_img = PhotoImage(file = 'ilum2.png')
	root.call('wm', 'iconphoto', root._w, icon_img)

	#Call the class to complete operations 
	appObject = MainApplication(root)
	
	#Program loop
	root.mainloop()

if __name__ == "__main__":
	main()

