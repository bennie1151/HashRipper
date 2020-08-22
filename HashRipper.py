#!/usr/bin/env python3

#Coded by S4RR4
#Contributed by გიო რგი

from urllib.request import urlopen
import hashlib
import os
import signal

def keyboardInterruptHandler(signal, frame):
    print("\nპროგრამა გაითიშა.".format(signal))
    exit(0)

signal.signal(signal.SIGINT, keyboardInterruptHandler)

os.system('clear')

                                                                                                                                                                                       
print("    _   _           _    ______ _                           ")
print("   | | | |         | |   | ___ (_)                          ")
print("   | |_| | __ _ ___| |__ | |_/ /_ _ __  _ __   ___ _ __     ")
print("   |  _  |/ _` / __| '_ \|    /| | '_ \| '_ \ / _ \ '__|    ")
print("   | | | | (_| \__ \ | | | |\ \| | |_) | |_) |  __/ |       ")
print("   \_| |_/\__,_|___/_| |_\_| \_|_| .__/| .__/ \___|_|.py    ")
print("                                 | |   | |                  ")
print("                                 |_|   |_|                  ")
print("\n                   ▶ Coded by S4RR4 ◀                       ")
print("               ▶ Contributed by გიო რგი ◀\n                   ")
print("https://github.com/AnonymousFromGeorgia/HashRipper            ")
print("\nℹ️HashRipper.py - გატეხე ან შექმენი სასურველი ჰეში სწრაფად და მარტივად.\n")

e	= '\033[0m'
r	= '\033[1;31m'
g	= '\033[1;32m'
y	= '\033[1;33m'
w	= '\033[1;37m'

print(w+"[1] გატეხე MD-5")
print(w+"[2] გატეხე SHA-1")
print(w+"[3] გატეხე SHA-256")
print(w+"[4] გატეხე SHA-512")
print(w+"[5] გატეხე SHA-224")
print(w+"[6] შექმენი ჰეში\n")




opt = input(y+"აირჩიე პარამეტრი: ")
print('\n')

#სანიმუშო ლექსიკონის ბმული
#https://gist.githubusercontent.com/roycewilliams/4003707694aeb44c654bf27a19249932/raw/7afc95e02df629515960a3e45109e6f88db3a99e/rockyou-top15k.txt

#სანიმუშო ჰეშები 
#სიტყვა --> !QAZ2wsx
#MD5 --> a1e0476879cab2a76cc22c80bbf364dd
#SHA1 --> 3357229dddc9963302283f4d4863a74f310c9e80
#SHA224 --> e2543fb1005b10532cec3f962cc56c5b64b829fa197f6ee46b5d8149
#SHA512 --> 4d2fa38025252a7aa0e1d4b22cb7d5981ccde72cf6eea8f102214baf089eb90d2816bb0adedf779d924a89df24d06794d5497533a5345979244e09fa3659ff21
#SHA256 --> 514cedc5a74404407cb25627410a3e8287d284f3da11ac4fea1725a649b9f987

if opt == '2':
    passurl = input('შეიყვანე ლექსიკონის ბმული: ') 
    passlist = str(urlopen(passurl).read(), 'utf-8')
    print('\n')
    sha1 = input(w+'[*] შეიყვანე ჰეში: ')
    for password in passlist.split('\n'):
        sha1g = hashlib.sha1(bytes(password, 'utf-8')).hexdigest()
        if sha1g == sha1:
            print(g+"[+] სწორი პაროლია: " + str(password))
            quit()
        else:
            print(r+'[-] : ' + str(password))

if opt == '1':
    passurl = input('შეიყვანე ლექსიკონის ბმული: ') 
    passlist = str(urlopen(passurl).read(), 'utf-8')
    print('\n')
    
    md5 = input(w+"[*] შეიყვანე ჰეში: ")
    for password in passlist.split('\n'):
        md5g = hashlib.md5(bytes(password, 'utf-8')).hexdigest()
        if md5g == md5:
            print(g+"[+] სწორი პაროლია: " + str(password))
            quit()
        else:
            print(r+"[-] : " + str(password))
    
    print('\n')
    print(y+'[*] მოცემული ლექსიკონიდან სწორი პაროლი სამწუხაროდ ვერ მოიძებნა.')
    print('\n')

if opt == '3':
    passurl = input('შეიყვანე ლექსიკონის ბმული: ') 
    passlist = str(urlopen(passurl).read(), 'utf-8')
    print('\n')
    
    sha256 = input(w+"[*] შეიყვანე ჰეში: ")
    for password in passlist.split('\n'):
        sha256g = hashlib.sha256(bytes(password, 'utf-8')).hexdigest()
        if sha256g == sha256:
            print(g+'[+] სწორი პაროლია: ' + str(password))
            quit()
        else:
            print(r+'[-] : ' + str(password))
    print('\n')
    print(y+'[*] მოცემული ლექსიკონიდან სწორი პაროლი სამწუხაროდ ვერ მოიძებნა.')
    print('\n')

if opt == '4':
    passurl = input('შეიყვანე ლექსიკონის ბმული: ') 
    passlist = str(urlopen(passurl).read(), 'utf-8')
    print('\n')
    
    sha512 = input(w+"[*] შეიყვანე ჰეში: ")
    for password in passlist.split('\n'):
        sha512g = hashlib.sha512(bytes(password, 'utf-8')).hexdigest()
        if sha512g == sha512:
            print(g+"[+] სწორი პაროლია: " + str(password))
            quit()
        else:
            print(r+'[-] : ' + str(password))
    
    print('\n')
    print(y+'[*] მოცემული ლექსიკონიდან სწორი პაროლი სამწუხაროდ ვერ მოიძებნა.')
    print('\n')


if opt == '5':
    passurl = input('შეიყვანე ლექსიკონის ბმული: ') 
    passlist = str(urlopen(passurl).read(), 'utf-8')
    print('\n')
    
    sha224 = input(w+'[*] შეიყვანე ჰეში: ')
    for password in passlist.split('\n'):
        sha224g = hashlib.sha224(bytes(password, 'utf-8')).hexdigest()
        if sha224g == sha224:
            print(g+"[+] სწორი პაროლია: " + str(password))
            quit()
        else:
            print(r+"[-] : " + str(password))

    print('\n')
    print(y+'[*] მოცემული ლექსიკონიდან სწორი პაროლი სამწუხაროდ ვერ მოიძებნა.')
    print('\n')




if opt == '6':
    
    os.system('clear')
    print(" _   _           _               ")
    print("| | | | __ _ ___| |__   ___ _ __ ")
    print("| |_| |/ _` / __| '_ \ / _ \ '__|")
    print("|  _  | (_| \__ \ | | |  __/ |   ")
    print("|_| |_|\__,_|___/_| |_|\___|_| \n")

    hv = input(r + "[*] შეიყვანე სასურველი სიტყვა დასაშიფრად: ")

    print('\n')

    hj1 = hashlib.md5()
    hj1.update(hv.encode())
    print(y + '[+] MD5 --> ' + hj1.hexdigest())

    hj2= hashlib.sha1()
    hj2.update(hv.encode())
    print(y + '[+] SHA1 --> ' + hj2.hexdigest())

    hj3 = hashlib.sha224()
    hj3.update(hv.encode())
    print(y + '[+] SHA224 --> ' + hj3.hexdigest())


    hj4 = hashlib.sha512()
    hj4.update(hv.encode())
    print(y + '[+] SHA512 --> ' + hj4.hexdigest())

    hj5 = hashlib.sha256()
    hj5.update(hv.encode())
    print(y + '[+] SHA256 --> ' + hj5.hexdigest())
    print('\n')
