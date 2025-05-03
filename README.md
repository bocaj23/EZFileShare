EZFILESHARE

DEPENDENCIES:
  -  Python v3.13
  -  customtkinter
  -  tkinter
  -  zlib
  -  dataclasses
  -  upnpy
  -  pathlib
  -  requests

HOW TO RUN:
When running the program for the first time you will be greeted with a log in screen. Type in a username and a password to go along with it.
Then hit register. It will say that an identifier.pem file has been created. This is your identifier token. If you lose it, the account will be lost.
This is by design as these accounts are meant to be disposable. If you lose your identifier.pem, you can re-register. The only thing you would have to change
is your settings.

Sending a file is very easy, you type in the desired name into the "To: " box and then hit "Select & Send." Once the file is
selected the client will attempt to send a file.

Receiving is a bit trickier. For one you must port forward traffic from port 65432 (or the port you select) to your computer. At which point
you will be able to receive files. All you do is it start server.
