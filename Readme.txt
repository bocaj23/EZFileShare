Dependencies:
bcrypt

Client (App) Requirements:
friends.json
server.key
server.crt
client.key
client.crt
ca.crt

Server Requirements:
data.json
server.key
server.crt
ca.crt

Instructions to Run:
Make sure requirements are in the same directory
python P2P_User_Server.py (Must Start Server First)
then 
python P2P_File_Transfer.py
