Dependencies:
bcrypt

Client (App) Requirements:
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


IMPORTANT 
Need to Uncomment these to for it to have a chance of working over the internet
#client(recipient_ip, recipient_port, selected_filepath)
#default_host = get_ip()
