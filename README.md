nerdz
=====

Nerdz encrypted messenger. (Public Key RSA 2048 and AES 256)

Installation and brief usage instructions:

	1. Install redis with defaults
	2. Install redis ruby gem
	3. Start redis
	4. Install nerdz with ./installer.sh (You need to be root)
	4. Then in another terminal run:  nerdz_server
	5. In another terminal: 
		nerdz register <username> <server_ip> <port> 				-Register User
		nerdz send <to_username> <from_username>  					-Send message to another User
		nerdz sendfile <filepath> <to_username> <from_username>  	-Send file to another User (10MB limit)
		nerdz read <username>  										-Read from a user message box
		nerdz watch <username>  									-Constantly watch a user messagebox
		nerdz unregister <username>  								-Unregister a user
		nerdz default <username>   									-Set Default Username
