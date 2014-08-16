nerdz
=====

Nerdz encrypted messenger. (Public Key RSA 2048 and AES 256)

Installation and brief usage instructions:

	1. Install redis with defaults
	2. Install redis ruby gem
	3. Start redis
	4. Install nerdz with ./installer.sh (You need to be root)
	5. Then in another terminal run:  nerdz_server
	6. In another terminal: 
		
		nerdz register <username@hostname>
		nerdz unregister <username@hostname>
		nerdz default <username@hostname>
		nerdz read <username@hostname>
		nerdz send <username@hostname_to> <username@hostname_from>
		nerdz sendfile <filepath> <username@hostname_to> <username@hostname_from>
		nerdz watch <username@hostname>
		
		Send and Sendfile can have multiple username@hostname entries separated by commas

