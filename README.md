nerdz
=====

Nerdz encrypted messenger. (Public Key RSA 2048 and AES 256)

Installation and brief usage instructions:

	1. Install redis with defaults
	2. Install redis gem
	3. Start redis
	4. Start ./nerdz_server.rb
	5. In another terminal: 
		./nerdz.rb register <username> localhost
		./nerdz.rb send <to_username> <from_username>
		./nerdz.rb read <username>
		./nerdz.rb watch <username>
		./nerdz.rb unregister <username>



	
