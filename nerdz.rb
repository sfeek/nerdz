#!/usr/bin/ruby 

$debug=false

##################
#  nerdz client	 #	
##################

# Register / Create New Config File
def cmd_register
	
	# Sanitize parameters
	if ARGV[1] == nil
		puts "\nInvalid Syntax - nerdz register <username> <hostname> <port>"
		return nil
	end
	if ARGV[2] == nil
		puts "\nInvalid Syntax - nerdz register <username> <hostname> <port>"
		return nil
	end
	if ARGV[3] == nil
		ARGV[3] = '5150'
	end
	begin
		username = ARGV[1].strip.downcase
		hostname = ARGV[2].strip
		port = ARGV[3].to_i
	rescue Exception => msg
		puts msg if $debug
		puts "\nBad Command Line Parameter!"
		return nil
	end

	# Make sure .nerdz directory exists or create if it doesn't
	begin
		if File.directory?($path) == false
			FileUtils.mkdir_p($path)
		end
	rescue Exception => msg
		puts msg if $debug
		puts "\nCannot Create .nerdz Directory!"
		return nil
	end

	# Create keys, open server, register user and upload public key
	begin
        # Quick test to make sure that we are not already locally registered
        if File.file?(File.expand_path("#{$path}/#{username}_nerdz_server.conf")) == true
            puts "\nUser #{username} Already Registered!"
			return nil    
        end

		puts "\nCreating Key Pair"
		make_keys(username)
		
        # Get public key from pem and hash the username
		hash_user = hash_data(username)
		pub_key = read_pub_key(username)

        # Open port and send to server
		s = TCPSocket.open(hostname,port)
		cmd = "register|#{hash_user}|#{pub_key}"
		s.puts cmd
    
        # Wait for response from server
		response = s.gets.strip
		case response 
		when "registered" 
			puts "\nUser #{username} Registered!"
		when "already_registered"
		    puts "\nUser #{username} Already Registered!"
			return nil
		when "failed"
			puts "\nUser Registration Failed!"
			return nil
		else
			puts "\nCorrupted Packet Received!"
			return nil
		end
	rescue Exception => msg
		puts msg if $debug
		puts "\nGeneral Registration Failure!"
		return nil
	ensure
		s.close unless s == nil
	end

	# Open config file and write data since registration was successful
	begin
		file = File.open(File.expand_path("#{$path}/#{username}_nerdz_server.conf"), "w")
		file.puts(hostname) 
		file.puts(port.to_s)
		puts "\nServer Config File Written to #{$path}" 
	rescue Exception => msg 
		puts msg if $debug
  		puts "\nError Writing Server Config File!"
  		return 1
	ensure
  		file.close unless file == nil
	end
	return 0
end

# Send message to one or more users
def cmd_send
    # Sanitize parameters
    if ARGV[1] == nil
        puts "\nInvalid Syntax - nerdz send <usernames_to> <username_from"
        return nil
    end

    if ARGV[2] == nil
        ARGV[2] = get_default
    end

    # Get usernames
    tusers = ARGV[1].strip.downcase.split(",")
    fusername = ARGV[2].strip.downcase

    # Let user know to enter a message
    puts "\nEnter Message, Ctrl-D to Send"

    # Get the text to send from STDIN
    inp = $stdin.read

    # Add our message header
    data = "**** From: #{fusername} - #{Time.now.asctime} ****\n".concat(inp)
  
 
    # Open config file to read host and port for user
    begin
        file = File.open(File.expand_path("#{$path}/#{fusername}_nerdz_server.conf"), "r")
        host=file.gets.strip 
        port=file.gets.strip.to_i
    rescue Exception => msg 
        puts msg if $debug
        puts "\nError Reading Server Config File or #{fusername} not Registered!"
        return nil
    ensure
        file.close unless file == nil
    end

    # Loop through each "To" user and send the data
    tusers.each do |tusername|
        send_each(tusername,fusername,data,host,port)
    end

    return 0
end        
     
# Send a message to one user
def send_each(tusername,fusername,data,host,port)
    begin
        # Hash the username
        hash_user = hash_data(tusername)
        
        # Open the socket and request public key for user
        s = TCPSocket.open(host,port)
        cmd = "send1|#{hash_user}"
        s.puts cmd

        # Interpret the results
        response = s.gets.strip
        case response 
        when "nouser" 
            puts "\nUser #{tusername} Does Not Exist!"
            return nil
        else
            # Get public key from returned data
            pub_key = key_from_Base64(response)
            
            # Encrypt the data with public key
            enc_data = encrypt_public(data,pub_key)
            
            # Send the data
            cmd = "send2|#{hash_user}|#{enc_data}"
            s.puts cmd
            
            # Interpret the results
            response = s.gets.strip
            case response 
            when "failed"
                puts "\nSend to user #{tusername} Failed!"
            when "sent"
                puts "\nMessage Sent to User #{tusername}"
            else
                puts "\nCorrupted Packet Received!"
            end
        end
    rescue Exception => msg 
        puts msg if $debug
        puts "\nGeneral Send Failure"
        return nil
    ensure
        s.close unless s == nil
    end
    return 0
end
   
# Watch the mailbox continuously
def cmd_read_watch(mode,prv_key)
    #Clean up username
    fusername = ARGV[1].strip.downcase

    # Open config file to read host and port for user
    begin
        file = File.open(File.expand_path("#{$path}/#{fusername}_nerdz_server.conf"), "r")
        host=file.gets.strip 
        port=file.gets.strip.to_i
    rescue Exception => msg 
        puts msg if $debug
        puts "\nError Reading Server Config File or #{fusername} not Registered!"
        return nil
    ensure
        file.close unless file == nil
    end

    # Read the mailbox
    begin
        # Hash the username
        hash_user = hash_data(fusername)

        # Open the socket and request challenge for mailbox of user
        s = TCPSocket.open(host,port)
        cmd = "read1|#{hash_user}"
        s.puts cmd

        # Interpret the results
        response = s.gets.strip

        case response 
        when "nomessage"
            if mode == "once"
                puts "\n **** NO MESSAGES ****\n"
                puts
            end
            return 0
        when "nouser" 
            puts "\nUser #{fusername} Has No Public Key!"
            return nil
        when "failed"
            puts "\nUser #{fusername} Mailbox Read Failed!"
            return nil   
        else
            # Decrypt the key that was sent from server
            dec_string=decrypt_RSA_public(response,prv_key)

            # Hash what we got from them
            hash_string = hash_data(dec_string)

            # Send it back to server to finish challenge
            s.puts hash_string

            # Wait for response
            response = s.gets.strip
            case response
            when "accepted"
                # Read messages from server
                messages = s.gets.strip.split("|")
                if messages.length == 0
                    if mode == "once"
                        puts "\n **** NO MESSAGES ****\n"
                        puts
                    end
                else
                    # Decrypt and Send messages to STDOUT
                    messages.reverse.each do |msg|
                        puts
                        puts decrypt_public(msg,prv_key)
                    end
                    puts
                end
            when "rejected"
                puts "\nUser #{fusername} Authentication Failed!"
                return nil
            when "failed"
                puts "\nUser #{fusername} Messagebox Read Failed!"
                return nil
            else
                puts "\nCorrupted Packet Received!"
                return nil
            end  
        end
    rescue Exception => msg 
        puts msg if $debug
        puts "\nGeneral Read Failure!"
        return nil
    end
    return 0
end

# Unregister User
def cmd_unregister
    # Sanitize parameters
    if ARGV[1] == nil
        puts "\nInvalid Syntax - nerdz unregister <username>"
        return nil
    end
    
    # Get the users private key
    prv_key=read_prv_key(ARGV[1].strip.downcase) 
    if prv_key == nil
        return nil
    end

    #Clean up username
    fusername = ARGV[1].strip.downcase

    # Open config file to read host and port for user
    begin
        file = File.open(File.expand_path("#{$path}/#{fusername}_nerdz_server.conf"), "r")
        host=file.gets.strip 
        port=file.gets.strip.to_i
    rescue Exception => msg 
        puts msg if $debug
        puts "\nError Reading Server Config File or #{fusername} not Registered!"
        return nil
    ensure
        file.close unless file == nil
    end

    # Check credentials and unregister user
    begin
        # Hash the username
        hash_user = hash_data(fusername)

        # Open the socket and request challenge for mailbox of user
        s = TCPSocket.open(host,port)
        cmd = "unregister|#{hash_user}"
        s.puts cmd

        # Interpret the results
        response = s.gets.strip

        case response 
        when "nouser" 
            puts "\nUser #{fusername} Has No Public Key!"
            return nil
        when "failed"
            puts "\nUser #{fusername} Unregistration Failed!"
            return nil   
        else
            # Decrypt the key that was sent from server
            dec_string=decrypt_RSA_public(response,prv_key)

            # Hash what we got from them
            hash_string = hash_data(dec_string)

            # Send it back to server to finish challenge
            s.puts hash_string

            # Wait for response
            response = s.gets.strip
            case response
            when "deleted"
                # Delete the config and key files
                conf = File.expand_path("#{$path}/#{fusername}_nerdz_server.conf")
                pubkeyname = File.expand_path("#{$path}/#{fusername}_public_key.pem")
		        prvkeyname = File.expand_path("#{$path}/#{fusername}_priv_key.pem")
 
                File.delete(conf) if File.exist?(conf)
                File.delete(pubkeyname) if File.exist?(pubkeyname)
                File.delete(prvkeyname) if File.exist?(prvkeyname)
        
                puts "\nUser #{fusername} Unregistered!"
            when "rejected"
                puts "\nUser #{fusername} Authentication Failed!"
                return nil
            when "failed"
                puts "\nUser #{fusername} Unregistration Failed!"
                return nil
            else
                puts "\nCorrupted Packet Received!"
                return nil
            end  
        end
    rescue Exception => msg 
        puts msg if $debug
        puts "\nGeneral Unregister Failure!"
        return nil
    end
    return 0
end

# Get default user from file
def get_default
    # Read from default.user file
    begin
        file = File.open(File.expand_path("#{$path}/default.user"), "r")
        user = file.gets.strip
        return user
    rescue Exception => msg 
        puts msg if $debug
        puts "\nNo Default User Set!"
        return nil
    ensure
        file.close unless file == nil
    end
end

# Set default user and write to file
def cmd_default
    # Sanitize parameters
    if ARGV[1] == nil
        puts "\nInvalid Syntax - nerdz default <username>"
        return nil
    end

    # Write to the default.user file
    begin
        file = File.open(File.expand_path("#{$path}/default.user"), "w")
        file.puts ARGV[1].strip
        puts "\nDefault User Set to #{ARGV[1].strip}"
        return 0
    rescue Exception => msg 
        puts msg if $debug
        puts "\nDefault User File Missing!"
        return nil
    ensure
        file.close unless file == nil
    end
end 

# Watch the mailbox every 5 seconds
def cmd_watch
    # Sanitize parameters
    if ARGV[1] == nil
        ARGV[1] = get_default
    end

    # Get the users private key
    prv_key=read_prv_key(ARGV[1].strip.downcase) 
    if prv_key == nil
        return nil
    end

    # Start watching for messages
    puts "\n**** Watching for Messages - Ctrl-C to Quit ****"    
    begin	
        while (true)
            cmd_read_watch("watch",prv_key)
            sleep 5
        end
    rescue Interrupt
    	exit 0
    end
end

# Read once
def cmd_read
    # Sanitize parameters
    if ARGV[1] == nil
        ARGV[1] = get_default
    end

    # Get the users private key
    prv_key=read_prv_key(ARGV[1].strip.downcase) 
    if prv_key == nil
        return nil
    end

    # Read the mailbox
    cmd_read_watch("once",prv_key)
end 

def cmd_help
	puts "Help Screen"
end

#####################
#  Main entry point #
#####################

require 'socket'
require 'openssl'
require 'base64'
require 'fileutils'
require_relative './public_encrypt'

#Global variable for path
$path = File.expand_path('~/.nerdz')

if ARGV[0] == nil
	puts "\nAvailable Commands are Register, Unregister, Default, Read, Send and Watch"
	exit 1
end

begin
	command = ARGV[0].downcase 

	case command
	when "register"
		cmd_register
	when "send"
		cmd_send
	when "read"
        cmd_read
	when "watch"
		cmd_watch
	when "help"
		cmd_help
    when "unregister"
        cmd_unregister
    when "default"
        cmd_default
	else
		puts "\nAvailable Commands are Register, Unregister, Default, Read, Send and Watch"
		exit 1
	end
rescue Exception => msg 
    puts msg if $debug
	exit 1
end
exit 0

