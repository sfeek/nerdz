#!/usr/bin/ruby 

$debug=false


##################
#  nerdz client  #  
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
            remove_local_user_files(username)
            return nil    
        end
    
        # Make sure that key pair was created successfully
        puts "\nCreating Key Pair"
        if make_keys(username) == nil 
            puts "Unable to complete Key Creation! Mostly likely passwords did not match!"
            remove_local_user_files(username)
            return nil
        end
        
        # Get public key from pem and hash the username
        hash_user = hash_data(username)
        pub_key = key_to_Base64(read_pub_key(username))

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
            remove_local_user_files(username)
            return nil
        when "failed"
            puts "\nUser Registration Failed!"
            remove_local_user_files(username)
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
        puts "\nInvalid Syntax - nerdz send <usernames_to> <username_from>"
        return nil
    end

    # If no username was specified, load from default file
    if ARGV[2] == nil
        ARGV[2] = get_default
    end

    # Get usernames
    tusers = ARGV[1].strip.downcase.split(",")
    fusername = ARGV[2].strip.downcase

    # Let user know to enter a message
    puts "\nEnter Message, Ctrl-D to Send (Enter, CTRL-Z and Enter for Windows) or Ctrl-C to Cancel Message"

    # Keep our old STDIN for later
    $oldstdin = $stdin.dup

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

# Send file to one or more users
def cmd_sendfile
    # Sanitize parameters
    if ARGV[1] == nil
        puts "\nInvalid Syntax - nerdz filesend <filepath> <usernames_to> <username_from>"
        return nil
    end
    if ARGV[2] == nil
        puts "\nInvalid Syntax - nerdz filesend <filepath> <usernames_to> <username_from>"
        return nil
    end

    # If no username was specified, load from default file
    if ARGV[3] == nil
        ARGV[3] = get_default
    end

    # Get usernames
    tusers = ARGV[2].strip.downcase.split(",")
    fusername = ARGV[3].strip.downcase

    # Read the file and turn into base64
    begin
        # Check file size
        if File.size(File.expand_path(ARGV[1])) > (10*1048576)
            puts "File Greater than 10MB, Send Aborted!"
            return nil
        end
        # Read and convert file for sending
        file = File.open(File.expand_path(ARGV[1]), "rb") {|io| io.read}
        fname = File.basename(File.expand_path(ARGV[1]))
        data = "**** File [#{fname}] Downloaded From: #{fusername} - #{Time.now.asctime} ****\n|".concat(Base64.strict_encode64(file))
    rescue Exception => msg 
        puts msg if $debug
        puts "\nError Reading File to be Sent!"
        return nil
    end

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
    puts "Sending file..."
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

            # Check to see if pub_key exists
            if (pub_key_tmp = read_pub_key(tusername)) == nil
                # If not, create it
                puts "Creating New Local Public Key File for #{tusername}"
                write_pub_key(tusername,pub_key)
            else
                # If yes, compare downloaded to local copy
                if (key_to_Base64(pub_key) != key_to_Base64(pub_key_tmp))
                    puts "The Public Key for User #{tusername} does not match"
                    puts "the Local Copy. Please verify Public Key change with"
                    puts "#{tusername} to make sure they changed their Key."
                    puts "\nUpdate Local Public Key and Continue Sending? <Y/N>\n"
                    
                    #Reopen $stdin that was closed by previous CTRL-D or CTRL-Z
      		          $stdin.reopen($oldstdin)
					          answer = $stdin.gets.strip.downcase
                    if (answer == "y") or (answer == "yes")
                        puts "Updating Local Public Key File for #{tusername}"
                        write_pub_key(tusername,pub_key)
                    else
                        puts "Send to User #{tusername} Aborted!"
                        return nil
                    end
                end
            end
                         
            # Encrypt the data with public key
            enc_data = encrypt_public(data,pub_key)
            
            # Send the data
            cmd = "send2|#{hash_user}|#{enc_data}"
            s.puts cmd
            
            # Interpret the results
            response = s.gets.strip
            case response 
            when "sent"
                puts "\nSent to User #{tusername}"
            when "failed"
                puts "\nSend to user #{tusername} Failed!"
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
                    # Decrypt and Send messages to STDOUT or a File
                    messages.reverse.each do |messsage|
                        puts
                        process_message(messsage,prv_key)
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

# Process incoming decrypted message or file
def process_message (msg,prv_key)
    # Decrypt the message or file
    message = decrypt_public(msg,prv_key)
    fyn = message.match(/^\*\*\*\* File \[(.*)\]/)
    begin

    # Check if a message or a file
    if fyn == nil
        # A Message
        puts message
    else
        # A file
        fdata = message.split("|")
        puts fdata[0]
        puts "Accept File <Y/N>?"
        answer = $stdin.gets.strip.downcase

        if (answer == "y") or (answer == "yes")
            begin
                puts "File was Accepted!"
                fdata = message.split("|")
                file = File.open(fyn[1],'wb')
                file.syswrite(Base64.strict_decode64(fdata[1]))
            rescue Exception => msg 
                puts msg if $debug
                puts "\nError Writing File  #{fyn[1]}!"
                return nil
            ensure
                file.close unless file == nil
            end
        else
            puts "File was Discarded!"
        end
    end
     rescue Exception => msg 
        puts msg if $debug
    end    
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
                remove_local_user_files(fusername)
        
                puts "\nUser #{fusername} Unregistered!"
                return 0
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

# Show the help screen
def cmd_help
    puts "**** Help Screen ****"
    puts "\nnerdz register <username> <hostname> <port>"
    puts "nerdz unregister <username>"
    puts "nerdz default <username>"
    puts "nerdz read <username>"
    puts "nerdz send <usernames_to> <username_from>"
    puts "nerdz sendfile <filepath> <usernames_to> <username_from>"
    puts "nerdz watch <username>"
end

# Delete local user files
def remove_local_user_files(username)
    # Delete the config and key files
    conf = File.expand_path("#{$path}/#{username}_nerdz_server.conf")
    pubkeyname = File.expand_path("#{$path}/#{username}_public_key.pem")
    prvkeyname = File.expand_path("#{$path}/#{username}_priv_key.pem")

    File.delete(conf) if File.exist?(conf)
    File.delete(pubkeyname) if File.exist?(pubkeyname)
    File.delete(prvkeyname) if File.exist?(prvkeyname)
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
$path = File.expand_path('~/nerdz')
$oldstdin

if ARGV[0] == nil
    cmd_help
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
    when "sendfile"
        cmd_sendfile
    else
        cmd_help
        exit 1
    end
rescue Exception => msg 
    puts msg if $debug
    exit 1
end
exit 0


