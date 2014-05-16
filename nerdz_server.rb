#!/usr/bin/ruby 

$debug=false

##################
#  nerdz server  #  
##################

# Reply to ping packets
def pong(client,cmd)
    sleep 2
    client.puts "pong\n"
end

# Register a new user
def register(client,cmd,redis)
    begin
        # Make sure input is clean
        if cmd[1] == nil
            client.puts "failed"
            return nil
        end
        if cmd[2] == nil
            client.puts "failed"
            return nil
        end

        key=cmd[1]
        data=cmd[2]

        # Add key tag
        key = "KEY-" + key

        # Check if already registered
        if redis.exists(key) == true 
            client.puts "already_registered"
            return nil
        end

        # Register new user
        if redis.set(key, data) != "OK"
            client.puts "failed"
            return nil
        end

        # Set expire to 30 days
        if redis.expire(key, "2592000") != true
            client.puts "failed"
            return nil
        end         

        # Success!
        client.puts "registered"
        return 0
    rescue Exception => msg
        puts msg if $debug
        client.puts "failed"        
        return nil
    end 
end

# Send to a client mailbox
def send(client,cmd,redis)
    begin
        # Make sure input is clean
        if cmd[1] == nil
            client.puts "failed"
            return nil
        end

        key=cmd[1]
    
        # Add key tag
        keykey = "KEY-" + key

        # Query Redis and send the public key to back to the client
        rdata = redis.get(keykey) 
        if rdata != nil
            client.puts rdata
        else
            client.puts "nouser"
            return nil
        end    
        
        # Wait for client to respond with data to be added to the database
        cmd=client.readline.strip.split('|')

        # Make sure input is clean
        if cmd[0] != "send2"
            client.puts "failed"
            return nil
        end
        if cmd[1] == nil
            client.puts "failed"
            return nil
        end
        if cmd[2] == nil
            client.puts "failed"
            return nil
        end

        key=cmd[1]
        data=cmd[2]
    
        # Add key tags
        keykey = "KEY-" + key
        keymsg = "MSG-" + key

        # Add message to user's list
        if redis.lpush(keymsg, data) == nil
            client.puts "failed"
            return nil
        end

        # Set message to expire in 30 days
        if redis.expire(keymsg, "2592000") != true
            client.puts "failed"
            return nil
        end     

        # Success!
        client.puts "sent"
        return 0
    rescue Exception => msg
        puts msg if $debug
        client.puts "failed"        
        return nil
    end 
end

# Read from client mailbox
def read(client,cmd,redis)
    begin
        # Make sure input is clean
        if cmd[1] == nil
            client.puts "failed"
            return nil
        end

        key=cmd[1]
    
        # Add key tags
        keykey = "KEY-" + key
        keymsg = "MSG-" + key

        # Reset user key expire to 30 days
        if redis.expire(keykey, "2592000") != true
            client.puts "failed"
            return nil
        end 

        # Query Redis and see if mailbox is empty, if so leave quickly 
        len = redis.llen(keymsg) 
        if len == 0
            client.puts "nomessage"
            return nil
        end 

        # Query Redis and get the public key for the user 
        rdata = redis.get(keykey) 
        if rdata == nil
            client.puts "nouser"
            return nil
        end    
    
        # Make a public key from the users key 
        pub_key = key_from_Base64(rdata)
        
        # Generate a random string and hash and keep for later
        string = generate_random_key(30)
        hash_string = hash_data(string)

        # Encrypt with RSA public key
        enc_rsa = encrypt_RSA_public(string,pub_key)
    
        # Send to client for verification
        client.puts enc_rsa

        # Wait for response from client
        response = client.gets.strip

        # Check response
        if response == hash_string then 
            client.puts "accepted"
        else
            client.puts "rejected"
            return nil
        end
        
        # Collect the messages from mailbox
        messages = ""
        
        while (msg=redis.lpop(keymsg)) != nil do
            messages.concat(msg+"|")
        end
        
        # Send them to the client
        client.puts messages
     rescue Exception => msg
        puts msg if $debug
        client.puts "failed"        
        return nil
    end 
end   

# Unregister a user
def unregister(client,cmd,redis)
    begin
        # Make sure input is clean
        if cmd[1] == nil
            client.puts "failed"
            return nil
        end

        key=cmd[1]
    
        # Add key tag
        keykey = "KEY-" + key
        keymsg = "MSG-" + key

        # Query Redis and get the public key for the user 
        rdata = redis.get(keykey) 
        if rdata == nil
            client.puts "nouser"
            return nil
        end    
    
        # Make a public key from the users key 
        pub_key = key_from_Base64(rdata)
        
        # Generate a random string and hash and keep for later
        string = generate_random_key(30)
        hash_string = hash_data(string)

        # Encrypt with RSA public key
        enc_rsa = encrypt_RSA_public(string,pub_key)
    
        # Send to client for verification
        client.puts enc_rsa

        # Wait for response from client
        response = client.gets.strip

        # Check response
        if response == hash_string then
            # Delete the public key and messages
            redis.del(keykey) 
            redis.del(keymsg)

            client.puts "deleted"
        else
            client.puts "rejected"
            return nil
        end
    rescue Exception => msg
        puts msg if $debug
        client.puts "failed"        
        return nil
    end 
end   
        
    

#####################
#  Main entry point #
#####################

require 'socket'
require 'redis'
require 'base64'
require_relative './public_encrypt'

puts "Usage: nerdz_server <listen port> <redis hostname> <redis port>"
puts "Ctrl-C to Stop Nerdz Server"

# Sanitize command line parameters
if ARGV[0]==nil
    ARGV[0]='5150'              
end
if ARGV[1]==nil
    ARGV[1]='localhost'
end
if ARGV[2]==nil
    ARGV[2]='6379'
end
begin
    lport=ARGV[0].strip.to_i
    rhostname=ARGV[1].strip
    rport=ARGV[2].strip.to_i
rescue Exception => msg
    puts msg if $debug
    puts "Bad Parameter Specified!"
    exit 1
end

# Connect with redis
begin
    redis = Redis.new(:host => rhostname, :port => rport, :db => 15)
    if redis.set("ping", "pong") == nil
        exit 1
    end
    puts "Connected to Redis Server"
rescue Exception => msg
    puts msg if $debug
    puts "Redis Server Connection Failed!"
    exit 1
end

# Open port for listening
begin
    server = TCPServer.open(lport)  
    puts "Nerdz Server Listening on #{lport}"
rescue Exception => msg
    puts msg if $debug
    puts "Unable to Listen on Port #{lport}, ABORTING!"
    exit 1
end

# Begin threaded client accept
begin
    while(true)                      
      Thread.start(server.accept) do |client|
        puts "Connection from #{client.peeraddr[2]}" if $debug
        begin    
            while (true) 
                cmd=client.readline.strip.split('|')
            
                case cmd[0]
                when "ping"
                    pong(client,cmd)
                when "register"
                    if register(client,cmd,redis) == nil
                        break
                    end
                when "send1"
                    if send(client,cmd,redis) == nil
                        break
                    end
                when "read1"
                    if read(client,cmd,redis) == nil
                        break;
                    end
                when "unregister"
                    if unregister(client,cmd,redis) == nil
                        break;
                    end                
                else
                    break
                end
            end
            client.close
        rescue Exception => msg
            puts msg if $debug
            client.close
        end                
      end
    end
rescue Interrupt
    # Exit due to Ctrl-C
    puts "\nClosing Port #{lport}"
    exit 0
end
