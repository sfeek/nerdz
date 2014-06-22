#!/usr/bin/ruby -w

require 'openssl'
require 'base64'


# Encrypt string using AES256 with another persons public key
# Input: string to be encrypted and public key
# Output: string containing encrypted data:key:IV in base64 encoding
def encrypt_public(string,key)
    begin
        # Encrypt with 256 bit AES with CBC
        cipher = OpenSSL::Cipher::Cipher.new('aes-256-cbc')

        # We are encypting
        cipher.encrypt 

        # The OpenSSL library will generate random keys and IVs
        cipher.key = random_key = cipher.random_key
        cipher.iv = random_iv = cipher.random_iv

        # Encrypt the data
        encrypted_data = cipher.update(string)
        encrypted_data << cipher.final

        # Create public key        
        public_key = OpenSSL::PKey::RSA.new(key)

        # Encrypt our AES key and IV
        encrypted_key = public_key.public_encrypt(random_key)
        encrypted_iv = public_key.public_encrypt(random_iv)

        # Creat Output string
        output=Base64.strict_encode64(encrypted_data)+":"+Base64.strict_encode64(encrypted_key)+":"+Base64.strict_encode64(encrypted_iv)
    rescue Exception => msg
        puts msg if $debug
        return nil
    end

    return output
end

# Decrypt using my private key
# Input Base64 encoded string data:key:IV and private key
# Output plain text string
def decrypt_public(string,key)
    begin

        # Split apart data, key, and IV
        data = string.split(":")
        
        # Decode from string back to binary format
        encrypted_data=Base64.strict_decode64(data[0])
        encrypted_key=Base64.strict_decode64(data[1])
        encrypted_iv=Base64.strict_decode64(data[2])

        # Create cipher object
        cipher = OpenSSL::Cipher::Cipher.new('aes-256-cbc')

        # We are decrypting
        cipher.decrypt

        # Set the key and IV
        cipher.key = key.private_decrypt(encrypted_key)
        cipher.iv = key.private_decrypt(encrypted_iv)

        # Perform the decryption and output
        decrypted_data = cipher.update(encrypted_data)
        decrypted_data << cipher.final

    rescue Exception => msg
        puts msg if $debug
        return nil
    end

    return decrypted_data
end

# Hash data and return base64 encoded string
def hash_data(data)
    begin
        sha256 = OpenSSL::Digest::SHA256.new
        string = Base64.encode64(sha256.digest(data)).strip
    rescue Exception => msg
        puts msg if $debug
        return nil
    end
    return string
end

# Create RSA key from Base64 string
def key_from_Base64(string)
    begin
        key = OpenSSL::PKey::RSA.new Base64.strict_decode64(string)
    rescue Exception => msg
        puts msg if $debug
        puts "Key Decode Error"
        return nil
    end
    
    return key
end

# Read public key from pem file and return as Base64 string
def read_pub_key(username)
    begin 
        pubkeyname = File.expand_path("#{$path}/#{username}_public_key.pem")
        
        file = File.open(pubkeyname, "rb")
        key = file.read
    rescue Exception => msg
        puts msg if $debug
        puts "Local Public Key Does Not Exist!"
        return nil
    ensure
        file.close unless file == nil
    end 
    
    return Base64.strict_encode64(key)
end

# Read private key from pem file and return as usable key
def read_prv_key(username)
    begin 
        prvkeyname = File.expand_path("#{$path}/#{username}_priv_key.pem")
        
        prv_key=OpenSSL::PKey::RSA.new File.read prvkeyname
    rescue Exception => msg
        puts msg if $debug
        puts "Private Key Read Failed!"
        return nil
    end
    return prv_key
end

# Create key pair and store in files
def write_pub_key(username,key)
    begin
        # Get the file paths
        pubkeyname = File.expand_path("#{$path}/#{username}_public_key.pem")
        
        # Write to file
        open pubkeyname, 'w' do |io| io.write key.public_key.to_pem end
    rescue Exception => msg
        puts msg if $debug
        puts "Key Write Failed!"
        return nil
    end
    return 0
end

# Create key pair and store in files
def make_keys(username)
    begin
        # New key
        key = OpenSSL::PKey::RSA.new 2048

        # Get the file paths
        pubkeyname = File.expand_path("#{$path}/#{username}_public_key.pem")
        prvkeyname = File.expand_path("#{$path}/#{username}_priv_key.pem")

        # Encrypt private key and save both keys to disk
        open pubkeyname, 'w' do |io| io.write key.public_key.to_pem end
        cipher = OpenSSL::Cipher.new 'AES-128-CBC'
        key_secure = key.export cipher
        open prvkeyname, 'w' do |io|
            io.write key_secure
        end
		return 0
    rescue Exception => msg
        puts msg if $debug
        puts "Key Pair Create Failed!"
        return nil
    end
    return 0
end

# Encrypt short string with RSA Public Key
def encrypt_RSA_public(string,key)
    begin
        encrypted_string = Base64.strict_encode64(key.public_encrypt(string))
    rescue Exception => msg
        puts msg if $debug
        return nil
    end
    return encrypted_string
end

# Decrypt short string with RSA Private Key
def decrypt_RSA_public(string,key)
    begin
        decrypted_string = (key.private_decrypt(Base64.strict_decode64(string)))
    rescue Exception => msg
        puts msg if $debug
        return nil
    end
    return decrypted_string
end

# Generate a random key and return as Base64
def generate_random_key(size)
    begin
        string=Base64.strict_encode64(OpenSSL::Random.random_bytes(size))
    rescue Exception => msg
        puts msg if $debug
        return nil
    end
    return string   
end










    
    

