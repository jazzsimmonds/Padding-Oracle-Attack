import socket

class parameters():
    def __init__(self):
        self.iv = #add iv
        self.ciphertext = bytes.fromhex('') #add ciphertext

def check_padding(message):
    p = parameters()
    host = #ip address
    port = #port number
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    iv = bytes(p.iv,'ascii') + b'\x0A'
    message = message.hex()
    message = message.encode() + b'\x0A'
    responce = s.recv(1024)
    s.send(iv)
    responce = s.recv(1024)
    s.send(message)
    feedback = s.recv(1024)
    decoded_feedback = feedback.decode()
    print(decoded_feedback)
    invalid = b'Invalid Padding!\n'
    if decoded_feedback == invalid.decode():
        return False
    else:
        return True
  #  if decoded_feedback.find('Padding') == -1:
   #     return True
    #else:
     #   return False


def padding_oracle_attack():
    p = parameters()
    iv = bytes.fromhex(p.iv)
    ciphertext = p.ciphertext
    block_size = int(len(ciphertext)/16)
    plaintext = bytes()
    for block in range(block_size,0,-1):
        print("Block: ",block)
        c2 = ciphertext[(block-1)*16:block*16]
        if block == 1:
            c1 = iv
        else:
            c1 = ciphertext[(block-2)*16:(block-1)*16]
        
        c1_temp = c1
        dec = bytearray(iv)
        padding = 0
    
        for i in range(16,0,-1):
            print("Byte: ",i)
            padding+=1
            for byte in range(0,256):
                print("value: ",byte)
                c1_temp = bytearray(c1_temp)
                c1_temp[i-1] = (c1_temp[i-1]+1)%256
                crafted_ciphertext = bytes(c1_temp)+c2
                valid_padding = check_padding(crafted_ciphertext)
                if valid_padding:
                    dec[-padding]=c1_temp[-padding]^c1[-padding]^padding
                    
                    for k in range(1, padding+1):
                        c1_temp[-k]=padding+1 ^ dec[-k] ^ c1[-k]
                    break
        plaintext = bytes(dec)+bytes(plaintext)
    return plaintext[:-plaintext[-1]]
                
                
            
    
    
    
if __name__ == '__main__':
    print("Plaintext: ", padding_oracle_attack().decode("ascii"))