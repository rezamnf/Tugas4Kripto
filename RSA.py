from sympy import randprime
import random

class RSA:
    def __init__(self, key_size=180):
        self.key_size = key_size
        self.e = None
        self.d = None
        self.n = None

    def gcd(self, a, b):
        while a != 0:
            a, b = b % a, a
        return b

    def extended_gcd(self, a, b):
        if a == 0:  # base
            return (b, 0, 1)
        g, y, x = self.extended_gcd(b % a, a)  # recc
        return (g, x - (b // a) * y, y)

    def mod_inverse(self, a, m):
        g, x, _ = self.extended_gcd(a, m)
        if g != 1:  # not exists
            raise Exception('Modular inverse not exists!')
        return x % m

    def generate_key(self):
        self.p = randprime(2**(self.key_size - 1), 2**self.key_size)
        self.q = randprime(2**(self.key_size - 1), 2**self.key_size)
        self.n = self.p*self.q
        self.toitent_euler = (self.p - 1) * (self.q - 1)

        while True:
            self.e = random.randrange(2 ** (self.key_size - 1), 2 ** self.key_size)
            if (self.gcd(self.e, self.toitent_euler) == 1):
                break
        self.d = self.mod_inverse(self.e, self.toitent_euler)

    def save_key(self, path, e, n, d):
        pub = open(path + ".pub", "w")
        pub.write(str(e) + " " + str(n))
        pub.close()
        pri = open(path + ".pri", "w")
        pri.write(str(d) + " " + str(n))
        pri.close()

    def load_public_key(self, path):
        f = open(path, "r")
        pub = f.read().split(" ")
        f.close()
        self.e = int(pub[0])
        self.n = int(pub[1])

    def load_private_key(self, path):
        f = open(path, "r")
        pri = f.read().split(" ")
        f.close()
        self.d = int(pri[0])
        self.n = int(pri[1])

    def rsa_sign(self, plaintext, d, n):		
        temp = (pow(plaintext, d, n))
        res = hex(temp)[2:]
        return res	

    def rsa_verify(self, pt, e, n, h):
        temp = int(pt, 16)
        res = (pow(temp, e, n))
        return res == h

    def save_eof(self, res, fname):
        with open("" + fname, "ab") as f:
            f.write(b"\n*** Begin of digital signature ****\n")
            f.write((str(res) + "\n").encode('utf-8'))
            f.write(b"*** End of digital signature ****\n")
        f.close()

    def save_nf(self, res, fname):
        with open(fname, "w") as f:
            f.write("*** Begin of digital signature ****\n")
            f.write(str(res) + "\n")
            f.write("*** End of digital signature ****\n")
        f.close()

    def writefile_bin(self, filename: str="output.png", content: str=""):
    # Menulis biner ke dalam file
        from pathlib import Path

        path = filename
        
        with open(path, 'wb') as file:
            bytes = []
            for char in content:
                byte = int.to_bytes(ord(char), 1, "big")
                bytes.append(byte)
            file.write(b"".join(bytes))

    def read_eof(self, path):
        m_text = ""
        content = ''
        signature = False
        f = self.readfile_bin(path)
        for line in f:   
            if (not signature):
                if line == ("*** Begin of digital signature ****"):
                    signature = True
                else:
                    m_text += (line)
            else:
                content = line.rstrip()
                break
        return m_text.rstrip(), content


    def read_nf(self, path_m, path_sign):
        m_text = self.read_m_separate(path_m)
        content = self.read_sign_separate(path_sign)
        return (m_text, content)

    def readfile_bin(self, filename: str = "blue.png"):
    # Membaca file menjadi biner
        from pathlib import Path
        path = filename
        
        with open(path, 'rb') as file:
            temp = []
            byte = file.read(1)
            while byte:
                temp.append(int.from_bytes(byte, "big"))
                byte = file.read(1)
            
            temp = [bin(bits)[2:] for bits in temp]
            result = []
            for e in temp:
                if len(e) < 8:
                    e = (8 - len(e)) * "0" + e
                result.append(e)
            msg = ""
            for e in result:
                msg += chr(int(e, 2))

            return "".join(msg).splitlines()

    def read_m_separate(self, path):
        m_text = ""
        f = self.readfile_bin(path)
        for line in f:
            m_text += line
        
        return m_text.rstrip()

    def read_sign_separate(self, path):
        signature = False
        content = ''
        f = self.readfile_bin(path)
        for line in f:
            if (not signature):
                if line == ("*** Begin of digital signature ****"):
                    signature = True                    
            else:
                content = line.rstrip()
                break       
        return content
