from utils import Rsa, Aes

from tkinter.filedialog import askopenfilename
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs.dialogs import Messagebox

import threading
from datetime import datetime


rsa = None
aes = None

class showDisplay(threading.Thread):
    """Dispaly text message with thread."""

    def __init__(self, tag, msg):
        threading.Thread.__init__(self)
        self.tag = tag
        self.msg = msg
        self.now = datetime.now().time()
    
    def run(self):
        self.tag.configure(state=NORMAL)
        self.tag.insert(END, f'{self.now.hour:02}:{self.now.minute:02}:{self.now.second:02} {self.msg}')
        self.tag.see("end")
        self.tag.configure(state=DISABLED)
        return



class Main(ttk.Frame):
    """Main Windows App."""

    def __init__(self, master):
        super().__init__(master)
        self.pack(fill=BOTH, expand=YES)

        # Zone
        self.label = ttk.Label(self, text="Encryption / Decryption", font=("Arial", 20), padding=(15,15,0,0)).pack(fill=X, anchor=NW)
        self.rsa_zone = RsaZone(self)
        self.encrypt_zone = EncryptionZone(self)
        self.decrypt_zone = DecryptionZone(self)



class RsaZone(ttk.Frame):
    """RSA Zone for Genarate Key and Get Key from file."""

    def __init__(self, master):
        super().__init__(master, padding=(15,15,15,0))
        self.pack(fill=X, anchor=NW, side=TOP)

        # application variables
        self.path_private_var = ttk.StringVar(value='')
        self.path_public_var = ttk.StringVar(value='')

        # header and labelframe option container
        self.lf = ttk.Labelframe(self, text="RSA", padding=15, bootstyle=DARK)
        self.lf.pack(fill=BOTH, expand=YES)
        self.nb = ttk.Notebook(self.lf)
        self.nb.pack(fill=BOTH, expand=YES, side=BOTTOM, pady=(5,0))
        self.nb_public = ttk.Frame(self.nb, height=5)
        self.nb_public.pack(fill='both', expand=True)
        self.st_public = ttk.ScrolledText(self.nb_public, height=5, state=DISABLED)
        self.st_public.pack(fill=BOTH, expand=YES, side=BOTTOM)
        self.nb_private = ttk.Frame(self.nb, height=5)
        self.nb_private.pack(fill='both', expand=True)
        self.st_private = ttk.ScrolledText(self.nb_private, height=5, state=DISABLED)
        self.st_private.pack(fill=BOTH, expand=YES, side=BOTTOM)
        self.nb.add(self.nb_public, text='Public Key')
        self.nb.add(self.nb_private, text='Private Key')
        self.lf_gen = ttk.Labelframe(self.lf, text="Genarate key", padding=15)
        self.lf_gen.pack(fill=BOTH, expand=YES, side=LEFT, padx=(0,2.5))
        self.create_genarate_key()
        self.lf_get = ttk.Labelframe(self.lf, text="Get key from file", padding=15)
        self.lf_get.pack(fill=BOTH, expand=YES, side=LEFT, padx=(2.5,0))
        self.create_public_path_row()
        self.create_private_path_row()
        self.btn = ttk.Button(self.lf_get, command=self.rsa_get_key, text="GETKEY", bootstyle=PRIMARY).pack(pady=(15, 0))

    def print_privateKey(self):
        self.st_private.config(state=NORMAL)
        self.st_private.insert('1.0', rsa.privateKey)
        self.st_private.config(state=DISABLED)
    
    def print_publicKey(self):
        self.st_public.config(state=NORMAL)
        self.st_public.insert('1.0', rsa.publicKey)
        self.st_public.config(state=DISABLED)

    def rsa_get_key(self):
        """Get RSA Private/Public Key pair from file."""
        global rsa
        try:
            rsa = Rsa.getRSAKeyPair(self.path_private_var.get(), self.path_public_var.get())
            self.print_privateKey()
            self.print_publicKey()
            Messagebox.ok('Get Private / Public key pair complete.', title='Get RSA key Complete')
        except Exception as e:
            print(e)
            Messagebox.show_error("Can't get RSA key", title='Get RSA key Error')

    def create_genarate_key(self):
        """Create Radio button key size for gen key."""
        label = ttk.Label(self.lf_gen, text="What's your key size?")
        label.pack(fill=X, padx=5, pady=5)

        def rsa_genarate_key():
            global rsa
            try:
                rsa = Rsa.genarateRSA(int(self.selected_size.get()))
                self.print_privateKey()
                self.print_publicKey()
                Messagebox.ok('Create Private / Public key pair complete.', title='Genarate RSA key Complete')
            except Exception as e:
                print(e)
                Messagebox.show_error('Genarate not complete', title='Genarate RSA key Error')

        # radio buttons
        self.selected_size = ttk.StringVar()
        sizes = (('1024', 1024), ('2048', 2048), ('4096', 4096))
        for size in sizes:
            r = ttk.Radiobutton(self.lf_gen, text=size[0], value=size[1], variable=self.selected_size)
            r.pack(fill='x', padx=5, pady=5)
        # button
        button = ttk.Button(self.lf_gen, text="Genarate Key", command=rsa_genarate_key)
        button.pack(fill=X, padx=5, pady=5)

    def create_public_path_row(self):
        """Add path row to labelframe."""
        path_row = ttk.Frame(self.lf_get)
        path_row.pack(fill=X, expand=YES, pady=(15, 0))
        path_lbl = ttk.Label(path_row, text="Public Path", width=10)
        path_lbl.pack(side=LEFT, padx=(15, 0))
        path_ent = ttk.Entry(path_row, textvariable=self.path_public_var)
        path_ent.pack(side=LEFT, fill=X, expand=YES, padx=5)
        browse_btn = ttk.Button(
            master=path_row, 
            text="Browse", 
            command=self.on_browse_public, 
            width=8,
            bootstyle=(DARK, OUTLINE)
        )
        browse_btn.pack(side=LEFT, padx=5)
      
    def on_browse_public(self):
        """Callback for directory browse."""
        path = askopenfilename(title="Browse directory")
        if path:
            self.path_public_var.set(path)

    def create_private_path_row(self):
        """Add path row to labelframe."""
        path_row = ttk.Frame(self.lf_get)
        path_row.pack(fill=X, expand=YES)
        path_lbl = ttk.Label(path_row, text="Private Path", width=10)
        path_lbl.pack(side=LEFT, padx=(15, 0))
        path_ent = ttk.Entry(path_row, textvariable=self.path_private_var)
        path_ent.pack(side=LEFT, fill=X, expand=YES, padx=5)
        browse_btn = ttk.Button(
            master=path_row, 
            text="Browse", 
            command=self.on_browse_private, 
            width=8,
            bootstyle=(DARK, OUTLINE)
        )
        browse_btn.pack(side=LEFT, padx=5)
      
    def on_browse_private(self):
        """Callback for directory browse."""
        path = askopenfilename(title="Browse directory")
        if path:
            self.path_private_var.set(path)



class EncryptionZone(ttk.Frame):
    """Encryption Zone for encrypt file with LocalKey AES(Key, IV)."""

    def __init__(self, master):
        super().__init__(master, padding=15)
        self.pack(fill=X, expand=True, anchor=NW, side=LEFT)

        # application variables
        self.path_encrypt_var = ttk.StringVar(value='')
        self.path_LocalKey_var = ttk.StringVar(value='')

        # header and labelframe option container
        self.lf = ttk.Labelframe(self, text="AES Encryption", padding=15, bootstyle=DANGER)
        self.lf.pack(fill=X, expand=YES)
        self.create_path_encrypt_row()
        self.create_path_LocalKey_row()
        self.info = ttk.ScrolledText(self.lf, height=5, state=DISABLED)
        self.info.pack(fill=BOTH, expand=YES, side=TOP, pady=(5,0))

        # encrypt button
        self.btn = ttk.Button(self.lf, text="Encrypt", command=self.run_thr_encrypt, bootstyle=DANGER).pack(pady=(15, 0))

    def encrypt(self):
        """Encrypt file."""
        global rsa, aes
        thr_start = showDisplay(self.info, f'[START] AES Genarate Key and IV.\n')
        thr_start.start()
        thr_start.join()
        aes = Aes.genarateKeyAndIV(32)
        thr_aesKey = showDisplay(self.info, f'[INFO] AES Key ({len(aes.key)}) = {aes.key}\n')
        thr_aesKey.start()
        thr_aesKey.join()

        thr_encrypt = showDisplay(self.info, f'[WAITING] Encrypting file...\n')
        thr_encrypt.start()
        thr_encrypt.join()
        try:
            aes.encrypt(self.path_encrypt_var.get())
        except:
            thr_encrypt = showDisplay(self.info, f'[ERROR] Not found encrypt file...\n')
            thr_encrypt.start()
            thr_encrypt.join()
            return

        thr_LocalKey = showDisplay(self.info, f'[WAITING] Save AES key and IV to LocalKey file.\n')
        thr_LocalKey.start()
        thr_LocalKey.join()
        try:
            with open(self.path_LocalKey_var.get(), 'wb') as f:
                f.write(aes.key+aes.iv)
        except:
            aes.decrypt(self.path_encrypt_var.get())
            thr_LocalKey = showDisplay(self.info, f'[ERROR] Not found LocalKey file...\n')
            thr_LocalKey.start()
            thr_LocalKey.join()
            return

        thr_LocalKey = showDisplay(self.info, f'[WAITING] Encrypt LocalKey file with RSA public key\n')
        thr_LocalKey.start()
        thr_LocalKey.join()
        try:
            rsa.encrypt(self.path_LocalKey_var.get())
        except:
            aes.decrypt(self.path_encrypt_var.get())
            thr_LocalKey = showDisplay(self.info, f'[ERROR] Don\'t have RSA key.\n')
            thr_LocalKey.start()
            thr_LocalKey.join()
            return

        thr_done = showDisplay(self.info, f'[DONE] Complete.\n')
        thr_done.start()
        thr_done.join()
    
    def run_thr_encrypt(self):
        """Run with thread."""
        thr = threading.Thread(target=self.encrypt)
        thr.start()
    
    def create_path_encrypt_row(self):
        """Add path row to labelframe."""
        path_row = ttk.Frame(self.lf)
        path_row.pack(fill=X, expand=YES)
        path_lbl = ttk.Label(path_row, text="Encrypt Path", width=12)
        path_lbl.pack(side=LEFT, padx=(15, 0))
        path_ent = ttk.Entry(path_row, textvariable=self.path_encrypt_var)
        path_ent.pack(side=LEFT, fill=X, expand=YES, padx=5)
        browse_btn = ttk.Button(
            master=path_row, 
            text="Browse", 
            command=self.on_browse_encrypt, 
            width=8,
            bootstyle=(DARK, OUTLINE)
        )
        browse_btn.pack(side=LEFT, padx=5)
      
    def on_browse_encrypt(self):
        """Callback for directory browse."""
        path = askopenfilename(title="Browse directory")
        if path:
            self.path_encrypt_var.set(path)

    def create_path_LocalKey_row(self):
        """Add path row to labelframe."""
        path_row = ttk.Frame(self.lf)
        path_row.pack(fill=X, expand=YES, pady=(5, 0))
        path_lbl = ttk.Label(path_row, text="LocalKey Path", width=12)
        path_lbl.pack(side=LEFT, padx=(15, 0))
        path_ent = ttk.Entry(path_row, textvariable=self.path_LocalKey_var)
        path_ent.pack(side=LEFT, fill=X, expand=YES, padx=5)
        browse_btn = ttk.Button(
            master=path_row, 
            text="Save as", 
            command=self.on_browse_LocalKey, 
            width=8,
            bootstyle=(INFO, OUTLINE)
        )
        browse_btn.pack(side=LEFT, padx=5)
      
    def on_browse_LocalKey(self):
        """Callback for directory browse."""
        path = askopenfilename(title="Browse directory")
        if path:
            self.path_LocalKey_var.set(path)



class DecryptionZone(ttk.Frame):
    """Decryption Zone for decrypt file with LocalKey AES(Key, IV)."""

    def __init__(self, master):
        super().__init__(master, padding=15)
        self.pack(fill=X, expand=True, anchor=NW, side=LEFT)

        # application variables
        self.path_var = ttk.StringVar(value='')

        # application variables
        self.path_decrypt_var = ttk.StringVar(value='')
        self.path_LocalKey_var = ttk.StringVar(value='')

        # header and labelframe option container
        self.lf = ttk.Labelframe(self, text="AES Decryption", padding=15, bootstyle=INFO)
        self.lf.pack(fill=X, expand=YES)
        self.create_path_decrypt_row()
        self.create_path_LocalKey_row()
        self.info = ttk.ScrolledText(self.lf, height=5, state=DISABLED)
        self.info.pack(fill=BOTH, expand=YES, side=TOP, pady=(5,0))

        # encrypt button
        self.btn = ttk.Button(self.lf, text="Decrypt", command=self.run_thr_decrypt, bootstyle=SUCCESS).pack(pady=(15, 0))

    def decrypt(self):
        """Decrypt file."""
        global rsa, aes
        thr_start = showDisplay(self.info, f'[START] RSA decrypt LocalKey.\n')
        thr_start.start()
        thr_start.join()
        try:
            rsa.decrypt(self.path_LocalKey_var.get())
        except:
            thr_start = showDisplay(self.info, f'[ERROR] Not Found RSA key or LocalKey file.\n')
            thr_start.start()
            thr_start.join()
            return

        thr_aesKey = showDisplay(self.info, f'[WAITING] AES get Key from LocalKey file.\n')
        thr_aesKey.start()
        thr_aesKey.join()
        aes = Aes.getSecretKey(32, self.path_LocalKey_var.get())
        thr_aesKey = showDisplay(self.info, f'[INFO] AES Key ({len(aes.key)}) = {aes.key}\n')
        thr_aesKey.start()
        thr_aesKey.join()

        thr_decrypt = showDisplay(self.info, f'[WAITING] Decrypting file...\n')
        thr_decrypt.start()
        thr_decrypt.join()
        try:
            aes.decrypt(self.path_decrypt_var.get())
        except:
            rsa.encrypt(self.path_LocalKey_var.get())
            thr_decrypt = showDisplay(self.info, f'[ERROR] Not found decrypt file...\n')
            thr_decrypt.start()
            thr_decrypt.join()
            return
        
        thr_done = showDisplay(self.info, f'[DONE] Complete.\n')
        thr_done.start()
        thr_done.join()
    
    def run_thr_decrypt(self):
        """Run with thread."""
        thr = threading.Thread(target=self.decrypt)
        thr.start()
    
    def create_path_decrypt_row(self):
        """Add path row to labelframe."""
        path_row = ttk.Frame(self.lf)
        path_row.pack(fill=X, expand=YES)
        path_lbl = ttk.Label(path_row, text="Decrypt Path", width=12)
        path_lbl.pack(side=LEFT, padx=(15, 0))
        path_ent = ttk.Entry(path_row, textvariable=self.path_decrypt_var)
        path_ent.pack(side=LEFT, fill=X, expand=YES, padx=5)
        browse_btn = ttk.Button(
            master=path_row, 
            text="Browse", 
            command=self.on_browse_decrypt, 
            width=8,
            bootstyle=(DARK, OUTLINE)
        )
        browse_btn.pack(side=LEFT, padx=5)
      
    def on_browse_decrypt(self):
        """Callback for directory browse."""
        path = askopenfilename(title="Browse directory")
        if path:
            self.path_decrypt_var.set(path)

    def create_path_LocalKey_row(self):
        """Add path row to labelframe."""
        path_row = ttk.Frame(self.lf)
        path_row.pack(fill=X, expand=YES, pady=(5, 0))
        path_lbl = ttk.Label(path_row, text="LocalKey Path", width=12)
        path_lbl.pack(side=LEFT, padx=(15, 0))
        path_ent = ttk.Entry(path_row, textvariable=self.path_LocalKey_var)
        path_ent.pack(side=LEFT, fill=X, expand=YES, padx=5)
        browse_btn = ttk.Button(
            master=path_row, 
            text="Open", 
            command=self.on_browse_LocalKey, 
            width=8,
            bootstyle=(INFO, OUTLINE)
        )
        browse_btn.pack(side=LEFT, padx=5)
      
    def on_browse_LocalKey(self):
        """Callback for directory browse."""
        path = askopenfilename(title="Browse directory")
        if path:
            self.path_LocalKey_var.set(path)



if __name__ == '__main__':

    app = ttk.Window("Encryption & Decryption", minsize=(500, 500))
    Main(app)
    app.mainloop()



