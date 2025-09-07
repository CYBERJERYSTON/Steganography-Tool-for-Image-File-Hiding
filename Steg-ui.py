
from __future__ import annotations

import sys
import os
import struct
import argparse
import tempfile
from typing import Optional, Tuple

# PIL (Pillow) image library
try:
    from PIL import Image
except Exception as e:
    print('ERROR: Pillow (PIL) is required. Please install with `pip install pillow`')
    raise

# Optional: cryptography support
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

# GUI availability: try importing tkinter. If not present, we'll use CLI.
GUI_AVAILABLE = True
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    # import ImageTk lazily (Pillow's ImageTk may import tkinter internals)
    from PIL import ImageTk
except Exception:
    GUI_AVAILABLE = False

# Optional drag and drop lib (only used if GUI_AVAILABLE)
HAS_DND = False
if GUI_AVAILABLE:
    try:
        import tkinterdnd2
        HAS_DND = True
    except Exception:
        HAS_DND = False

HEADER_MAGIC = b'STEGv1'  # 6 bytes
# header layout: MAGIC(6) | flags(1) | filename_len(1) | filename(N) | payload_len(8)
# flags bits: 0x1 = is_file; 0x2 = encrypted

# === Utility functions ===

def bytes_to_bits(data: bytes):
    for b in data:
        for i in range(7, -1, -1):
            yield (b >> i) & 1


def bits_to_bytes(bits):
    b = bytearray()
    acc = 0
    c = 0
    for bit in bits:
        acc = (acc << 1) | (bit & 1)
        c += 1
        if c == 8:
            b.append(acc)
            acc = 0
            c = 0
    return bytes(b)


def calc_capacity(img: Image.Image) -> int:
    w, h = img.size
    return w * h * 3  # bits: 3 channels per pixel


def int_to_bytes64(n: int) -> bytes:
    return struct.pack('>Q', n)


def bytes64_to_int(b: bytes) -> int:
    return struct.unpack('>Q', b)[0]

# === Encryption helpers ===

def derive_key_from_password(password: str) -> bytes:
    # Simple KDF for demonstration. Replace with PBKDF2/scrypt for production use.
    from hashlib import sha256
    return sha256(password.encode('utf-8')).digest()


def encrypt_payload(payload: bytes, password: str) -> bytes:
    if not HAS_CRYPTO:
        raise RuntimeError('pycryptodome is required for encryption')
    key = derive_key_from_password(password)
    # Using a 12-byte nonce is common for GCM; we'll use 12 for compatibility.
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    # store as: nonce(12) + tag(16) + ciphertext
    return iv + tag + ciphertext


def decrypt_payload(enc: bytes, password: str) -> bytes:
    if not HAS_CRYPTO:
        raise RuntimeError('pycryptodome is required for decryption')
    key = derive_key_from_password(password)
    if len(enc) < 12 + 16:
        raise ValueError('Encrypted payload too short or corrupt')
    iv = enc[:12]
    tag = enc[12:28]
    ciphertext = enc[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

# === LSB embedding/extraction ===

def _choose_mode_and_bands(img: Image.Image) -> Tuple[Image.Image, bool]:
    """Return an image converted to RGB or RGBA and a boolean indicating if alpha is present."""
    bands = img.getbands()  # e.g. ('R','G','B') or ('R','G','B','A')
    has_alpha = 'A' in bands
    if has_alpha:
        return img.convert('RGBA'), True
    return img.convert('RGB'), False


def embed_bytes_into_image(img: Image.Image, payload: bytes) -> Image.Image:
    """Embed payload (bytes) into a copy of image using LSB of RGB channels.

    Returns a new PIL Image object (mode RGB or RGBA) with the payload embedded.
    """
    img, has_alpha = _choose_mode_and_bands(img)
    pixels = list(img.getdata())
    flat = []
    if has_alpha:
        for (r, g, b, a) in pixels:
            flat.extend([r, g, b, a])
    else:
        for (r, g, b) in pixels:
            flat.extend([r, g, b])

    # indices we can modify: RGB channels only (preserve alpha)
    mod_indices = []
    if has_alpha:
        for i in range(0, len(flat), 4):
            mod_indices.extend([i, i + 1, i + 2])
    else:
        mod_indices = list(range(len(flat)))

    capacity = len(mod_indices)
    bits = list(bytes_to_bits(payload))
    if len(bits) > capacity:
        raise ValueError(f'Payload too large: need {len(bits)} bits, capacity {capacity} bits')

    flat_copy = flat[:]  # copy
    for i, bit in enumerate(bits):
        idx = mod_indices[i]
        flat_copy[idx] = (flat_copy[idx] & ~1) | bit

    # reconstruct pixels
    new_pixels = []
    if has_alpha:
        for i in range(0, len(flat_copy), 4):
            new_pixels.append((flat_copy[i], flat_copy[i + 1], flat_copy[i + 2], flat_copy[i + 3]))
        new_img = Image.new('RGBA', img.size)
    else:
        for i in range(0, len(flat_copy), 3):
            new_pixels.append((flat_copy[i], flat_copy[i + 1], flat_copy[i + 2]))
        new_img = Image.new('RGB', img.size)

    new_img.putdata(new_pixels)
    return new_img


def extract_bytes_from_image(img: Image.Image, num_bits: int) -> bytes:
    img, has_alpha = _choose_mode_and_bands(img)
    pixels = list(img.getdata())
    flat = []
    if has_alpha:
        for (r, g, b, a) in pixels:
            flat.extend([r, g, b, a])
    else:
        for (r, g, b) in pixels:
            flat.extend([r, g, b])

    mod_indices = []
    if has_alpha:
        for i in range(0, len(flat), 4):
            mod_indices.extend([i, i + 1, i + 2])
    else:
        mod_indices = list(range(len(flat)))

    bits = []
    for i in range(min(num_bits, len(mod_indices))):
        bits.append(flat[mod_indices[i]] & 1)
    return bits_to_bytes(bits)

# === Pack header and payload ===

def make_stego_payload(payload: bytes, is_file: bool, filename: Optional[str], encrypt: bool, password: Optional[str]) -> bytes:
    flags = 0
    if is_file:
        flags |= 0x1
    data = payload
    if encrypt:
        if password is None:
            raise ValueError('Password required when encrypt=True')
        flags |= 0x2
        data = encrypt_payload(payload, password)
    name_bytes = filename.encode('utf-8') if (filename and is_file) else b''
    if len(name_bytes) > 255:
        raise ValueError('Filename too long (max 255 bytes)')
    header = HEADER_MAGIC + bytes([flags]) + bytes([len(name_bytes)]) + name_bytes + int_to_bytes64(len(data))
    return header + data


def parse_stego_header(stream_bytes: bytes):
    if len(stream_bytes) < 6 + 1 + 1 + 8:
        raise ValueError('Header too small')
    if stream_bytes[:6] != HEADER_MAGIC:
        raise ValueError('Magic header not found')
    flags = stream_bytes[6]
    name_len = stream_bytes[7]
    pos = 8
    filename = None
    if name_len:
        filename = stream_bytes[pos:pos + name_len].decode('utf-8')
    pos += name_len
    payload_len = bytes64_to_int(stream_bytes[pos:pos + 8])
    pos += 8
    return {
        'flags': flags,
        'is_file': bool(flags & 0x1),
        'encrypted': bool(flags & 0x2),
        'filename': filename,
        'payload_len': payload_len,
        'header_size': pos,
    }

# === File-based helpers (used by both GUI and CLI) ===

def embed_to_image_file(in_path: str, out_path: str, payload: bytes, is_file: bool = False, filename: Optional[str] = None, encrypt: bool = False, password: Optional[str] = None) -> str:
    img = Image.open(in_path)
    stego = make_stego_payload(payload, is_file, filename, encrypt, password)
    cap = calc_capacity(img)
    if len(stego) * 8 > cap:
        raise ValueError(f'Payload+header too large: need {len(stego)*8} bits, capacity {cap} bits')
    out_img = embed_bytes_into_image(img, stego)
    # Always save as PNG to preserve lossless data
    out_img.save(out_path, format='PNG')
    return out_path


def extract_from_image_file(in_path: str, password: Optional[str] = None) -> Tuple[dict, bytes]:
    img = Image.open(in_path)
    header_max_len = 6 + 1 + 1 + 255 + 8
    header_bytes = extract_bytes_from_image(img, header_max_len * 8)
    meta = parse_stego_header(header_bytes)
    total_bits = (meta['header_size'] + meta['payload_len']) * 8
    all_bytes = extract_bytes_from_image(img, total_bits)
    payload_bytes = all_bytes[meta['header_size']:meta['header_size'] + meta['payload_len']]
    if meta['encrypted']:
        if not password:
            raise ValueError('Payload is encrypted; password is required')
        payload_bytes = decrypt_payload(payload_bytes, password)
    return meta, payload_bytes

# === Simple CLI ===

def run_cli(argv=None):
    p = argparse.ArgumentParser(prog='steg-ui', description='Steganography tool (CLI mode)')
    sub = p.add_subparsers(dest='cmd', required=True)

    # Embed
    e = sub.add_parser('embed', help='Embed text or file into an image')
    e.add_argument('--in', dest='infile', required=True, help='Cover image (PNG/BMP recommended)')
    e.add_argument('--out', dest='outfile', required=True, help='Output stego image (PNG)')
    g = e.add_mutually_exclusive_group(required=True)
    g.add_argument('--text', dest='text', help='Text message to embed')
    g.add_argument('--file', dest='file', help='Path to file to embed')
    e.add_argument('--encrypt', action='store_true', help='Encrypt payload (AES-GCM)')
    e.add_argument('--password', help='Password for encryption')

    # Extract
    x = sub.add_parser('extract', help='Extract payload from a stego image')
    x.add_argument('--in', dest='infile', required=True, help='Stego image')
    x.add_argument('--out', dest='outfile', help='Output path (for extracted file). If not provided and payload is text, prints text.')
    x.add_argument('--password', help='Password (if encrypted)')

    # Capacity
    c = sub.add_parser('capacity', help='Show approximate capacity of an image')
    c.add_argument('--in', dest='infile', required=True, help='Image file')

    # Selftest
    s = sub.add_parser('selftest', help='Run a basic self-test (embed+extract)')

    args = p.parse_args(argv)

    try:
        if args.cmd == 'embed':
            if args.text:
                payload = args.text.encode('utf-8')
                is_file = False
                filename = None
            else:
                with open(args.file, 'rb') as f:
                    payload = f.read()
                is_file = True
                filename = os.path.basename(args.file)
            if args.encrypt and not HAS_CRYPTO:
                print('Error: Encryption requested but pycryptodome is not installed')
                return 2
            if args.encrypt and not args.password:
                print('Error: --password required when --encrypt is used')
                return 2
            embed_to_image_file(args.infile, args.outfile, payload, is_file, filename, args.encrypt, args.password)
            print(f'Success: embedded payload into {args.outfile}')
            return 0

        if args.cmd == 'extract':
            meta, payload = extract_from_image_file(args.infile, args.password)
            if meta['is_file']:
                outp = args.outfile or meta.get('filename') or 'extracted_payload'
                with open(outp, 'wb') as f:
                    f.write(payload)
                print(f'Success: extracted file saved to {outp}')
            else:
                if args.outfile:
                    with open(args.outfile, 'wb') as f:
                        f.write(payload)
                    print(f'Success: extracted text saved to {args.outfile}')
                else:
                    print('--- extracted text start ---')
                    print(payload.decode('utf-8', errors='replace'))
                    print('--- extracted text end ---')
            return 0

        if args.cmd == 'capacity':
            img = Image.open(args.infile)
            cap = calc_capacity(img)
            print(f'Capacity: {cap} bits ({cap//8} bytes)')
            return 0

        if args.cmd == 'selftest':
            return run_selftest()

    except Exception as e:
        print('ERROR:', e)
        return 1


def run_selftest() -> int:
    print('Running self-test: embedding and extracting a short text payload...')
    try:
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as t:
            tmpname = t.name
        # create a small cover image
        img = Image.new('RGB', (128, 128), color=(123, 222, 100))
        img.save(tmpname)
        ##message = b'Hello world — steg selftest'
        message = "Hello world — steg selftest".encode("utf-8")

        outpath = tmpname + '.stego.png'
        embed_to_image_file(tmpname, outpath, message, is_file=False, filename=None, encrypt=False, password=None)
        meta, extracted = extract_from_image_file(outpath, password=None)
        if extracted != message:
            print('Self-test FAILED: extracted payload does not match original')
            return 2
        print('Self-test OK (plain payload)')
        if HAS_CRYPTO:
            print('Running encrypted self-test (AES-GCM)...')
            outpath_enc = tmpname + '.stego.enc.png'
            pwd = 'testpass'
            embed_to_image_file(tmpname, outpath_enc, message, is_file=False, filename=None, encrypt=True, password=pwd)
            meta2, extracted2 = extract_from_image_file(outpath_enc, password=pwd)
            if extracted2 != message:
                print('Encrypted self-test FAILED')
                return 3
            print('Encrypted self-test OK')
        else:
            print('Skipping encrypted self-test (pycryptodome not installed)')
        # cleanup
        try:
            os.remove(tmpname)
            os.remove(outpath)
            if HAS_CRYPTO:
                os.remove(outpath_enc)
        except Exception:
            pass
        print('All self-tests passed')
        return 0
    except Exception as e:
        print('Self-test error:', e)
        return 4

# === Simple GUI (only created if tkinter is available) ===

if GUI_AVAILABLE:
    class StegApp:
        def __init__(self, root):
            self.root = root
            root.title('StegUI — Image Steganography')
            self.mainframe = ttk.Frame(root, padding=10)
            self.mainframe.grid(sticky='nsew')
            root.rowconfigure(0, weight=1)
            root.columnconfigure(0, weight=1)

            # Variables
            self.input_image_path = tk.StringVar()
            self.output_image_path = tk.StringVar()
            self.embed_text = tk.StringVar()
            self.embed_file_path = tk.StringVar()
            self.password = tk.StringVar()
            self.encrypt_var = tk.BooleanVar(value=False)
            self.is_file_var = tk.BooleanVar(value=False)

            # Widgets
            self._build_widgets()

            # For preview
            self.preview_label = None
            self.loaded_image = None

        def _build_widgets(self):
            row = 0
            ttk.Label(self.mainframe, text='Input image (PNG/BMP recommended):').grid(column=0, row=row, sticky='w')
            row += 1
            inframe = ttk.Frame(self.mainframe)
            inframe.grid(column=0, row=row, sticky='ew')
            inframe.columnconfigure(0, weight=1)
            ttk.Entry(inframe, textvariable=self.input_image_path).grid(column=0, row=0, sticky='ew')
            ttk.Button(inframe, text='Browse', command=self.browse_input_image).grid(column=1, row=0)
            ttk.Button(inframe, text='Preview', command=self.preview_image).grid(column=2, row=0)
            row += 1

            ttk.Separator(self.mainframe, orient='horizontal').grid(column=0, row=row, sticky='ew', pady=8)
            row += 1

            ttk.Label(self.mainframe, text='Payload type:').grid(column=0, row=row, sticky='w')
            row += 1
            tframe = ttk.Frame(self.mainframe)
            tframe.grid(column=0, row=row, sticky='ew')
            ttk.Radiobutton(tframe, text='Text', variable=self.is_file_var, value=False).grid(column=0, row=0)
            ttk.Radiobutton(tframe, text='File', variable=self.is_file_var, value=True).grid(column=1, row=0)
            row += 1

            # Text payload
            ttk.Label(self.mainframe, text='Text message:').grid(column=0, row=row, sticky='w')
            row += 1
            ttk.Entry(self.mainframe, textvariable=self.embed_text, width=80).grid(column=0, row=row, sticky='ew')
            row += 1

            # File payload
            fframe = ttk.Frame(self.mainframe)
            fframe.grid(column=0, row=row, sticky='ew')
            ttk.Entry(fframe, textvariable=self.embed_file_path).grid(column=0, row=0, sticky='ew')
            ttk.Button(fframe, text='Browse', command=self.browse_payload_file).grid(column=1, row=0)
            row += 1

            ttk.Separator(self.mainframe, orient='horizontal').grid(column=0, row=row, sticky='ew', pady=8)
            row += 1

            # Encryption
            ttk.Checkbutton(self.mainframe, text='Encrypt payload (AES-256 GCM)', variable=self.encrypt_var).grid(column=0, row=row, sticky='w')
            row += 1
            ttk.Label(self.mainframe, text='Password (required if encrypting):').grid(column=0, row=row, sticky='w')
            row += 1
            ttk.Entry(self.mainframe, textvariable=self.password, show='*').grid(column=0, row=row, sticky='ew')
            row += 1

            # Output
            ttk.Label(self.mainframe, text='Output image path:').grid(column=0, row=row, sticky='w')
            row += 1
            outframe = ttk.Frame(self.mainframe)
            outframe.grid(column=0, row=row, sticky='ew')
            ttk.Entry(outframe, textvariable=self.output_image_path).grid(column=0, row=0, sticky='ew')
            ttk.Button(outframe, text='Browse', command=self.browse_output_image).grid(column=1, row=0)
            row += 1

            # Buttons
            btnframe = ttk.Frame(self.mainframe)
            btnframe.grid(column=0, row=row, sticky='ew', pady=10)
            ttk.Button(btnframe, text='Embed', command=self.do_embed).grid(column=0, row=0, padx=5)
            ttk.Button(btnframe, text='Extract', command=self.do_extract).grid(column=1, row=0, padx=5)
            ttk.Button(btnframe, text='Capacity Info', command=self.show_capacity).grid(column=2, row=0, padx=5)
            row += 1

            # Status
            self.status = tk.StringVar(value='Ready')
            ttk.Label(self.mainframe, textvariable=self.status).grid(column=0, row=row, sticky='w')

        def browse_input_image(self):
            p = filedialog.askopenfilename(filetypes=[('Images', '*.png *.bmp'), ('All', '*.*')])
            if p:
                self.input_image_path.set(p)

        def browse_output_image(self):
            p = filedialog.asksaveasfilename(defaultextension='.png', filetypes=[('PNG', '*.png'), ('BMP', '*.bmp')])
            if p:
                self.output_image_path.set(p)

        def browse_payload_file(self):
            p = filedialog.askopenfilename()
            if p:
                self.embed_file_path.set(p)
                self.is_file_var.set(True)

        def preview_image(self):
            p = self.input_image_path.get()
            if not p or not os.path.exists(p):
                messagebox.showerror('Error', 'Please select a valid input image')
                return
            try:
                img = Image.open(p)
                self.loaded_image = img.copy()
                img.thumbnail((400, 400))
                tkimg = ImageTk.PhotoImage(img)
                if getattr(self, 'preview_label', None) is None:
                    self.preview_label = ttk.Label(self.mainframe, image=tkimg)
                    self.preview_label.image = tkimg
                    self.preview_label.grid(column=0, row=999, pady=8)
                else:
                    self.preview_label.configure(image=tkimg)
                    self.preview_label.image = tkimg
            except Exception as e:
                messagebox.showerror('Error', f'Unable to preview image: {e}')

        def show_capacity(self):
            p = self.input_image_path.get()
            if not p or not os.path.exists(p):
                messagebox.showinfo('Capacity', 'Please choose an input image first')
                return
            img = Image.open(p)
            cap = calc_capacity(img)
            messagebox.showinfo('Capacity', f'Approx available capacity: {cap} bits ({cap//8} bytes)')

        def do_embed(self):
            inpath = self.input_image_path.get()
            outpath = self.output_image_path.get()
            if not inpath or not os.path.exists(inpath):
                messagebox.showerror('Error', 'Input image missing')
                return
            if not outpath:
                messagebox.showerror('Error', 'Please choose an output path')
                return
            is_file = self.is_file_var.get()
            encrypt = self.encrypt_var.get()
            pwd = self.password.get() if encrypt else None
            if encrypt and not pwd:
                messagebox.showerror('Error', 'Encryption selected but no password provided')
                return
            if is_file:
                fp = self.embed_file_path.get()
                if not fp or not os.path.exists(fp):
                    messagebox.showerror('Error', 'Please select a payload file')
                    return
                with open(fp, 'rb') as f:
                    payload = f.read()
                filename = os.path.basename(fp)
            else:
                text = self.embed_text.get() or ''
                payload = text.encode('utf-8')
                filename = None
            try:
                embed_to_image_file(inpath, outpath, payload, is_file=is_file, filename=filename, encrypt=encrypt, password=pwd)
                self.status.set(f'Embedded — saved to {outpath}')
                messagebox.showinfo('Success', f'Payload embedded and saved to {outpath}')
            except Exception as e:
                messagebox.showerror('Error', f'Failed to embed payload: {e}')

        def do_extract(self):
            inpath = self.input_image_path.get()
            if not inpath or not os.path.exists(inpath):
                messagebox.showerror('Error', 'Input image missing')
                return
            try:
                pwd = self.password.get() or None
                meta, payload = extract_from_image_file(inpath, password=pwd)
                if meta['is_file']:
                    suggested = meta.get('filename') or 'extracted_payload'
                    savep = filedialog.asksaveasfilename(initialfile=suggested)
                    if not savep:
                        messagebox.showinfo('Cancelled', 'Save cancelled')
                        return
                    with open(savep, 'wb') as f:
                        f.write(payload)
                    messagebox.showinfo('Success', f'Extracted file saved to {savep}')
                else:
                    text = payload.decode('utf-8', errors='replace')
                    top = tk.Toplevel(self.root)
                    top.title('Extracted message')
                    txt = tk.Text(top, wrap='word', width=80, height=20)
                    txt.pack(expand=True, fill='both')
                    txt.insert('1.0', text)
                self.status.set('Extraction complete')
            except Exception as e:
                messagebox.showerror('Error', f'Failed to extract: {e}')

    def run_gui():
        # If tkinter is available, start GUI
        root = tk.Tk()
        app = StegApp(root)
        root.mainloop()

# === Entry point ===

def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    # If GUI available and no explicit CLI command requested, open GUI.
    if GUI_AVAILABLE and (len(argv) == 0):
        try:
            run_gui()
            return 0
        except Exception as e:
            print('Failed to start GUI, falling back to CLI:', e)
    # Else, run CLI
    return run_cli(argv)

if __name__ == '__main__':
    rc = main()
    # if running as script, exit with rc
    sys.exit(rc)

