#!/usr/bin/env python3
import argparse
import ctypes
import enum
import json
import os
from struct import pack_into, unpack_from
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Union

# For Checksum, AES and LZ
import binascii
from Crypto.Cipher import AES
from fastlz import fast_lz

# ===============================================================================
# CRC32 implementation
# ===============================================================================

class CRC32:
    def __init__(self):
        pass
    
    def compute(self, data: bytes) -> int:
        """Compute CRC32"""
        return binascii.crc32(data) & 0xffffffff # little-endian byte order

crc32 = CRC32()

# ===============================================================================
# Flags and Enums
# ===============================================================================

class Mode(enum.Enum):
    DECRYPT = 0
    ENCRYPT = 1

class EncryptionKeys(enum.Enum):
    KAKAO = 0
    QQ = 1

class Flags(enum.Flag):
    AES_ECB = 0x1
    AES_CBC = 0x2  # ≥ 0x0102
    FASTLZ = 0x80  # ≥ 0x0101

# ===============================================================================
# KeyChain implementation
# ===============================================================================

@dataclass
class KeyEntry:
    """Entry in the KeyChain"""
    key: bytes
    iv: bytes

class KeyChain:
    """Manages encryption keys and IVs"""
    
    # Kakao: Confirmed
    # QQ   : 2.0, maybe others
    DEFAULT_KEYS = {
        "kakao": {
            "key": [
                0xC0, 0x01, 0xC1, 0xE1, 0x26, 0x11, 0x10, 0xDA,
                0x90, 0x90, 0x35, 0x81, 0xFE, 0xBA, 0xA9, 0x7F,
                0xA1, 0x45, 0x1C, 0x4F, 0x97, 0x88, 0x71, 0xFA,
                0xC3, 0xF1, 0xF8, 0x29, 0x3D, 0xDE, 0xE2, 0xB3
            ],
            "iv": [
                0x58, 0xA8, 0xB9, 0xDD, 0x13, 0x61, 0x62, 0xAA,
                0x99, 0x88, 0x7A, 0x1F, 0xF2, 0x3F, 0x7C, 0x91
            ]
        },
        "qq": {
            "key": [
                0xC0, 0x29, 0xC1, 0xE1, 0x26, 0x88, 0x71, 0xFA,
                0xA1, 0x45, 0x1C, 0x4F, 0x97, 0xDE, 0xD2, 0xB3,
                0x90, 0x94, 0x35, 0x81, 0xFE, 0xBA, 0xA9, 0x7F,
                0xC3, 0xF1, 0xF8, 0x29, 0x3D, 0x11, 0x10, 0xFA
            ],
            "iv": [
                0x13, 0x61, 0x62, 0xAA, 0x38, 0xA8, 0xB9, 0xDD,
                0x99, 0x6F, 0xF2, 0x3F, 0x7C, 0x91, 0x88, 0x7A
            ]
        }
    }
    
    def __init__(self, key_type: Union[str, EncryptionKeys, int]):
        self.entries = {}
        self.load_default_keys()
        
        if isinstance(key_type, str):
            self.key_name = key_type.lower()
        elif isinstance(key_type, EncryptionKeys):
            self.key_name = key_type.name.lower()
        else:  # Assume it's an index, I guess.
            self.key_name = list(self.entries.keys())[key_type]
    
    def load_default_keys(self):
        """Load default keys"""
        for name, data in self.DEFAULT_KEYS.items():
            key = bytes(data["key"])
            iv = bytes(data["iv"])
            self.entries[name] = KeyEntry(key=key, iv=iv)
    
    def load_from_json(self, json_path: str):
        """Load keys from a JSON file"""
        try:
            with open(json_path, 'r') as f:
                key_data = json.load(f)
                
            for name, data in key_data.items():
                key = bytes(data.get("key", []))
                iv = bytes(data.get("iv", []))
                
                if len(key) == 32 and len(iv) == 16:
                    self.entries[name.lower()] = KeyEntry(key=key, iv=iv)
        except Exception as e:
            print(f"Error loading keys from JSON: {e}")
    
    def save_to_json(self, json_path: str):
        """Save keys to a JSON file"""
        key_data = {}
        for name, entry in self.entries.items():
            key_data[name] = {
                "key": list(entry.key),
                "iv": list(entry.iv)
            }
        
        with open(json_path, 'w') as f:
            json.dump(key_data, f, indent=2)
    
    def get_key(self) -> bytes:
        """Get the current encryption key"""
        return self.entries[self.key_name].key
    
    # IV is salted by adding the first
    # byte of the checksum to all values
    def get_iv(self, checksum: int) -> bytes:
        """Get the salted IV for the current key"""
        iv = self.entries[self.key_name].iv
        salt = checksum & 0xFF
        
        result = bytearray(16)
        for i in range(16):
            result[i] = (iv[i] + salt) & 0xFF
        
        return bytes(result)

# ===============================================================================
# DJBF Converter
# ===============================================================================

@dataclass
class DJBFHeader:
    """DJBF file header"""
    magic: int = 0x46424A44  # "DJBF"
    version: int = 0x0101    # Big endian
    reserved: int = 0
    checksum: int = 0
    data_size_lo: int = 0
    data_size_hi: int = 0
    flags: Flags = Flags(0)
    data_suffix: bytes = b'\x00' * 15
    data_suffix_size: int = 0
    
    def pack(self) -> bytes:
        """Pack the header into bytes"""
        result = bytearray(37)  # Size of the header
        
        # Pack fields
        pack_into('<I', result, 0, self.magic)
        pack_into('>H', result, 4, self.version)  # Big endian
        pack_into('<H', result, 6, self.reserved)
        pack_into('<I', result, 8, self.checksum)
        pack_into('<i', result, 12, self.data_size_lo)
        pack_into('<i', result, 16, self.data_size_hi)
        pack_into('<B', result, 20, self.flags.value)
        
        # Copy data suffix
        for i in range(15):
            if i < len(self.data_suffix):
                result[21 + i] = self.data_suffix[i]
        
        result[36] = self.data_suffix_size
        
        return bytes(result)
    
    @classmethod
    def unpack(cls, data: bytes) -> 'DJBFHeader':
        """Unpack bytes into a header"""
        if len(data) < 37:
            raise ValueError("Header data too short")
        
        header = cls()
        
        # Unpack fields
        header.magic = unpack_from('<I', data, 0)[0]
        header.version = unpack_from('>H', data, 4)[0]  # Big endian
        header.reserved = unpack_from('<H', data, 6)[0]
        header.checksum = unpack_from('<I', data, 8)[0]
        header.data_size_lo = unpack_from('<i', data, 12)[0]
        header.data_size_hi = unpack_from('<i', data, 16)[0]
        header.flags = Flags(unpack_from('<B', data, 20)[0])
        
        # Extract data suffix
        header.data_suffix = data[21:36]
        header.data_suffix_size = data[36]
        
        return header

class DJBFConverter:
    """Cookie Run DJBF file converter"""
    
    def __init__(self, key_chain: KeyChain, debug: bool = False, skipCK: bool = False):
        self.key_chain = key_chain
        self.debug = debug
        self.skipCK = skipCK
    
    def decrypt_file(self, input_path: str, output_path: Optional[str] = None) -> bool:
        """Decrypt a DJBF file"""
        try:
            with open(input_path, 'rb') as f:
                header_data = f.read(37)
                header = DJBFHeader.unpack(header_data)
                
                # Check for DJBF magic
                if header.magic != 0x46424A44:
                    print(f"Not a DJBF file: {input_path}")
                    return False
                
                # Flag fixes for various versions
                if header.version < 0x0101:
                    header.flags &= ~Flags.FASTLZ
                if header.version < 0x0102:
                    header.flags &= ~Flags.AES_CBC
                
                # Ver 0x0100 files have bad data if 128 bit aligned
                if header.data_suffix_size > 0xF:
                    header.data_suffix_size = 0
                
                print(f"\tDetected: [Version: {header.version:04X} Flags: {self._prettify_flags(header.flags)}]")
                
                # Read the remaining data
                data = f.read()
                buffer = bytearray(len(data) + header.data_suffix_size)
                buffer[:len(data)] = data
                
                # Append suffix bytes
                for i in range(header.data_suffix_size):
                    buffer[len(data) + i] = header.data_suffix[i]
                
                if self.debug:
                    print(f"\tData size: {len(buffer)} bytes")
                    print(f"\tExpected checksum: {header.checksum:08X}")
                
                # AES decrypt
                if (header.flags & (Flags.AES_CBC | Flags.AES_ECB)):
                    buffer = self._aes_decrypt(header, buffer)
                    if self.debug:
                        print(f"\tAfter AES decrypt: {len(buffer)} bytes")
                
                # FastLZ decompress
                if header.flags & Flags.FASTLZ:
                    original_len = len(buffer)
                    buffer = fast_lz.decompress(buffer, header.data_size_lo)
                    if self.debug:
                        print(f"\tAfter FastLZ decompress: {len(buffer)} bytes (from {original_len})")
                
                # Verify checksum
                calculated_checksum = crc32.compute(buffer)
                if self.debug: print(f"\tCalculated checksum: {calculated_checksum:08X}")

                if calculated_checksum != header.checksum:
                    print(f"\tERROR: Checksum mismatch: {calculated_checksum:08X} != {header.checksum:08X}")
                    print("\tPlease double check if file got corrupted or something else.\n\tPlease send an issues with file attached.")
                    if self.skipCK: print("\tProceeding anyway...")
                    else: 
                        print("\tExiting program...")
                        # buffer.flush()
                        exit()
                elif self.debug:
                    print(f"\tMatched checksum: {calculated_checksum:08X} == {header.checksum:08X}")
                
                # Do it raw.
                result = buffer

                '''
                # Alternative way: Convert to UTF-8
                try:
                    result = buffer.decode('ascii').encode('utf-8')
                except UnicodeDecodeError:
                    # If ASCII decode fails, just use the binary data
                    result = buffer
                    print("\tWARNING: Could not decode as ASCII. Using binary data.")
                '''

                # Write output
                if output_path is None:
                    output_path = os.path.splitext(input_path)[0] + '.bin'
                
                with open(output_path, 'wb') as out_f:
                    out_f.write(result)
                
                print(f"\tSuccessfully decrypted to {output_path}")
                return True
                
        except Exception as e:
            print(f"Error decrypting {input_path}: {e}")
            # Save whatever we have for debugging
            if 'buffer' in locals() and output_path:
                try:
                    with open(output_path + ".error", 'wb') as out_f:
                        out_f.write(buffer)
                    print(f"\tSaved partial data to {output_path}.error for debugging")
                except:
                    pass
            return False
    
    def encrypt_file(self, input_path: str, output_path: Optional[str] = None, 
                    version: int = 0x0101, flags: Flags = Flags.AES_ECB | Flags.FASTLZ) -> bool:
        """Encrypt a file to DJBF format"""
        try:
            # Read file
            with open(input_path, 'rb') as f:
                content = f.read()
            
            # Do it raw
            buffer = content
            
            '''
            # Alternative way: Try to convert from UTF-8 to ASCII
            try:
                buffer = content.decode('utf-8').encode('ascii')
            except UnicodeDecodeError:
                # If UTF-8 decode fails, just use the binary data
                buffer = content
                print("\tWARNING: Could not decode as UTF-8. Using binary data.")
            '''
            
            # Header
            header = DJBFHeader()
            header.magic = 0x46424A44  # "DJBF"
            header.version = version
            header.checksum = crc32.compute(buffer)
            header.data_size_lo = len(buffer)
            header.data_suffix = bytearray(15)
            header.flags = flags
            
            if self.debug:
                print(f"\tOriginal data size: {len(buffer)} bytes")
                print(f"\tOriginal checksum: {header.checksum:08X}")
            
            # Flag fixes for various versions
            if version < 0x0101:
                flags &= ~Flags.FASTLZ
            if version < 0x0102:
                flags &= ~Flags.AES_CBC
            
            # FastLZ compress
            if flags & Flags.FASTLZ:
                original_len = len(buffer)
                buffer = fast_lz.compress(buffer, 1)
                if self.debug:
                    print(f"\tAfter FastLZ compress: {len(buffer)} bytes (from {original_len})")
            
            # Align to 128 bits and calculate suffix size
            if len(buffer) % 16 != 0:
                header.data_suffix_size = 16 - (len(buffer) % 16)
                buffer = bytearray(buffer) + bytearray(header.data_suffix_size)
            
            # AES encrypt
            if (flags & (Flags.AES_CBC | Flags.AES_ECB)):
                buffer = self._aes_encrypt(header, buffer)
                if self.debug:
                    print(f"\tAfter AES encrypt: {len(buffer)} bytes")
            
            # Copy the suffix to the header
            for i in range(header.data_suffix_size):
                header.data_suffix[i] = buffer[len(buffer) - header.data_suffix_size + i]
            
            # Write output
            if output_path is None:
                output_path = os.path.splitext(input_path)[0] + '.djb'
            
            with open(output_path, 'wb') as f:
                f.write(header.pack())
                f.write(buffer[:len(buffer) - header.data_suffix_size])
            
            print(f"\tSuccessfully encrypted to {output_path}")
            return True
            
        except Exception as e:
            print(f"Error encrypting {input_path}: {e}")
            return False
    
    def _aes_encrypt(self, header: DJBFHeader, data: bytes) -> bytes:
        """AES encrypt data"""
        key = self.key_chain.get_key()
        iv = self.key_chain.get_iv(header.checksum)
        
        if self.debug:
            print(f"\tUsing key: {key.hex()}")
            print(f"\tUsing IV: {iv.hex()}")
        
        if header.flags & Flags.AES_CBC:
            cipher = AES.new(key, AES.MODE_CBC, iv)
        else:
            cipher = AES.new(key, AES.MODE_ECB)
        
        # Encrypt
        encrypted = cipher.encrypt(data)
        
        # Truncate to original size
        if len(encrypted) > header.data_size_lo:
            encrypted = encrypted[:header.data_size_lo]
        
        return encrypted
    
    def _aes_decrypt(self, header: DJBFHeader, data: bytes) -> bytes:
        """AES decrypt data"""
        key = self.key_chain.get_key()
        iv = self.key_chain.get_iv(header.checksum)
        
        if self.debug:
            print(f"\tUsing key: {key.hex()}")
            print(f"\tUsing IV: {iv.hex()}")
        
        if header.flags & Flags.AES_CBC:
            cipher = AES.new(key, AES.MODE_CBC, iv)
        else:
            cipher = AES.new(key, AES.MODE_ECB)
        
        # Decrypt
        decrypted = cipher.decrypt(data)
        
        # Truncate to original size
        if len(decrypted) > header.data_size_lo:
            decrypted = decrypted[:header.data_size_lo]
        
        return decrypted
    
    def _prettify_flags(self, flags: Flags) -> str:
        """Convert flags to a readable string"""
        result = []
        
        if flags & Flags.AES_ECB:
            result.append("AES_ECB")
        if flags & Flags.AES_CBC:
            result.append("AES_CBC")
        if flags & Flags.FASTLZ:
            result.append("FastLZ")
        
        return ", ".join(result)

# ===============================================================================
# Command line parsing and main function
# ===============================================================================

def parse_flags(flags_str: str) -> Flags:
    """Parse flags from a string"""
    result = Flags(0)
    
    if not flags_str:
        return result
    
    parts = [p.strip() for p in flags_str.split(',')]
    for part in parts:
        if part.upper() == "AES_ECB":
            result |= Flags.AES_ECB
        elif part.upper() == "AES_CBC":
            result |= Flags.AES_CBC
        elif part.upper() == "FASTLZ":
            result |= Flags.FASTLZ
    
    return result

def validate_options(mode: Mode, key: str, version: int, flags: Flags) -> bool:
    """Validate command line options"""
    try:
        if mode == Mode.ENCRYPT:
            if flags == Flags(0):
                print("Error: No flags provided")
                return False
            
            if version < 0x100:
                version += 0x100
            
            if version < 0x0100 or version > 0x0103:
                print("Error: Invalid version number")
                return False
            
            if version >= 0x0102 and (flags & Flags.AES_ECB) and (flags & Flags.AES_CBC):
                print("Error: Invalid flags. Only one AES mode can be set")
                return False
        
        return True
    except Exception as e:
        print(f"Error validating options: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Cookie Run DJBF Converter")
    parser.add_argument('-m', '--mode', required=True, choices=['encrypt', 'decrypt'],
                        help="Encrypt or Decrypt")
    parser.add_argument('-k', '--key', required=True, choices=['kakao', 'qq'],
                        help="Encryption key to use")
    parser.add_argument('-v', '--version', type=int, default=1,
                        help="Output file version (0, 1, 2, or 3)")
    parser.add_argument('-f', '--flags', default="AES_ECB, FastLZ",
                        help="Output file encryption and compression methods")
    parser.add_argument('-s', '--search-pattern', default="*",
                        help="Filename filter")
    parser.add_argument('-i', '--input',
                        help="Input file (instead of searching in folder)")
    parser.add_argument('-o', '--output',
                        help="Output file (instead of auto-generating)")
    parser.add_argument('--keyfile',
                        help="JSON file containing encryption keys")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="Enable debug output")
    parser.add_argument('--ignore-checksum', action='store_true',
                        help="Ignore checksum verification errors")
    
    args = parser.parse_args()
    
    mode = Mode.ENCRYPT if args.mode.lower() == 'encrypt' else Mode.DECRYPT
    flags = parse_flags(args.flags)
    key_chain = KeyChain(args.key.lower())
    if args.keyfile:
        key_chain.load_from_json(args.keyfile)
    if not validate_options(mode, args.key, args.version, flags):
        return 1
    converter = DJBFConverter(key_chain, args.debug, args.ignore_checksum)
    
    # Single file mode
    if args.input:
        if mode == Mode.DECRYPT:
            print(f"Decrypting {args.input}")
            result = converter.decrypt_file(args.input, args.output)
        else:
            print(f"Encrypting {args.input}")
            result = converter.encrypt_file(args.input, args.output, args.version, flags)
        
        return 0 if result else 1
    
    success = True
    found_files = False
    
    for file in Path('.').glob(args.search_pattern):
        if file.is_file():
            found_files = True
            if mode == Mode.DECRYPT:
                print(f"Decrypting {file.name}")
                result = converter.decrypt_file(str(file))
            else:
                print(f"Encrypting {file.name}")
                result = converter.encrypt_file(str(file), None, args.version, flags)
            
            if not result:
                success = False
    
    if not found_files:
        print(f"No files matching '{args.search_pattern}' found.")
        return 1
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main()) 