#!/usr/bin/env python3
"""
FastLZ compression/decompression implementation - ported from C# version
https://github.com/barncastle/CookieRun-DJBF-Converter/blob/master/CookieRunDJBFConverter/FastLZ.cs

Based on https://github.com/ariya/FastLZ
"""

class FastLZ:
    MAX_COPY = 32
    MAX_LEN = 264  # 256 + 8
    MAX_L1_DISTANCE = 8192
    MAX_L2_DISTANCE = 8191
    MAX_FARDISTANCE = 65535 + MAX_L2_DISTANCE - 1
    HASH_LOG = 14
    HASH_SIZE = 1 << HASH_LOG
    HASH_MASK = HASH_SIZE - 1
    
    def __init__(self):
        pass
    
    def compress(self, input_data: bytes, level: int = 1) -> bytes:
        """Compress data using FastLZ algorithm"""
        if not input_data:
            return b''
        
        length = len(input_data)
        max_output_size = length + length // 20 + 36
        output = bytearray(max_output_size)
        
        # Use level 2 for large data
        if length >= 65536 and level == 1:
            level = 2
        
        max_distance = self.MAX_L1_DISTANCE if level == 1 else self.MAX_FARDISTANCE
        
        # Initialize hash table
        htab = [0] * self.HASH_SIZE
        
        ip = 0  # Input pointer
        ip_bound = length - 4  # Bound for read_u32
        ip_limit = length - 12 - 1
        op = 0  # Output pointer
        
        # We start with literal copy
        anchor = ip
        ip += 2
        
        # Main loop
        while ip < ip_limit:
            ref = 0
            distance = 0
            
            # Find potential match
            while True:
                seq = (input_data[ip] << 16) | (input_data[ip+1] << 8) | input_data[ip+2]
                hash_value = self._hash(seq)
                ref = htab[hash_value]
                htab[hash_value] = ip
                distance = ip - ref
                
                if ip >= ip_limit:
                    break
                
                if distance < max_distance:
                    # Compare sequences
                    ref_seq = (input_data[ref] << 16) | (input_data[ref+1] << 8) | input_data[ref+2]
                    if seq == ref_seq:
                        break
                
                ip += 1
            
            if ip >= ip_limit:
                break
            
            # Go back one step
            ip -= 1
            
            # Far, needs at least 5-byte match for level 2
            if level == 2 and distance >= self.MAX_L2_DISTANCE:
                if input_data[ref+3] != input_data[ip+3] or input_data[ref+4] != input_data[ip+4]:
                    ip += 1
                    continue
            
            # Copy literals
            if ip > anchor:
                op = self._output_literals(input_data[anchor:ip], output, op)
            
            # Compute match length
            len_best = 3  # Minimum match length
            ref_ptr = ref + 3
            ip_ptr = ip + 3
            
            while ip_ptr < length and ref_ptr < length and input_data[ip_ptr] == input_data[ref_ptr]:
                ip_ptr += 1
                ref_ptr += 1
            
            len_best = ip_ptr - ip
            
            # Encode match
            if level == 1:
                op = self._output_match_1(len_best, distance, output, op)
            else:
                op = self._output_match_2(len_best, distance, output, op)
            
            # Update pointers
            ip += len_best
            anchor = ip
            
            # Update hash at match boundary
            if ip < ip_bound:
                seq = (input_data[ip] << 16) | (input_data[ip+1] << 8) | input_data[ip+2]
                hash_value = self._hash(seq)
                htab[hash_value] = ip
                ip += 1
                
                if ip < ip_bound:
                    seq = (input_data[ip] << 16) | (input_data[ip+1] << 8) | input_data[ip+2]
                    hash_value = self._hash(seq)
                    htab[hash_value] = ip
                    ip += 1
        
        # Copy remaining literals
        if ip < length:
            op = self._output_literals(input_data[anchor:length], output, op)
        
        # Mark for level 2
        if level == 2:
            output[0] |= 1 << 5
        
        return bytes(output[:op])
    
    def decompress(self, input_data: bytes, expected_size: int) -> bytes:
        """Decompress data using FastLZ algorithm"""
        if not input_data or not expected_size:
            return b''
        
        output = bytearray(expected_size)
        
        # Get compression level from first byte
        level = ((input_data[0] >> 5) & 1) + 1
        
        ip = 0  # Input pointer
        ip_limit = len(input_data)
        ip_bound = ip_limit - 2
        op = 0  # Output pointer
        
        ctrl = input_data[ip] & 31
        ip += 1
        
        while True:
            if ctrl >= 32:
                # Match from latest distance
                len_best = (ctrl >> 5) - 1
                ofs = (ctrl & 31) << 8
                ref = op - ofs - 1
                
                if len_best == 7 - 1:
                    if ip <= ip_bound:
                        len_best += input_data[ip]
                        ip += 1
                    
                    if level == 2:
                        while ip < ip_limit and input_data[ip] == 255:
                            len_best += 255
                            ip += 1
                    
                        if ip < ip_limit:
                            len_best += input_data[ip]
                            ip += 1
                
                ref -= input_data[ip]
                ip += 1
                
                len_best += 3
                
                # Match from 16-bit distance
                if level == 2 and input_data[ip-1] == 255:
                    if ofs == (31 << 8):
                        if ip <= ip_bound:
                            ofs = (input_data[ip] << 8) | input_data[ip+1]
                            ip += 2
                            ref = op - ofs - self.MAX_L2_DISTANCE - 1
                
                # Copy match
                for i in range(len_best):
                    output[op + i] = output[ref + i]
                
                op += len_best
            else:
                # Literal copy
                ctrl += 1
                
                if ip + ctrl > ip_limit or op + ctrl > expected_size:
                    break
                
                for i in range(ctrl):
                    output[op + i] = input_data[ip + i]
                
                op += ctrl
                ip += ctrl
            
            if (level == 2 and ip >= ip_limit) or (level == 1 and ip > ip_bound):
                break
            
            ctrl = input_data[ip]
            ip += 1
        
        return bytes(output[:op])
    
    def _hash(self, v):
        """Hash function for finding matches"""
        h = (v * 2654435769) & 0xFFFFFFFF
        return (h >> (32 - self.HASH_LOG)) & self.HASH_MASK
    
    def _output_literals(self, literals, output, op):
        """Output literal bytes"""
        runs = len(literals)
        
        # Handle large literal copies
        while runs >= self.MAX_COPY:
            output[op] = self.MAX_COPY - 1
            op += 1
            
            for i in range(self.MAX_COPY):
                output[op + i] = literals[i]
            
            literals = literals[self.MAX_COPY:]
            op += self.MAX_COPY
            runs -= self.MAX_COPY
        
        # Handle remaining literals
        if runs > 0:
            output[op] = runs - 1
            op += 1
            
            for i in range(runs):
                output[op + i] = literals[i]
            
            op += runs
        
        return op
    
    def _output_match_1(self, length, distance, output, op):
        """Output a match for level 1 compression"""
        distance -= 1
        
        if length < 7:
            output[op] = ((length << 5) + (distance >> 8)) & 0xFF
            op += 1
            output[op] = distance & 0xFF
            op += 1
        else:
            output[op] = (7 << 5) + (distance >> 8)
            op += 1
            output[op] = length - 7
            op += 1
            output[op] = distance & 0xFF
            op += 1
        
        return op
    
    def _output_match_2(self, length, distance, output, op):
        """Output a match for level 2 compression"""
        distance -= 1
        
        if distance < self.MAX_L2_DISTANCE:
            if length < 7:
                output[op] = ((length << 5) + (distance >> 8)) & 0xFF
                op += 1
                output[op] = distance & 0xFF
                op += 1
            else:
                output[op] = (7 << 5) + (distance >> 8)
                op += 1
                
                length -= 7
                while length >= 255:
                    output[op] = 255
                    op += 1
                    length -= 255
                
                output[op] = length
                op += 1
                output[op] = distance & 0xFF
                op += 1
        else:
            # Far away match
            distance -= self.MAX_L2_DISTANCE
            
            if length < 7:
                output[op] = ((length << 5) + 31) & 0xFF
                op += 1
                output[op] = 255
                op += 1
                output[op] = (distance >> 8) & 0xFF
                op += 1
                output[op] = distance & 0xFF
                op += 1
            else:
                output[op] = (7 << 5) + 31
                op += 1
                
                length -= 7
                while length >= 255:
                    output[op] = 255
                    op += 1
                    length -= 255
                
                output[op] = length
                op += 1
                output[op] = 255
                op += 1
                output[op] = (distance >> 8) & 0xFF
                op += 1
                output[op] = distance & 0xFF
                op += 1
        
        return op

fast_lz = FastLZ() 