/**
 * @mattandneil Apex implementation of RSA-SHA512
 */
public class CryptoRsaSha512
{
    /**
     * Hash function SHA-512
     */
    static public Blob generateDigest(Blob input)
    {
        return new SHA512(input).generateDigest();
    }
    
    /**
     * Sign using RSA PRIVATE KEY in ASN.1 DER
     * Hash uses PKCS#1 with padded DigestInfo
     */
    static public Blob sign(Blob input, Blob privateKey)
    {
        Asn key = new Asn(privateKey);
        Rsa rsa = new Rsa(key.values());
        return rsa.signSha512(input);
    }

    /**
     * Sign using RSA PRIVATE KEY in PEM file
     * Hash uses PKCS#1 with padded DigestInfo
     */
    static public Blob sign(Blob input, String pemFile)
    {
        Asn key = new Asn(pemFile);
        Rsa rsa = new Rsa(key.values());
        return rsa.signSha512(input);
    }



    /**
     * @mattandneil Apex port of Abstract Syntax Notation reader
     * https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One
     * 
     * Copyright (c) 2010-2017
     * kjur.github.io/jsrsasign/license
     * Kenji Urushima (kenji.urushima@gmail.com)
     * The above copyright and license notice shall be 
     * included in all copies or substantial portions of the Software.
     */
    public class Asn
    {
        /**
         * Hexadecimal string of ASN.1 DER encoded data
         */
        String hex;
        
        /**
         * PEM file constructor
         * https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
         * Format must be consistent with the following example:
         * 
         * -----BEGIN RSA PRIVATE KEY-----\n
         * MIIEpAIBAAKCAQEAy5REcVYFbh8wwC9\n
         * 7qkKp1cm8Zx+FzukKBodOgg87mevD5Y\n
         * W2+T12o+f7WEf53Sp6W51p3/4Q1DyPl\n
         * KNHRodQEjx8DAAYvYagiE3/zgkYzC2I\n
         * -----END RSA PRIVATE KEY-----
         */
        public Asn(String pemFile)
        {
            pemFile = pemFile.trim();
            String ends = '-----END RSA PRIVATE KEY-----';
            String begins = '-----BEGIN RSA PRIVATE KEY-----';
            if (!pemFile.startsWith(begins)) throw new StringException('PEM file must start with ' + begins);
            if (!pemFile.endsWith(ends)) throw new StringException('PEM file must terminate with ' + ends);
            
            String base64 = pemFile.substringBetween(begins, ends).deleteWhitespace();
            this.hex = EncodingUtil.convertToHex(EncodingUtil.base64Decode(base64));
        }
        
        /**
         * An RSA private key should be represented with the ASN.1 type RSAPrivateKey:
         * https://tools.ietf.org/html/rfc3447#appendix-A.1.2
         * 
         * RSAPrivateKey ::= SEQUENCE {
         *     version           Version,
         *     modulus           INTEGER,  -- n
         *     publicExponent    INTEGER,  -- e
         *     privateExponent   INTEGER,  -- d
         *     prime1            INTEGER,  -- p
         *     prime2            INTEGER,  -- q
         *     exponent1         INTEGER,  -- d mod (p-1)
         *     exponent2         INTEGER,  -- d mod (q-1)
         *     coefficient       INTEGER,  -- (inverse of q) mod p
         *     otherPrimeInfos   OtherPrimeInfos OPTIONAL
         * }
         * 
         * An RSA private key is a list of 8 integer values
         * - Modulus and publicExponent comprise the public key
         * - The third value, PrivateExponent is the private key
         * - The remaining values are for the Chinese Remainder Theorem
         * https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art049
         */
        public Asn(Blob asn1data)
        {
            this.hex = EncodingUtil.convertToHex(asn1data);
            if (this.hex.contains('2d2d2d2d2d'))
            throw new StringException('Use PEM file constructor. ASN.1 data cannot include "-----"');
        }
        
        /**
         * Integer list of indexes for ASN.1
         * objects appearing in hex string
         */
        public List<Integer> indexes()
        {
            Integer start = getVindex(0);
            List<Integer> indexes = new List<Integer>();
            if (this.hex.substring(0, 2) == '03') indexes.add(start + 2);
            else indexes.add(start);
            Integer max = 0;
            Integer curr = start;
            Integer length = getVblen(0);
            while (true)
            {
                Integer next = getNextSiblingIndex(curr);
                if (next == null || (next - start >= (length * 2))) break;
                if (max >= 200) break;
                indexes.add(next);
                curr = next;
                max++;
            }
            return indexes;
        }
        
        /**
         * All data (eg primes/coefficient)
         * appearing in the DER structure
         */
        public List<Blob> values()
        {
            List<Blob> values = new List<Blob>();
            for (Integer index : this.indexes()) values.add(value(index));
            return values;
        }
        
        /**
         * Data value for object
         * according to index
         */
        Blob value(Integer index)
        {
            Integer start = getVindex(index);
            Integer length = getVblen(index);
            String hex = this.hex.substring(start, start + length * 2);
            return EncodingUtil.convertFromHex(hex);
        }
        
        /**
         * Starting index of next
         * sibling in ASN.1 hex string
         */
        Integer getNextSiblingIndex(Integer index)
        {
            Integer start = getVindex(index);
            Integer length = getVblen(index);
            return start + length * 2;
        }
        
        /**
         * Value start position in ASN.1 hex 
         * for object according to index
         */
        Integer getVindex(Integer index)
        {
            Integer length = getLblen(index);
            if (length < 0) return length;
            return index + (length + 1) * 2;
        }
        
        /**
         * Byte length of item
         * in ASN.1 hex string
         */
        Integer getLblen(Integer index)
        {
            if (this.hex.substring(index + 2, index + 3) != '8') return 1;
            Integer i = Integer.valueOf(this.hex.substring(index + 3, index + 4));
            if (i == 0) return -1; // length octet '80' indefinite length
            if (0 < i && i < 10) return i + 1; // including '8?' octet;
            return -2; // malformed format
        }
        
        /**
         * Hex string for item
         * according to index
         */
        String getL(Integer index)
        {
            Integer length = getLblen(index);
            if (length < 1) return '';
            return this.hex.substring(index + 2, index + 2 + (length * 2));
        }
        
        /**
         * Length of binary data for
         * item according to index
         */
        Integer getVblen(Integer index)
        {
            String hex = this.getL(index);
            if (hex == '') return -1;
            if (hex.substring(0, 1) == '8') return hexToDec(hex.substring(2, hex.length()));
            return hexToDec(hex);
        }
        
        /**
         * Hexadecimal converter by Brian Fear @sfdcfox
         * https://salesforce.stackexchange.com/a/127545
         */
        Integer hexToDec(String hex) {
            Integer dec = 0;
            List<String> chars = hex.toLowerCase().split('');
            for (Integer i = 0, size = chars.size(); i < size; i++)
            dec = (dec << 4) + digits.indexOf(chars[i]);
            if (dec < 0) throw new MathException('Overflow: ' + hex);
            return dec;
        }
        
        final List<String> digits = new List<String>
        {
            '0', '1', '2', '3',
            '4', '5', '6', '7',
            '8', '9', 'a', 'b',
            'c', 'd', 'e', 'f'
        };
    }



    /**
     * @mattandneil Apex port of Big Integer library by Tom Wu
     * https://en.wikipedia.org/wiki/Arbitrary-precision_arithmetic
     * 
     * Copyright (c) 2003-2005  Tom Wu
     * All Rights Reserved. tjw@cs.stanford.edu
     * http://www-cs-students.stanford.edu/~tjw/jsbn/LICENSE
     *
     * Permission is hereby granted, free of charge, to any person obtaining
     * a copy of this software and associated documentation files (the
     * "Software"), to deal in the Software without restriction, including
     * without limitation the rights to use, copy, modify, merge, publish,
     * distribute, sublicense, and/or sell copies of the Software, and to
     * permit persons to whom the Software is furnished to do so, subject to
     * the following conditions:
     *
     * The above copyright notice and this permission notice shall be
     * included in all copies or substantial portions of the Software.
     *
     * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
     * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
     * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
     *
     * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
     * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
     * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
     * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
     * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
     *
     * In addition, the following condition applies:
     *
     * All redistributions must retain an intact copy of this copyright notice
     * and disclaimer.
     */
    public class BigInt
    {
        /**
         * 30-bit words used
         */
        final Integer DBITS = 30;
        final Integer DVAL = 1 << DBITS;
        final Integer DMAX = ((1 << DBITS) - 1);
    
        /**
         * 52-bit mantissa
         */
        final Integer FBITS = 52;
        final Integer FLOAT1 = FBITS - DBITS;
        final Integer FLOAT2 = 2 * DBITS - FBITS;
        final Double FLOATV = Math.pow(2, FBITS);
        
        /**
         * Integer to hexadecimal
         */
        final Map<Integer,String> int2hex = new Map<Integer,String>
        {
            0 => '0',  1 => '1',  2 => '2',  3 => '3',  4 => '4',  5 => '5',  6 => '6',  7 => '7',
            8 => '8',  9 => '9', 10 => 'a', 11 => 'b', 12 => 'c', 13 => 'd', 14 => 'e', 15 => 'f'
        };
        
        /**
         * charAt() to integer
         */
        final Map<Integer,Integer> chr2int = new Map<Integer,Integer>
        {
            48 =>  0,  49 =>  1,  50 =>  2,  51 =>  3,  52 =>  4, // ASCII 01234
            53 =>  5,  54 =>  6,  55 =>  7,  56 =>  8,  57 =>  9, // ASCII 56789
            65 => 10,  66 => 11,  67 => 12,  68 => 13,  69 => 14,  70 => 15, // ASCII ABCDEF
            97 => 10,  98 => 11,  99 => 12, 100 => 13, 101 => 14, 102 => 15  // ASCII abcdef
        };
        
        /**
         * Returns bit length of the int x
         */
        Integer bits(Integer x)
        {
            Integer t;
            Integer r = 1;
            if ((t = x >>> 16) != 0) {x = t; r += 16;}
            if ((t = x >>   8) != 0) {x = t; r +=  8;}
            if ((t = x >>   4) != 0) {x = t; r +=  4;}
            if ((t = x >>   2) != 0) {x = t; r +=  2;}
            if ((t = x >>   1) != 0) {x = t; r +=  1;}
            return r;
        }
        
        /**
         * -1 or 0
         */
        Integer sign;
    
        /**
         * Number of 30-bit words
         */
        Integer size;
    
        /**
         * Map avoids 'List index out of bounds'
         */
        Map<Integer,Integer> words = new Map<Integer,Integer>();
        
        /**
         * Constructors
         */
        public BigInt()
        {
            this.fromInt(0);
        }
        
        public BigInt(Integer i)
        {
            this.fromInt(i);
        }
        
        public BigInt(String hex)
        {
            this.fromHex(hex);
        }
        
        public BigInt(Blob data)
        {
            this.fromHex(EncodingUtil.convertToHex(data));
        }
        
        /**
         * this[x]++
         */
        Integer increment(Integer i)
        {
            Integer temp = this.words.get(i) + 1;
            this.words.put(i, temp);
            return temp;
        }
    
        /**
         * this[x] += v
         */
        Integer plusEquals(Integer i, Integer value)
        {
            Integer temp = this.words.get(i) + value;
            this.words.put(i, temp);
            return temp;
        }
        
        /**
         * this[x] |= v
         */
        Integer pipeEquals(Integer i, Integer value)
        {
            Integer temp = this.words.get(i) | value;
            this.words.put(i, temp);
            return temp;
        }
        
        /**
         * this[x] -= v
         */
        Integer minusEquals(Integer i, Integer value)
        {
            Integer temp = this.words.get(i) - value;
            this.words.put(i, temp);
            return temp;
        }
        
        /**
         * Add-and-Multiply loop
         * https://bugs.webkit.org/show_bug.cgi?id=40367
         * 
         * am: Compute w_j += (x*this_i), propagate carries,
         * c is initial carry, returns final carry.
         * c < 3*dvalue, x < 2*dvalue, this_i < dvalue
         * 
         * am2 avoids a big mult-and-extract completely.
         * Max digit bits should be <= 30 because we do bitwise ops
         * on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
         */
        public Integer am(Integer i, Integer x, BigInt w, Integer j, Integer c, Integer n)
        {
            Integer xl = x & 32767;
            Integer xh = x >> 15;
            while (--n >= 0)
            {
                Integer l = this.words.get(i) & 32767;
                Integer h = this.words.get(i++) >> 15;
                Integer m = xh * l + h * xl;
                l = xl * l + ((m & 32767) << 15) + w.words.get(j) + (c & 1073741823);
                c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
                w.words.put(j++, l & 1073741823);
            }
            return c;
        }
        
        /**
         * copy this to r
         */
        void copyTo(BigInt target)
        {
            for (Integer i = this.size - 1; i >= 0; --i) target.words.put(i, this.words.get(i));
            target.size = this.size;
            target.sign = this.sign;
        }
        
        /**
         * set from int value x, -DV <= x < DV
         */
        void fromInt(Integer value)
        {
            this.size = 1;
            this.sign = (value < 0) ? -1 : 0;
            if (value > 0) this.words.put(0, value);
            else if (value < -1) this.words.put(0, value + DVAL);
            else this.size = 0;
        }
        
        /**
         * set from hex string
         */
        void fromHex(String hex)
        {
            Integer k = 4; // base 16
            this.size = 0;
            this.sign = 0;
            Integer i = hex.length();
            Boolean minus = false;
            Integer sh = 0;
            while (--i >= 0)
            {
                Integer x = chr2int.get(hex.charAt(i));
                if (x == null)
                {
                    if (hex.substring(i, i + 1) == '-') minus = true;
                    continue;
                }
                minus = false;
                if (sh == 0) this.words.put(this.size++, x);
                else if (sh + k > DBITS)
                {
                    this.pipeEquals(this.size - 1, (x & ((1 << (DBITS - sh)) - 1)) << sh);
                    this.words.put(this.size++, (x >> (DBITS - sh)));
                }
                else this.pipeEquals(this.size - 1, x << sh);
                sh += k;
                if (sh >= DBITS) sh -= DBITS;
            }
            this.clamp();
            if (minus) new BigInt(0).subTo(this, this);
        }
        
        /**
         * r = this - a
         */
        @TestVisible void subTo(BigInt minus, BigInt target)
        {
            Integer i = 0;
            Integer c = 0;
            Integer m = Math.min(minus.size, this.size);
            while (i < m)
            {
                c += this.words.get(i) - minus.words.get(i);
                target.words.put(i++, (c & DMAX));
                c >>= DBITS;
            }
            if (minus.size < this.size)
            {
                c -= minus.sign;
                while (i < this.size)
                {
                    c += this.words.get(i);
                    target.words.put(i++, (c & DMAX));
                    c >>= DBITS;
                }
                c += this.sign;
            }
            else
            {
                c += this.sign;
                while (i < minus.size)
                {
                    c -= minus.words.get(i);
                    target.words.put(i++, (c & DMAX));
                    c >>= DBITS;
                }
                c -= minus.sign;
            }
            target.sign = (c < 0) ? -1 : 0;
            if (c < -1) target.words.put(i++, (DVAL + c));
            else if (c > 0) target.words.put(i++, c);
            target.size = i;
            target.clamp();
        }
        
        /**
         * clamp off excess high words
         */
        void clamp()
        {
            Integer c = this.sign & DMAX;
            while (this.size > 0 && this.words.get(this.size - 1) == c) --this.size;
        }
        
        BigInt negate()
        {
            BigInt result = new BigInt();
            new BigInt(0).subTo(this, result);
            return result;
        }
        
        /**
         * 0 if this == 0, 1 if this > 0
         */
        public Integer sigNum()
        {
            if (this.sign < 0) return -1;
            if (this.size <= 0 || this.size == 1 && (this.words.get(0) <= 0)) return 0;
            else return 1;
        }
        
        public Blob toBlob()
        {
            return EncodingUtil.convertFromHex(this.toHex());
        }
        
        /**
         * return string representation in hex
         */
        public String toHex()
        {
            if (this.sign < 0) return '-' + this.negate().toHex();
            Integer k = 4; // base 16
            Integer km = (1 << k) - 1;
            Integer digit;
            Boolean m = false;
            String hex = '';
            Integer i = this.size;
            Integer p = DBITS - Math.mod((i * DBITS), k);
            if (i-- > 0)
            {
                if (p < DBITS && (digit = this.words.get(i) >> p) > 0)
                {
                    m = true; hex = int2hex.get(digit);
                }
                while (i >= 0)
                {
                    if (p < k)
                    {
                        digit = (this.words.get(i) & ((1 << p) - 1)) << (k - p);
                        digit |= this.words.get(--i) >> (p += DBITS - k);
                    }
                    else
                    {
                        digit = (this.words.get(i) >> (p -= k)) & km;
                        if (p <= 0)
                        {
                            p += DBITS;
                            --i;
                        }
                    }
                    if (digit > 0) m = true;
                    if (m) hex += int2hex.get(digit);
                }
            }
            return m ? hex : '0';
        }
        
        /**
         * |this|
         */
        public BigInt abs()
        {
            return (this.sign < 0) ? this.negate() : this;
        }
        
        /**
         * return + if this > a, - if this < a, 0 if equal
         */
        public Integer compareTo(BigInt cmp)
        {
            Integer r = this.sign - cmp.sign;
            if (r != 0) return r;
            Integer i = this.size;
            r = i - cmp.size;
            if (r != 0) return (this.sign < 0) ? -r : r;
            while (--i >= 0) if ((r = this.words.get(i) - cmp.words.get(i)) != 0) return r;
            return 0;
        }
        
        /**
         * return the number of bits in "this"
         */
        public Integer bitLength()
        {
            if (this.size <= 0) return 0;
            return DBITS * (this.size - 1) + bits(this.words.get(this.size - 1) ^ (this.sign & DMAX));
        }
        
        /**
         * Double left shift
         * r = this << n*DB
         */
        @TestVisible void dlShiftTo(Integer words, BigInt target)
        {
            Integer i;
            for (i = this.size - 1; i >= 0; --i) target.words.put(i + words, this.words.get(i));
            for (i = words - 1; i >= 0; --i) target.words.put(i, 0);
            target.size = this.size + words;
            target.sign = this.sign;
        }
        
        /**
         * Left shift
         * r = this << n
         */
        @TestVisible void lShiftTo(Integer bits, BigInt target)
        {
            Integer bs = Math.mod(bits, DBITS);
            Integer cbs = DBITS - bs;
            Integer bm = (1 << cbs) - 1;
            Integer ds = (Integer)Math.floor(bits / DBITS);
            Integer c = (this.sign << bs) & DMAX;
            Integer i;
            for (i = this.size - 1; i >= 0; --i)
            {
                target.words.put(i + ds + 1, ((this.words.get(i) >> cbs) | c));
                c = (this.words.get(i) & bm) << bs;
            }
            for (i = ds - 1; i >= 0; --i) target.words.put(i, 0);
            target.words.put(ds, c);
            target.size = this.size + ds + 1;
            target.sign = this.sign;
            target.clamp();
        }
        
        /**
         * Right shift
         * r = this >> n
         */
        @TestVisible void rShiftTo(Integer bits, BigInt target)
        {
            target.sign = this.sign;
            Integer ds = (Integer)Math.floor(bits / DBITS);
            if (ds >= this.size)
            {
                target.size = 0;
                return;
            }
            Integer bs = Math.mod(bits, DBITS);
            Integer cbs = DBITS - bs;
            Integer bm = (1 << bs) - 1;
            target.words.put(0, (this.words.get(ds) >> bs));
            for (Integer i = ds + 1; i < this.size; ++i)
            {
                target.pipeEquals(i - ds - 1, (this.words.get(i) & bm) << cbs);
                target.words.put(i - ds, (this.words.get(i) >> bs));
            }
            if (bs > 0)
            {
                target.pipeEquals(this.size - ds - 1, (this.sign & bm) << cbs);
            }
            target.size = this.size - ds;
            target.clamp();
        }
        
        /**
         * r = this * a, r != this,a (HAC 14.12)
         * "this" should be the larger one if appropriate.
         */
        void multiplyTo(BigInt a, BigInt target)
        {
            BigInt x = this.abs();
            BigInt i = a.abs();
            Integer xSize = x.size;
            target.size = xSize + i.size;
            while (--xSize >= 0) target.words.put(xSize, 0);
            for (xSize = 0; xSize < i.size; ++xSize) target.words.put(
                xSize + x.size,
                x.am(0, i.words.get(xSize), target, xSize, 0, x.size)
            );
            target.sign = 0;
            target.clamp();
            if (this.sign != a.sign)
            {
                new BigInt(0).subTo(target, target);
            }
        }
        
        /**
         * r = this^2, r != this (HAC 14.16)
         */
        void squareTo(BigInt target)
        {
            BigInt x = this.abs();
            Integer i = target.size = 2 * x.size;
            while (--i >= 0) target.words.put(i, 0);
            for (i = 0; i < x.size - 1; ++i)
            {
                Integer c = x.am(i, x.words.get(i), target, 2 * i, 0, 1);
                if ((target.plusEquals(i + x.size, x.am(i + 1, 2 * x.words.get(i), target, 2 * i + 1, c, x.size - i - 1))) >= DVAL)
                {
                    target.minusEquals(i + x.size, DVAL);
                    target.words.put(i + x.size + 1, 1);
                }
            }
            if (target.size > 0) target.plusEquals(target.size -1, x.am(i, x.words.get(i), target, 2 * i, 0, 1));
            target.sign = 0;
            target.clamp();
        }
        
        /**
         * Double right shift
         * r = this >> n*DB
         */
        @TestVisible void drShiftTo(Integer words, BigInt target)
        {
            for (Integer i = words; i < this.size; ++i) target.words.put(i - words, this.words.get(i));
            target.size = Math.max(this.size - words, 0);
            target.sign = this.sign;
        }
        
        /**
         * divide this by m, quotient and remainder to q, r (HAC 14.20)
         * r != q, this != m.  q or r may be null.
         */
        @TestVisible void divRemTo(BigInt divisor, BigInt quotient, BigInt remainder)
        {
            BigInt pm = divisor.abs();
            if (pm.size <= 0) return;
            BigInt pt = this.abs();
            if (pt.size < pm.size)
            {
                if (quotient != null) quotient.fromInt(0);
                if (remainder != null) this.copyTo(remainder);
                return;
            }
            
            if (remainder == null) remainder = new BigInt();
            BigInt y = new BigInt();
            Integer thisSign = this.sign;
            Integer mSign = divisor.sign;
            Integer nsh = DBITS - bits(pm.words.get(pm.size - 1));
            if (nsh > 0) {pm.lShiftTo(nsh, y); pt.lShiftTo(nsh, remainder);}
            else {pm.copyTo(y); pt.copyTo(remainder);}
            Integer ySize = y.size;
            Integer y0 = y.words.get(ySize - 1);
            if (y0 == 0) return;
            Double yt = (Double)y0 * (1 << FLOAT1) + ((ySize > 1) ? y.words.get(ySize - 2) >> FLOAT2 : 0);
            Double double1 = FLOATV / yt;
            Double double2 = (1 << FLOAT1) / yt;
            Integer e = 1 << FLOAT2;
            Integer rSize = remainder.size;
            Integer j = rSize - ySize;
            BigInt t = (quotient == null) ? new BigInt() : quotient;
            y.dlShiftTo(j, t);
            if (remainder.compareTo(t) >= 0)
            {
                remainder.words.put(remainder.size++, 1);
                remainder.subTo(t, remainder);
            }
            new BigInt(1).dlShiftTo(ySize, t);
            t.subTo(y, y);
            while (y.size < ySize) y.words.put(y.size++, 0);
            while (--j >= 0)
            {
                // Estimate quotient digit
                Integer qd =
                    (remainder.words.get(--rSize) == y0)
                    ? DMAX
                    : (Integer)Math.floor(remainder.words.get(rSize) * double1 + (remainder.words.get(rSize - 1) + e) * double2)
                ;
                if ((remainder.plusEquals(rSize, y.am(0, qd, remainder, j, 0, ySize))) < qd)
                {
                    y.dlShiftTo(j, t);
                    remainder.subTo(t, remainder);
                    while (remainder.words.get(rSize) < --qd) remainder.subTo(t, remainder);
                }
            }
            if (quotient != null)
            {
                remainder.drShiftTo(ySize, quotient);
                if (thisSign != mSign) new BigInt(0).subTo(quotient, quotient);
            }
            remainder.size = ySize;
            remainder.clamp();
            if (nsh > 0) remainder.rShiftTo(nsh, remainder);
            if (thisSign < 0) new BigInt(0).subTo(remainder, remainder);
        }
        
        /**
         * this mod a
         */
        public BigInt mod(BigInt a)
        {
            BigInt r = new BigInt();
            this.abs().divRemTo(a, null, r);
            if (this.sign < 0 && r.compareTo(new BigInt(0)) > 0) a.subTo(r, r);
            return r;
        }
        
        /**
         * r = this + a
         */
        void addTo(BigInt a, BigInt r)
        {
            Integer i = 0;
            Integer c = 0;
            Integer m = Math.min(a.size, this.size);
            while (i < m)
            {
                c += this.words.get(i) + a.words.get(i);
                r.words.put(i++, (c & DMAX));
                c >>= DBITS;
            }
            
            if (a.size < this.size)
            {
                c += a.sign;
                while (i < this.size)
                {
                    c += this.words.get(i);
                    r.words.put(i++, (c & DMAX));
                    c >>= DBITS;
                }
                c += this.sign;
            }
            else
            {
                c += this.sign;
                while (i < a.size)
                {
                    c += a.words.get(i);
                    r.words.put(i++, (c & DMAX));
                    c >>= DBITS;
                }
                c += a.sign;
            }
            r.sign = (c < 0) ? -1 : 0;
            if (c > 0) r.words.put(i++, c);
            else if (c < -1) r.words.put(i++, (DVAL + c));
            r.size = i;
            r.clamp();
        }
        
        /**
         * this + a
         */
        public BigInt add(BigInt plus)
        {
            BigInt r = new BigInt();
            this.addTo(plus, r);
            return r;
        }
        
        /**
         * this - a
         */
        public BigInt subtract(BigInt minus)
        {
            BigInt r = new BigInt();
            this.subTo(minus, r);
            return r;
        }
        
        /**
         * this * a
         */
        public BigInt multiply(BigInt multiplicand)
        {
            BigInt r = new BigInt();
            this.multiplyTo(multiplicand, r);
            return r;
        }
    
        /**
         * this / a
         */
        BigInt divide(BigInt divisor)
        {
            BigInt quotient = new BigInt();
            this.divRemTo(divisor, quotient, null);
            return quotient;
        }
        
        /**
         * this^e % m (HAC 14.85)
         */
        public BigInt powMod(BigInt exp, BigInt mod)
        {
            Integer i = exp.bitLength();
            Integer k;
            BigInt r = new BigInt(1);
            Reducer z;
            if (i <= 0) return r;
            else if (i < 18) k = 1;
            else if (i < 48) k = 3;
            else if (i < 144) k = 4;
            else if (i < 768) k = 5;
            else k = 6;
            
            if (i < 8)
            {
                z = new ClassicReducer(mod);
            }
            else if (mod.isEven())
            {
                z = new BarrettReducer(mod);
            }
            else
            {
                z = new MontgomeryReducer(mod);
            }
            
            // precomputation
            Map<Integer,BigInt> g = new Map<Integer,BigInt>();
            Integer n = 3;
            Integer k1 = k - 1;
            Integer km = (1 << k) - 1;
            g.put(1, z.convert(this));
            if (k > 1)
            {
                BigInt g2 = new BigInt();
                z.sqrTo(g.get(1), g2);
                while (n <= km)
                {
                    g.put(n, new BigInt());
                    z.mulTo(g2, g.get(n - 2), g.get(n));
                    n += 2;
                }
            }
            Integer j = exp.size - 1;
            Integer w;
            Boolean is1 = true;
            BigInt r2 = new BigInt();
            BigInt t;
            i = bits(exp.words.get(j)) - 1;
            while (j >= 0)
            {
                if  (i >= k1) w = (exp.words.get(j) >> (i - k1)) & km;
                else
                {
                    w = (exp.words.get(j) & ((1 << (i + 1)) - 1)) << (k1 - i);
                    if (j > 0) w |= exp.words.get(j - 1) >> (DBITS + i - k1);
                }
                n = k;
                while ((w & 1) == 0) {w >>= 1; --n;}
                if ((i -= n) < 0) {i += DBITS; --j;}
                if (is1)
                {
                    g.get(w).copyTo(r);
                    is1 = false;
                }
                else
                {
                    while (n > 1) {z.sqrTo(r, r2); z.sqrTo(r2, r); n -= 2;}
                    if (n > 0) z.sqrTo(r, r2); else {t = r; r = r2; r2 = t;}
                    z.mulTo(r2, g.get(w), r);
                }
                while (j >= 0 && (exp.words.get(j) & (1 << i)) == 0)
                {
                    z.sqrTo(r, r2); t = r; r = r2; r2 = t;
                    if (--i < 0) {i = DBITS - 1; --j;}
                }
            }
            return z.revert(r);
        }
    
        /**
         * true iff this is even
         */
        Boolean isEven()
        {
            return ((this.size > 0) ? (this.words.get(0) & 1) : this.sign) == 0;
        }

        /**
         * return "-1/this % 2^DB"; useful for Mont. reduction
         * justification:
         *         xy == 1 (mod m)
         *         xy =  1+km
         *   xy(2-xy) = (1+km)(1-km)
         * x[y(2-xy)] = 1-k^2m^2
         * x[y(2-xy)] == 1 (mod m^2)
         * if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
         * should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
         * JS multiply "overflows" differently from C/C++, so care is needed here.
         */
        Integer invDigit()
        {
            if (this.size < 1) return 0;
            Integer x = this.words.get(0);
            if ((x & 1) == 0) return 0;
            Integer y = x & 3; // y == 1/x mod 2^2
            y = (y * (2 - (x & 15) * y)) & 15; // y == 1/x mod 2^4
            y = (y * (2 - (x & 255) * y)) & 255; // y == 1/x mod 2^8
            y = (y * (2 - (((x & 65535) * y) & 65535))) & 65535; // y == 1/x mod 2^16
            
            // last step - calculate inverse mod DV directly;
            // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
            y = Math.mod(y * (2 - Math.mod(x * y, DVAL)), DVAL); // y == 1/x mod 2^dbits
            
            // we really want the negative inverse, and -DV < y < DV
            return (y > 0) ? DVAL - y : -y;
        }

        /**
         * this += n << w words, this >= 0
         */
        void dAddOffset(Integer n, Integer w)
        {
            if (n == 0) return;
            while (this.size <= w) this.words.put(this.size++, 0);
            this.plusEquals(w, n);
            while (this.words.get(w) >= DVAL)
            {
                this.minusEquals(w, DVAL);
                if (++w >= this.size) this.words.put(this.size++, 0);
                this.increment(w);
            }
        }

        /**
         * r = "this * a" without lower n words, n > 0
         * "this" should be the larger one if appropriate.
         */
        void multiplyUpperTo(BigInt a, Integer n, BigInt r)
        {
            --n;
            Integer i = r.size = this.size + a.size - n;
            r.sign = 0; // assumes a,this >= 0
            while (--i >= 0) r.words.put(i, 0);
            for (i = Math.max(n - this.size, 0); i < a.size; ++i)
            {
                r.words.put(this.size + i - n, this.am(n - i, a.words.get(i), r, 0, 0, this.size + i - n));
            }
            r.clamp();
            r.drShiftTo(1, r);
        }

        /**
         * r = lower n words of "this * a", a.t <= n
         * "this" should be the larger one if appropriate.
         */
        void multiplyLowerTo(BigInt a, Integer n, BigInt r)
        {
            Integer i = Math.min(this.size + a.size, n);
            r.sign = 0; // assumes a,this >= 0
            r.size = i;
            while(i > 0) r.words.put(--i, 0);
            Integer j;
            for (j = r.size - this.size; i < j; ++i)
            {
                r.words.put(i + this.size, this.am(0, a.words.get(i), r, i, 0, this.size));
            }
            for (j = Math.min(a.size, n); i < j; ++i)
            {
                this.am(0, a.words.get(i), r, i, 0, n - i);
            }
            r.clamp();
        }
    }

    /**
     * A "null" reducer
     */
    abstract class Reducer
    {
        Reducer() {}
        abstract BigInt revert(BigInt x);
        abstract BigInt convert(BigInt x);
        abstract void sqrTo(BigInt x, BigInt r);
        abstract void mulTo(BigInt x, BigInt y, BigInt r);
    }

    /**
     * Modular reduction using "classic" algorithm
     */
    class ClassicReducer extends Reducer
    {
        BigInt m;
        
        ClassicReducer(BigInt m)
        {
            this.m = m;
        }
        
        override BigInt convert(BigInt x)
        {
            if (x.sign < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
            else return x;
        }
        
        override BigInt revert(BigInt x)
        {
            return x;
        }
        
        void reduce(BigInt x)
        {
            x.divRemTo(this.m, null, x);
        }
        
        override void mulTo(BigInt x, BigInt y, BigInt r)
        {
            x.multiplyTo(y, r);
            this.reduce(r);
        }
        
        override void sqrTo(BigInt x, BigInt r)
        {
            x.squareTo(r);
            this.reduce(r);
        }
    }

    /**
     * Montgomery reduction
     */
    class MontgomeryReducer extends Reducer
    {
        BigInt m;
        Integer mp;
        Integer mpl;
        Integer mph;
        Integer um;
        Integer mt2;
        
        MontgomeryReducer(BigInt m)
        {
            this.m = m;
            this.mp = m.invDigit();
            this.mpl = this.mp & 32767;
            this.mph = this.mp >> 15;
            this.um = (1 << (m.DBITS - 15)) - 1;
            this.mt2 = 2 * m.size;
        }
        
        override BigInt convert(BigInt x)
        {
            BigInt r = new BigInt();
            x.abs().dlShiftTo(this.m.size, r);
            r.divRemTo(this.m, null, r);
            if (x.sign < 0 && r.compareTo(new BigInt(0)) > 0) this.m.subTo(r, r);
            return r;
        }
        
        /**
         * x/R mod m
         */
        override BigInt revert(BigInt x)
        {
          BigInt r = new BigInt();
          x.copyTo(r);
          this.reduce(r);
          return r;
        }

        /**
         * r = "xy/R mod m"; x,y != r
         */
        override void mulTo(BigInt x, BigInt y, BigInt r)
        {
            x.multiplyTo(y, r);
            this.reduce(r);
        }

        /**
         * r = "x^2/R mod m"; x != r
         */
        override void sqrTo(BigInt x, BigInt r)
        {
            x.squareTo(r);
            this.reduce(r);
        }
        
        /**
         * x = x/R mod m (HAC 14.32)
         */
        void reduce(BigInt x)
        {
            // pad x so am has enough room later
            while (x.size <= this.mt2) x.words.put(x.size++, 0);
            
            for (Integer i = 0; i < this.m.size; ++i)
            {
                // faster way of calculating u0 = x[i]*mp mod DV
                Integer j = x.words.get(i) & 32767;
                Integer u0 = (j * this.mpl + (((j * this.mph + (x.words.get(i) >> 15) * this.mpl) & this.um) << 15)) & x.DMAX;

                // use am to combine the multiply-shift-add into one call
                j = i + this.m.size;
                x.plusEquals(j, this.m.am(0, u0, x, i, 0, this.m.size));

                // propagate carry
                while(x.words.get(j) >= x.DVAL)
                {
                    x.minusEquals(j, x.DVAL);
                    x.increment(++j);
                }
            }
            x.clamp();
            x.drShiftTo(this.m.size, x);
            if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
        }
    }

    /**
     * Barrett modular reduction
     */
    class BarrettReducer extends Reducer
    {
        BigInt m;
        BigInt r2;
        BigInt q3;
        BigInt mu;
        
        BarrettReducer(BigInt m)
        {
            // setup Barrett
            this.r2 = new BigInt();
            this.q3 = new BigInt();
            new BigInt(1).dlShiftTo(2 * m.size, this.r2);
            this.mu = this.r2.divide(m);
            this.m = m;
        }
        
        /**
         * r = x*y mod m; x != r
         */
        override void mulTo(BigInt x, BigInt y, BigInt r)
        {
            x.multiplyTo(y, r);
            this.reduce(r);
        }
        
        /**
         * r = x^2 mod m; x != r
         */
        override void sqrTo(BigInt x, BigInt r)
        {
            x.squareTo(r);
            this.reduce(r);
        }
        
        override BigInt revert(BigInt x)
        {
            return x;
        }

        override BigInt convert(BigInt x)
        {
            if (x.sign < 0 || x.size > 2 * this.m.size)
            {
                return x.mod(m);
            }
            else if (x.compareTo(m) < 0)
            {
                return x;
            }
            else
            {
                BigInt r = new BigInt();
                x.copyTo(r);
                this.reduce(r);
                return r;
            }
        }
        
        /**
         * x = x mod m (HAC 14.42)
         */
        void reduce(BigInt x)
        {
            x.drShiftTo(this.m.size - 1, r2);
            if (x.size > this.m.size + 1)
            {
                x.size = this.m.size + 1;
                x.clamp();
            }
            this.mu.multiplyUpperTo(this.r2, this.m.size + 1, this.q3);
            this.m.multiplyLowerTo(this.q3, this.m.size + 1, this.r2);
            while (x.compareTo(this.r2) < 0)
            {
                x.dAddOffset(1, this.m.size + 1);
            }
            x.subTo(r2, x);
            while (x.compareTo(this.m) >= 0)
            {
                x.subTo(this.m, x);
            }
        }
        
    }



    /**
     * @mattandneil Apex port of RSA Key Util by Kenji Urushima
     * https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Operation
     * 
     * Copyright (c) 2010-2018  Kenji Urushima
     * All Rights Reserved. kenji.urushima@gmail.com
     * kjur.github.com/jsrsasign/license
     *
     * Permission is hereby granted, free of charge, to any person obtaining
     * a copy of this software and associated documentation files (the
     * "Software"), to deal in the Software without restriction, including
     * without limitation the rights to use, copy, modify, merge, publish,
     * distribute, sublicense, and/or sell copies of the Software, and to
     * permit persons to whom the Software is furnished to do so, subject to
     * the following conditions:
     *
     * The above copyright notice and this permission notice shall be
     * included in all copies or substantial portions of the Software.
     *
     * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
     * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
     * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
     *
     * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
     * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
     * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
     * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
     * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
     */
    public class Rsa
    {
        BigInt N; // modulus
        BigInt E; // publicExponent
        BigInt D; // privateExponent
        BigInt P; // prime1
        BigInt Q; // prime2
        BigInt Dp; // exponent1 -- d mod (p-1)
        BigInt Dq; // exponent2 -- d mod (q-1)
        BigInt Qinv; // coefficient -- (inverse of q) mod p
    
        public Rsa(List<Blob> values)
        {
            if (values.size() == 9) this(values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8]);
            else throw new StringException('RSA key must contain 9 values: ' + values); // disregard 0th blob '00'
        }
        
        /**
         * Set the private key fields N, e, d and CRT params
         */
        public Rsa(Blob n, Blob e, Blob d, Blob p, Blob q, Blob dp, Blob dq, Blob qinv)
        {
            this.N = new BigInt(n);
            this.E = new BigInt(e);
            this.D = new BigInt(d);
            this.P = new BigInt(p);
            this.Q = new BigInt(q);
            this.Dp = new BigInt(dp);
            this.Dq = new BigInt(dq);
            this.Qinv = new BigInt(qinv);
        }
        
        /**
         * sign hash value of message to be signed with RSA private key.
         */
        public Blob signSha512(Blob message) //function(sHashHex, hashAlg) {
        {
            Blob messageDigest = new SHA512(message).generateDigest();
            return this.doPrivate(messageDigest);
        }
        
        /**
         * Perform raw private operation on cryptoMessage: C ^ D % PQ
         * https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm
         * "This is more efficient than computing exponentiation by squaring even though two modular exponentiations have to
         * be computed. The reason is that these two modular exponentiations both use a smaller exponent and a smaller modulus."
         */
        Blob doPrivate(Blob cryptoMessage)
        {
            BigInt C = new BigInt(cryptoMessage);
            
            // BigInt m = C.powMod(D, P.multiply(Q));
            // too slow, exceeds Apex CPU time limit
            // use Chinese remainder theorem below
            
            // m1 = C ^ Dp % P
            BigInt m1 = C.powMod(Dp, P);
            
            // m2 = C ^ Dq % Q
            BigInt m2 = C.powMod(Dq, Q);
            
            // sometimes m1 < m2
            while (m1.compareTo(m2) < 0) m1 = m1.add(P);
            
            // h = Qinv (m1 - m2) % P
            BigInt h = Qinv.multiply(m1.subtract(m2)).mod(P);
            
            // m = m2 + hq % PQ
            BigInt m = m2.add(h.multiply(Q).mod(P.multiply(Q)));
            
            // === C ^ D % PQ
            return m.toBlob();
        }
        
    }



    /**
     * @mattandneil Apex port of SHA-512 message digest
     * https://en.wikipedia.org/wiki/SHA-512#Test_vectors
     * 
     * Copyright (c) Michael Trittin
     * github.com/trittimo/SHA512/tree/master
     */
    public class SHA512
    {
        /**
         * Message to hash
         */
        Blob input;
        
        /**
         * initial buffer values
         */
        final List<Long> iv = new List<Long>
        {
            7640891576956012808L,
           -4942790177534073029L,
            4354685564936845355L,
           -6534734903238641935L,
            5840696475078001361L,
           -7276294671716946913L,
            2270897969802886507L,
            6620516959819538809L
        };
        
        /**
         * constant words used
         */
        final List<Long> k = new List<Long>
        {
            4794697086780616226L,  8158064640168781261L, -5349999486874862801L, -1606136188198331460L,
            4131703408338449720L,  6480981068601479193L, -7908458776815382629L, -6116909921290321640L,
           -2880145864133508542L,  1334009975649890238L,  2608012711638119052L,  6128411473006802146L,
            8268148722764581231L, -9160688886553864527L, -7215885187991268811L, -4495734319001033068L,
           -1973867731355612462L, -1171420211273849373L,  1135362057144423861L,  2597628984639134821L,
            3308224258029322869L,  5365058923640841347L,  6679025012923562964L,  8573033837759648693L,
           -7476448914759557205L, -6327057829258317296L, -5763719355590565569L, -4658551843659510044L,
           -4116276920077217854L, -3051310485924567259L,  0489312712824947311L,  1452737877330783856L,
            2861767655752347644L,  3322285676063803686L,  5560940570517711597L,  5996557281743188959L,
            7280758554555802590L,  8532644243296465576L, -9096487096722542874L, -7894198246740708037L,
           -6719396339535248540L, -6333637450476146687L, -4446306890439682159L, -4076793802049405392L,
           -3345356375505022440L, -2983346525034927856L, -0860691631967231958L,  1182934255886127544L,
            1847814050463011016L,  2177327727835720531L,  2830643537854262169L,  3796741975233480872L,
            4115178125766777443L,  5681478168544905931L,  6601373596472566643L,  7507060721942968483L,
            8399075790359081724L,  8693463985226723168L, -8878714635349349518L, -8302665154208450068L,
           -8016688836872298968L, -6606660893046293015L, -4685533653050689259L, -4147400797238176981L,
           -3880063495543823972L, -3348786107499101689L, -1523767162380948706L, -0757361751448694408L,
            0500013540394364858L,  0748580250866718886L,  1242879168328830382L,  1977374033974150939L,
            2944078676154940804L,  3659926193048069267L,  4368137639120453308L,  4836135668995329356L,
            5532061633213252278L,  6448918945643986474L,  6902733635092675308L,  7801388544844847127L
        };
        
        public SHA512(Blob input)
        {
            this.input = input;
        }
        
        /**
         * Does the actual hash
         */
        public Blob generateDigest()
        {
            List<Integer> bytes = EncodingUtil.convertToHex(this.input).replaceAll('..', '\\\\u00$0').getChars();
            
            // First pad the input to the correct length, adding the bits specified in the SHA algorithm
            bytes = pad(bytes);
            
            // Break the padded input up into blocks
            List<List<Long>> blocks = toBlocks(bytes);
            
            // And get the expanded message blocks
            List<List<Long>> w = message(blocks);
            
            // Set up the buffer which will eventually contain the final hash
            // Initially, it's set to the constants provided as part of the algorithm
            List<Long> buffer = iv.clone();
            
            // For every block
            for (Integer i = 0, size = blocks.size(); i < size; i++)
            {
                // a-h is set to the buffer initially
                Long a = buffer[0];
                Long b = buffer[1];
                Long c = buffer[2];
                Long d = buffer[3];
                Long e = buffer[4];
                Long f = buffer[5];
                Long g = buffer[6];
                Long h = buffer[7];
                
                // Run 80 rounds of the SHA-512 compression function on a-h
                for (Integer j = 0; j < 80; j++)
                {
                    Long t1 = h + sigma1(e) + ch(e, f, g) + k[j] + w[i][j];
                    Long t2 = sigma0(a) + Maj(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }
                
                // After finishing the compression, save the state to the buffer
                buffer[0] += a;
                buffer[1] += b;
                buffer[2] += c;
                buffer[3] += d;
                buffer[4] += e;
                buffer[5] += f;
                buffer[6] += g;
                buffer[7] += h;
            }
            
            // After everything is done, return the final hash as a blob
            String hex = '';
            for (Integer i = 0; i < 8; i++)
            {
                hex += qwordToHex(buffer[i]);
            }
            
            return EncodingUtil.convertFromHex(hex);
        }
        
        /**
         * Used in the compression function
         */
        Long ch(Long x, Long y, Long z)
        {
            return (x & y) ^ (~x & z);
        }
        
        Long Maj(Long x, Long y, Long z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }
        
        Long rotate(Long x, Integer l)
        {
            return (x >>> l) | (x << (64 - l)); // Long.SIZE = 64
        }
        
        /**
         * Right shift by n bits = sX
         * Right rotate by n bits = rX
         */
        Long sigma0(Long x)
        {
            // r28(x) ^ r34(x) ^ r39(x)
            return rotate(x, 28) ^ rotate(x, 34) ^ rotate(x, 39); 
        }
        
        Long sigma1(Long x)
        {
            // r14(x) ^ r18(x) ^ r41(x)
            return rotate(x, 14) ^ rotate(x, 18) ^ rotate(x, 41);
        }
        
        Long uSigma0(Long x)
        {
            // r1(x) ^ r8(x) ^ s7(x)
            return rotate(x, 1) ^ rotate(x, 8) ^ (x >>> 7);
        }
        
        Long uSigma1(Long x)
        {
            // r19(x) ^ r61(x) ^ s6(x)
            return rotate(x, 19) ^ rotate(x, 61) ^ (x >>> 6);
        }
        
        /**
         * Pad the input byte array
         */
        List<Integer> pad(List<Integer> bytes)
        {
            // Need to append at least 17 bytes (16 for length of the message, and 1 for the '1' bit)
            // then fill with 0s until multiple of 128 bytes
            Integer length = bytes.size() + 17;
            while (Math.mod(length, 128) != 0)
            {
                length += 1;
            }
            
            // The padded byte array
            List<Integer> out = new List<Integer>(length);
    
            // Copy over the old stuff
            for (Integer i = 0, size = bytes.size(); i < size; i++)
            {
                out[i] = bytes[i];
            }
            
            // Add the '1' bit
            out[bytes.size()] = 128; // -128 = 0x80
            
            // Convert the original length of the input to a byte array
            List<Integer> lenInBytes = new List<Integer>{bytes.size() * 8};
            // https://crypto.stackexchange.com/a/22957
            
            // And put it at the end of our padded input
            for (Integer i = lenInBytes.size(); i > 0; i--)
            {
                out[length - i] = lenInBytes[lenInBytes.size() - i];
            }
            
            return out;
        }
        
        /**
         * Converts the byte array input
         * starting at index j into a Long
         */
        Long arrToLong(List<Integer> input, Integer j)
        {
            for (Integer i = 0, size = input.size(); i < size; i++)
            if (input[i] == null) input[i] = 0;
            
            Long v = 0;
            if (input.isEmpty()) return 0;
            
            for (Integer i = 0; i < 8; i++)
            v = (v << 8) + (input[i + j] & -1); //-1 = 0xFF
            
            return v;
        }
        
        /**
         * Converts the byte array input into blocks of longs
         */
        List<List<Long>> toBlocks(List<Integer> input)
        {
            // a block has: 1024 bits = 128 bytes = 16 longs
            List<List<Long>> blocks = new List<List<Long>>(input.size() / 128);
            for (Integer i = 0, size = blocks.size(); i < size; i++) blocks[i] = new List<Long>(16);
            
            // For every block
            for (Integer i = 0, size = input.size(); i < size / 128; i++)
            {
                // For each long in a block
                for (Integer j = 0; j < 16; j++)
                {
                    // Set the block value to the correct one
                    blocks[i][j] = arrToLong(input, i * 128 + j * 8);
                }
            }
            return blocks;
        }
        
        /**
         * Calculates the expanded message blocks W0-W79
         */
        List<List<Long>> message(List<List<Long>> m)
        {
            List<List<Long>> w = new List<List<Long>>(m.size());
            for (Integer i = 0, size = w.size(); i < size; i++) w[i] = new List<Long>(80);
    
            // For each block in the input
            for (Integer i = 0, size = m.size(); i < size; i++)
            {
                // For each long in the block
                for (Integer j = 0; j < 16; j++)
                {
                    // Set the initial values of W to be the value of the input directly
                    w[i][j] = m[i][j];
                }
    
                // For the rest of the values
                for (Integer j = 16; j < 80; j++)
                {
                    // Do some math from the SHA512 algorithm
                    w[i][j] = uSigma1(w[i][j-2]) + w[i][j-7] + uSigma0(w[i][j-15]) + w[i][j-16];
                }
            }
            
            return w;
        }
        
        /**
         * Big endian int2hex like #45 RGBA color format
         * https://introcs.cs.princeton.edu/java/61data/
         */
        String qwordToHex(Long qword)
        {
            return ''
                + bytes[(255 & qword >> 56).intValue()]
                + bytes[(255 & qword >> 48).intValue()]
                + bytes[(255 & qword >> 40).intValue()]
                + bytes[(255 & qword >> 32).intValue()]
                + bytes[(255 & qword >> 24).intValue()]
                + bytes[(255 & qword >> 16).intValue()]
                + bytes[(255 & qword >> 08).intValue()]
                + bytes[(255 & qword >> 00).intValue()]
            ;
        }
        
        final List<String> bytes = new List<String>{
            '00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f',
            '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f',
            '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f',
            '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f',
            '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f',
            '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f',
            '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f',
            '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f',
            '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f',
            '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f',
            'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af',
            'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf',
            'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf',
            'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df',
            'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef',
            'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff'
        };
    }
}
