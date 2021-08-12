# RSA-SHA512 in Apex

This solution stands of the shoulders of a number of people who provided reference<br/>implementations and ideas. We wish to express appreciation for their published work:

* RSA key utility by Kenju Urushima [https://github.com/kjur/jsrsasign](https://github.com/kjur/jsrsasign)
* ASN.1 parser by Lapo Luchini [https://github.com/lapo-luchini/asn1js](https://github.com/lapo-luchini/asn1js)
* BIGINT math by Tom Hu [http://www-cs-students.stanford.edu/~tjw](http://www-cs-students.stanford.edu/~tjw)
* SHA512 message digest by Michael Tritton [https://github.com/trittimo/SHA512](https://github.com/trittimo/SHA512)

![diagram](https://raw.githubusercontent.com/mattandneil/apex-rsa-sha-512/master/diagram.png)

1. A **private key file** holds secret prime numbers
2. An **ASN key reader** handles the binary file format
3. The **message to sign** consists of a JSON Web Token
4. Then a **SHA512 hash** reduces the message to a big integer
5. Finally the **RSA signer** executes the modPow signature math

## Usage:

```
Blob signature = CryptoRsaSha512.sign(message, privateKey);
```

While we can't provide ad-hoc support for this code, please contact us with your company<br/>name and address if you need a warranty for its use and we will assist: [www.tostring.co.uk/contact](https://www.tostring.co.uk/contact)
