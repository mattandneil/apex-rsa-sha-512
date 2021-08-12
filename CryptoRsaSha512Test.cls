@IsTest(IsParallel=false) class CryptoRsaSha512Test
{
    static String pemFile = ''
        + '-----BEGIN RSA PRIVATE KEY-----\n'
        + 'MIICXAIBAAKBgQCpIwKH7fYUgtCtOCtnvIlAXcFvzLPkLWWHNZoT+hOIzTWR+PrO'
        + 'QiQrat7wsVD+161g3CUUcdpTR2HMSThWxEjLldsZq0BA3TqEecXmV6rZzy0ZTJb2'
        + 'tgzjoX+eNiLvIHpgAaq5x2g2J9mB/b/9PFWspvQgMPAXl6rpAM5ZNIEwuQIDAQAB'
        + 'AoGBAKLMYP5HbMo3U/a3Dwhtr8p1s+ARr8FcdNIdJO4/khfmNb8IYRixDzF/T5Fr'
        + 'iyOQo4CMxWAVamkoVxkUDRdvHQTO17hWMKysLIn46y3bHxxRb6g5tpSwK61L25Hd'
        + 'iwi9GjqGrn7Z5rMFIqOqaCIX9gUQICmW31Y7XyekZ9RPA+8VAkEA39A2eqystpFT'
        + 'tkvfrAgG7uOL4IrckA5kuC4xPHeehvlI8bDZU4kmLFNnduNOVtfKSxzfT4l+Qvl8'
        + 'IRxUycRodwJBAMF12s9NvILcJ1i2Ah2oTf91gkv82XoNOr0DsdLMqRkNSODKWiqx'
        + 'wZTVq8OeiWwF58FzdBmNJegVfoE2eO0zrE8CQH7B0KkHtMWtZwjeze4DmdGgQ+9H'
        + 'FgXscPSzDKWfZcQx2TMxItSh32HJVtbJg+vBSUvjLUJBr6XE4J1sC0U+nJ8CQE/4'
        + 'eunk1X82qGEoY7mEwDFQjvsAW5nzbAuEQnbEOUZs0mpx21H4xu/SX71uhJoN2t6B'
        + '7kU9rqTAddnN/bD4AksCQBuhIVld31iTzgyrc4R9e+KnLuW0rP/01SWYPYE0oeYC'
        + 'ViZ/r19XsHQicPFLjKtKoOLNhVlHGsrW0yCnpcb2ahs=\n'
        + '-----END RSA PRIVATE KEY-----'
    ;
    
    @IsTest static void testSign()
    {
        // arrange
        Blob message = Blob.valueOf('achoo');
        
        // act
        Blob actual = CryptoRsaSha512.sign(message, pemFile);
        
        // assert
        System.assertEquals('195657c3d157fe851370ebc6a6c8034cba9d2d01a2406c3b733e8caf76914d828fc1e3cee1a2ded9adbf39bf830a6b48ad51db7a6ad4d32fc372b4642b6e0241480f9b67f540946c4a910559ce24af0687886acd54e890c865f98b89f92db9ebd3248d135dba69fedcf73ff9557cb099f5302fc601a020dc904570ae63dce4e5', EncodingUtil.convertToHex(actual));
    }
}
