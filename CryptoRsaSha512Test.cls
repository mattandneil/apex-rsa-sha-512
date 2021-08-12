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
        System.assertEquals('8493cf2b7f3e16e6a143dd6f5bcacc5cbadef0ac8c5e02a2e9f6b8ce67538b02d2d2e2cc1dfd285be750375fabbd742ccde527ba6bd0247eef64e0b189497b30df381a1976c2c0267a2ba521ba32994f180f251f55193b290c2dc3f8d3c26a736853ce1fc3eecb3cdbeacce5b77f5e108fbde81a7b476f89bf0ec395ebdd2ebf', EncodingUtil.convertToHex(actual));
    }
}
