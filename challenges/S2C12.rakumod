use Base64;
use S2C9;
use S2C11;
use S1C7;
use S1C5;


my $key = generateAESKey();
my $BLOCKSIZE = 16;

my $secret = decode-base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK", :bin);

say $secret.decode;
class ECBOracle {
  has Buf $.secret;
  has Buf $.key;
  has Int $.blocksize;

  method unknownStringECBEncrypt(Buf $plaintext) {
    my $text = pkcs7pad($plaintext ~ $!secret, $BLOCKSIZE);
    AES_ECB_Encrypt($text, $!key);
  }

  method getBlockLength() {
    my $text = Buf.new();
    my $ciphertext = self.unknownStringECBEncrypt($text);
    my $empty_len = $ciphertext.bytes;
    my $len = $empty_len;
    while $empty_len == $len {
      $text.push: 'A'.ord;
      $ciphertext = self.unknownStringECBEncrypt($text);
      $len = $ciphertext.bytes;
    }
    $!blocksize = ($len - $empty_len);
    $.blocksize;
  }

  method decryptByte(Buf $decryptedString) {
    my $testlength = ($.blocksize - (1 + $decryptedString.bytes)) % $.blocksize;
    my $prefix = asciiToBuf("A" x $testlength);
    my $realcipher = self.unknownStringECBEncrypt($prefix);
    my $len = $testlength + $decryptedString.bytes;
    for (0..255).map: { Buf.new($_) } {
      my $result = self.unknownStringECBEncrypt($prefix ~ $decryptedString ~ $_);
      return $_ if $result[0..$len].List eqv $realcipher[0..$len].List;
    }
    Buf.new();
  }

  method decryptUnknownString() {
    my Buf $decryptedString = Buf.new;
    for 1..$secret.bytes {
      my $result = self.decryptByte($decryptedString);
      $decryptedString.push: $result if $result.defined;
    }
    $decryptedString;
  }
}



sub MAIN() {
  my $oracle = ECBOracle.new( key => $key, secret => $secret);
  say $oracle.getBlockLength();
  say $oracle.decryptUnknownString().decode;
  
}
