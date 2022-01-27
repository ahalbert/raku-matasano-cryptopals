use Base64;
use S2C9;
use S2C11;
use S1C7;
use S1C5;


my $key = generateAESKey();
my $BLOCKSIZE = 16;
my $secret = asciiToBuf("hello");
#my $unknownString = decode-base64("", :bin);

sub unknownStringECBEncrypt(Buf $plaintext is copy) {
  my $text = pkcs7pad($plaintext ~ $secret, $BLOCKSIZE);
  AES_ECB_Encrypt($text, $key);
}

sub getBlockLength() {
  my $text = Buf.new();
  my $ciphertext = unknownStringECBEncrypt($text);
  my $empty_len = $ciphertext.bytes;
  my $len = $empty_len;
  while $empty_len == $len {
    $text.push: 'A'.ord;
    $ciphertext = unknownStringECBEncrypt($text);
    $len = $ciphertext.bytes;
  }
  $len - $empty_len;
}

sub decryptByte(Buf $decryptedString) {
  say $decryptedString;
  my $testlength = ($BLOCKSIZE - (1 + $decryptedString.bytes)) % $BLOCKSIZE;
  my $prefix = asciiToBuf("A" x $testlength);
  my $realcipher = unknownStringECBEncrypt($prefix);
  my $len = $testlength + $decryptedString.bytes;
  for (0..255).map: { Buf.new($_) } {
    my $result = unknownStringECBEncrypt($prefix ~ $decryptedString ~ $_);
    return $_ if $result[0..$len].List eqv $realcipher[0..$len].List;
  }
    say $realcipher;
}

sub decryptUnknownString() {
  my Buf $decryptedString = Buf.new;
  for 1..$secret.bytes {
    say "--";
    say $_;
    my $result = decryptByte($decryptedString);
    $decryptedString.push: $result if $result.defined;
    say $decryptedString.decode;
  }
  $decryptedString;
}

sub MAIN() {
  my $plaintext = generateAESKey();
  my $ciphertext = unknownStringECBEncrypt(Buf.new());
  say getBlockLength();
  say decryptUnknownString().decode;
  
}
