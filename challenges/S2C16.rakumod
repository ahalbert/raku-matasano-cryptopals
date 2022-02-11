use S2C10;
use S2C9;
use S2C11;
use S1C5;

my $BLOCKSIZE = 16;

role Oracle {
  has Buf $.key;
  has Buf $.secret;
  has Int $.blocksize = 16;

  submethod BUILD() {
    $!key = generateAESKey();
    $!secret = asciiToBuf("this is armands-test supersecret");
  }

  multi method encrypt(Buf $plaintext) {}

  multi method decrypt(Buf $plaintext) {}
}

class CBCOracle does Oracle {
  has Buf $.iv = generateAESKey();


  multi method encrypt(Str $userdata) {
    my $text = asciiToBuf("comment1=cooking%20MCs;userdata=" ~ $userdata.subst(";", "").subst("=","") ~ ";comment2=%20like%20a%20pound%20of%20bacon");
    $text = pkcs7pad($text, $BLOCKSIZE);
    encrypt_AES_CBC($text, $.key, $.iv);
  }

  multi method decrypt(Buf $ciphertext) {
    my $plaintext = decrypt_AES_CBC($ciphertext, $.key, $.iv);
    $plaintext = Buf.new($plaintext.List.grep: {$_ < 128});
    say $plaintext.decode;
    return True if $plaintext ~~ /.*admin\=true.*/; 
    False;
  }
}

class CBCBitFlipper {
  has Oracle $.oracle;
  has Int $.prefixLength;

  method getPrefixLength() {
    my $ciphertextA = $.oracle.encrypt("A");
    my $ciphertextB = $.oracle.encrypt("B");
    my $len = 0;
    $len++ while $ciphertextA[$len] == $ciphertextB[$len];
    $len = ($len/$BLOCKSIZE).Int * $BLOCKSIZE;
    for 1..$BLOCKSIZE {
      $ciphertextA = $.oracle.encrypt(("A" x $_) ~ "X");
      $ciphertextB = $.oracle.encrypt(("A" x $_) ~ "Y");
      return $len + ($BLOCKSIZE-$_) if $ciphertextA[$len..$len+$BLOCKSIZE-1] eqv $ciphertextB[$len..$len+$BLOCKSIZE-1];
    }
    -1;
  }

  method insertAdmin() {
    $!prefixLength = self.getPrefixLength();
    my $payload = "??????admin?true";
    my $ciphertext = $.oracle.encrypt($payload);
    my $semicolon = Buf.new($ciphertext[$!prefixLength - 11]) ~^ asciiToBuf("?") ~^ asciiToBuf(";");
    my $equals = Buf.new($ciphertext[$!prefixLength - 5]) ~^ asciiToBuf("?") ~^ asciiToBuf("=");
    my $adminCiphertext = Buf.new(flat $ciphertext[0..$!prefixLength-12], $semicolon.List, $ciphertext[$!prefixLength-10..$!prefixLength-6], $equals.List, $ciphertext[$!prefixLength-4..$ciphertext.bytes-1]);
    say $adminCiphertext.bytes;
    say $.oracle.decrypt($adminCiphertext);
  }

}

sub MAIN() {
  my $oracle = CBCOracle.new();
  my $ciphertext = $oracle.encrypt("Armand");
  say $oracle.decrypt($ciphertext);
  say "---------";
  my $solver = CBCBitFlipper.new(oracle => $oracle);
  $solver.insertAdmin();
}
