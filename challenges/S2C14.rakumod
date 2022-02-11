use Base64;
use S2C9;
use S1C5;
use AES;


my $key = generateAESKey();
my $BLOCKSIZE = 16;

role Oracle {
  has Buf $.key;
  has Buf $.secret;
  has Int $.blocksize = 16;


  multi method encrypt(Buf $plaintext) {
    AES_ECB_Encrypt(pkcs7pad($plaintext, $BLOCKSIZE));
  }

  multi method encrypt(Buf $plaintext) {
    AES_ECB_Encrypt(pkcs7pad($plaintext, $BLOCKSIZE));
  }
}

class RandomStringOracle does Oracle {

  has $.noise = Buf.new((2..64.rand.Int).map: {256.rand.Int});

  submethod BUILD() {
    $!key = generateAESKey();
    $!secret = asciiToBuf("this is armands-test supersecret");
  }

  multi method encrypt(Buf $plaintext) {
    my $text = pkcs7pad($!noise ~ $plaintext ~ $!secret, $BLOCKSIZE);
    AES_ECB_Encrypt($text, $!key);
  }
}

role ECB_OracleSolver {
  has Oracle $.oracle;

  multi method decrypt() { }

}

class AES_ECB_Solver does ECB_OracleSolver {

  # method getBlockLength() {
  #   my $text = Buf.new();
  #   my $ciphertext = self.unknownStringECBEncrypt($text);
  #   my $empty_len = $ciphertext.bytes;
  #   my $len = $empty_len;
  #   while $empty_len == $len {
  #     $text.push: 'A'.ord;
  #     $ciphertext = self.unknownStringECBEncrypt($text);
  #     $len = $ciphertext.bytes;
  #   }
  #   $!blocksize = ($len - $empty_len);
  #   $.blocksize;
  # }
  #
  
  has $.prefixLength;

  method getPrefixLength() {
    my $attack = asciiToBuf("B");
    my $empty_ciphertext = $!oracle.encrypt(Buf.new);
    my $padded_ciphertext = $!oracle.encrypt($attack);
    my $prefix_block = 0;
    for zip($empty_ciphertext.rotor($BLOCKSIZE), $padded_ciphertext.rotor($BLOCKSIZE)) {
      last  unless $_[0] eqv $_[1];
      $prefix_block++;
    }
    $attack = asciiToBuf("B" x (2*$BLOCKSIZE));
    for 0..$BLOCKSIZE-1 {
      my $ciphertext = $!oracle.encrypt($attack);
      $!prefixLength = $_ != 0 ?? ($prefix_block*($BLOCKSIZE) + ($BLOCKSIZE - $_))  !! $prefix_block*$BLOCKSIZE  if detectRepeatingBytes($ciphertext);
      return $_ != 0 ?? ($prefix_block*($BLOCKSIZE) + ($BLOCKSIZE - $_))  !! $prefix_block*$BLOCKSIZE if detectRepeatingBytes($ciphertext);
      $attack.push: "B".ord;
    }
  }

  method decryptByte(Buf $decryptedString) {
    my $testlength = ($BLOCKSIZE - (1 + $decryptedString.bytes)) % $BLOCKSIZE;
    my $prefix = asciiToBuf("A" x $testlength);
    my $realcipher = self.getTargetStringFromOracle($prefix);
    my $len = $testlength + $decryptedString.bytes;
    for (0..127).map: { Buf.new($_) } {
      my $result = self.getTargetStringFromOracle($prefix ~ $decryptedString ~ $_);
      # $result = self.getTargetStringFromOracle($prefix ~ $decryptedString ~ $_, True) if $testlength == 0;
      #  say $_ if $result[0..$len].List eqv $realcipher[0..$len].List;
      return $_ if $result[0..$len].List eqv $realcipher[0..$len].List;
    }
    say $testlength;
    Buf.new;
  }

  multi method getTargetStringFromOracle(Buf $input, Bool $debug) {
    my $attack = asciiToBuf("B" x ($BLOCKSIZE));
    my $ciphertext = $!oracle.encrypt($attack);
    my $index = detectRepeatingBytes($ciphertext);
    my $count = 0;
    while $index == 0 {
      $count++;
      $attack.push: "B".ord;
      $ciphertext = $!oracle.encrypt($attack ~ $input);
      my $str = Buf.new($ciphertext[($index+1)*$BLOCKSIZE..*]);
      $index = detectRepeatingBytes($ciphertext);
    }
    my $str = Buf.new($ciphertext[($index+1)*$BLOCKSIZE..*]);
    say AES_ECB_decrypt($str, $!oracle.key).decode;
    #say AES_ECB_decrypt($str, $!oracle.key).decode;
    Buf.new($ciphertext[($index+1)*$BLOCKSIZE..*]);
  }

  multi method getTargetStringFromOracle(Buf $input) {
    my $attack = asciiToBuf("B" x ($BLOCKSIZE*2 + ($BLOCKSIZE - ($.prefixLength % $BLOCKSIZE))));
    my $ciphertext = $!oracle.encrypt($attack ~ $input);
    my $index = detectRepeatingBytes($ciphertext);
    my $str = Buf.new($ciphertext[($index+1)*$BLOCKSIZE..*]);
    #say AES_ECB_decrypt($str, $!oracle.key).decode;
    Buf.new($ciphertext[($index+1)*$BLOCKSIZE..*]);
  }


  multi method decrypt() {
    say $!oracle.noise.bytes;
    my Buf $decryptedString = Buf.new;
    my $encryptedSecret = self.getTargetStringFromOracle(Buf.new);
    for (1..$encryptedSecret.bytes) {
      my $result = self.decryptByte($decryptedString);
      $decryptedString.push: $result if $result.defined;
      say $decryptedString;
      say $decryptedString.decode;
    }
    $decryptedString;
  }
}

sub detectRepeatingBytes(Buf $input) {
  my $prev = $input.rotor($BLOCKSIZE)[0];
  my $idx = 1;
  for $input.rotor($BLOCKSIZE)[1..*] {
    return $idx if $_ eqv $prev;
    $prev = $_;
    $idx++;
  }
  0;
}

our sub generateAESKey() {
  my Buf $key = Buf.new;
  for 1..$BLOCKSIZE {
    $key.push: 256.rand.Int;
  }
  $key;
}

sub MAIN() {
  my $oracle = RandomStringOracle.new();
  say $oracle.encrypt(asciiToBuf("123"));
  say "Secret:{$oracle.secret.bytes}";
  say "Noise:{$oracle.noise.bytes}";
  say detectRepeatingBytes(asciiToBuf("A" x 16 ~ "x" x 32));
  say "--";
  my $solver = AES_ECB_Solver.new(oracle => $oracle);
  say "Prefix:{$solver.getPrefixLength}";
  say $solver.decrypt;
  # $oracle.getBlockLength();
  # say $oracle.decryptUnknownString().decode;
  
}
