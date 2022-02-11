use S2C11;
use S2C15;
use S2C10;
use S2C9;
use S1C5;


my int $BLOCKSIZE = 16;
my @strings = "17.txt".IO.lines.List;

role Oracle {
  has Buf $.key;
  has Buf $.secret;
  has Int $.blocksize = 16;

  submethod BUILD() {
    $!key = generateAESKey();
  }

  multi method encrypt(Buf $plaintext) {}

  multi method decrypt(Buf $plaintext) {}
}

class RandomCBCOracle does Oracle {
  has Buf $.iv;

  submethod BUILD() {
    $!key = generateAESKey();
    $!iv = generateAESKey();
    $!secret = asciiToBuf(@strings.pick);
  }

  multi method encrypt() {
    encrypt_AES_CBC($!secret, $.key, $.iv);
  }

  multi method decrypt(Buf $ciphertext) {
    my $plaintext = decrypt_AES_CBC($ciphertext, $.key, $.iv);
    say $plaintext;
    given pkcs7unpad($plaintext) {
      when Buf { return True; } 
      when Bool { return False; } 
    } 
    die;
  }
}

sub breakCBCOracle(Oracle $oracle) {
  my Buf $solution = Buf.new();
  my $ciphertext = $oracle.encrypt();
  for 0..$ciphertext.bytes-1 {
  }
}

sub MAIN() {
  my $oracle = RandomCBCOracle.new();
  for "17.txt".IO.lines.List {
    $oracle.secret = asciiToBuf($_);
    pkcs7pad($oracle.secret, $BLOCKSIZE);
    my $ciphertext = $oracle.encrypt();
    say $oracle.decrypt($ciphertext);
  }
  my $ciphertext = $oracle.encrypt();
  # say $ciphertext;
  # say $oracle.decrypt($ciphertext);
  # $ciphertext[*-12] =0;
  # say $ciphertext;
  # say $oracle.decrypt($ciphertext);
}

