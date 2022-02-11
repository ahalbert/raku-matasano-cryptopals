use S1C8;
use S1C1;
use AES;

my $BLOCKSIZE = 16;


our sub encrypt_AES_CBC (Buf $plaintext, Buf $key, Buf $iv) {
  my $context_block = $iv;
  my Buf $ciphertext = Buf.new();
  for $plaintext.rotor($BLOCKSIZE, :partial).map: { Buf.new($_)} {
    my $block_to_encrypt = $context_block ~^ $_;
    my $encrypted_block = AES_ECB_Encrypt($block_to_encrypt, $key);
    $context_block = $encrypted_block;
    $ciphertext.push: $encrypted_block;
  }
  $ciphertext;
}

our sub generateAESKey() {
  my Buf $key = Buf.new();
  for 1..$BLOCKSIZE {
    $key.push: 256.rand.Int;
  }
  $key;
}

our sub randomAESEncrypt(Buf $plaintext is copy) {
  my $key = generateAESKey();
  my $iv = generateAESKey();
  my $frontpadding = generateAESKey();
  my $backpadding = generateAESKey();
  $plaintext = $plaintext.unshift: $frontpadding;
  $plaintext = $plaintext.push: $backpadding;
  return encrypt_AES_CBC($plaintext, $key, $iv) if Bool.pick;
  return AES_ECB_Encrypt($plaintext, $key);
}

sub MAIN() {
  for "8.txt".IO.lines {
    my $ciphertext = randomAESEncrypt(hexStrToBuf($_));
    say $ciphertext if detectECBEncryption($ciphertext);
  }
}
