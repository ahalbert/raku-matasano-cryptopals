use Inline::Python;
use Base64;
use S1C1;
use S1C5;
use S2C9;

#No module for raku. We're using python
my $py = Inline::Python.new();
$py.run('import AES');
# my $encrypted_block = $py.call('AES', 'encrypt_aes_128_ecb', $block_to_encrypt, $key);
# my $decrypted_block =  $py.call('AES', 'decrypt_aes_128_ecb', $_, $key);

my $BLOCKSIZE=16;


our sub encrypt_AES_CBC (Buf $plaintext, Buf $key, Buf $iv) {
  my $context_block = $iv;
  my Buf $ciphertext = Buf.new();
  # for $plaintext.rotor($BLOCKSIZE, :partial).map: { pkcs7pad(Buf.new($_), $BLOCKSIZE)} {
  for $plaintext.rotor($BLOCKSIZE, :partial).map: { Buf.new($_)} {
    my $block_to_encrypt = $context_block ~^ $_;
    my $encrypted_block = $py.call('AES', 'encrypt_aes_128_ecb', $block_to_encrypt, $key);
    $context_block = $encrypted_block;
    $ciphertext.push: $encrypted_block;
  }
  $ciphertext;
}

our sub decrypt_AES_CBC (Buf $ciphertext, Buf $key, Buf $iv) {
  my $context_block = $iv;
  my Buf $plaintext = Buf.new();
  # for $ciphertext.rotor($BLOCKSIZE, :partial).map: { pkcs7pad(Buf.new($_), $BLOCKSIZE)} {
  for $ciphertext.rotor($BLOCKSIZE, :partial).map: { Buf.new($_)} {
    my $decrypted_block =  $py.call('AES', 'decrypt_aes_128_ecb', $_, $key);
    $decrypted_block = $context_block ~^ $decrypted_block;
    $context_block = $_;
    $plaintext.push: $decrypted_block;
  }
  $plaintext;
}

sub MAIN () {
  my $x = decode-base64("7.txt".IO.slurp, :bin);
  $x = $py.call('AES','encrypt_aes_128_ecb', $x, asciiToBuf("YELLOW SUBMARINE"));
  $x = $py.call('AES', 'decrypt_aes_128_ecb', $x, asciiToBuf("YELLOW SUBMARINE"));
  $x = $py.call('AES', 'decrypt_aes_128_ecb', $x, asciiToBuf("YELLOW SUBMARINE"));
  say $x.decode;
  say $x;
  #-----
  $x = encrypt_AES_CBC($x, asciiToBuf("YELLOW SUBMARINE"), Buf.new(0 xx 16));
  say $x;
  $x = decrypt_AES_CBC($x, asciiToBuf("YELLOW SUBMARINE"), Buf.new(0 xx 16));
  say $x;
  $x = decode-base64("10.txt".IO.slurp, :bin);
  say decrypt_AES_CBC($x, asciiToBuf("YELLOW SUBMARINE"), Buf.new(0 xx 16)).decode();
}
