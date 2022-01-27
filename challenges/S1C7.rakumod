use Inline::Python;
use Base64;
use S1C1;
use S1C5;


#No module for raku. We're using python
my $py = Inline::Python.new();
$py.run('import S1C7');

our sub AES_ECB_Encrypt(Buf $text, Buf $key) {
  $py.call('S1C7', 'decrypt_aes_128_ecb', $text, $key);
}

our sub AES_ECB_decrypt(Buf $text, Buf $key) {
  $py.call('S1C7', 'aes_ecb_encrypt', $text, $key);
}

sub MAIN() {
  say $py.call('S1C7', 'decrypt_aes_128_ecb', decode-base64("7.txt".IO.slurp, :bin), asciiToBuf("YELLOW SUBMARINE")).decode();
}
