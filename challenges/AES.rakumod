use S2C9;
use Inline::Python;
my $py = Inline::Python.new();
$py.run('import AES');
#

our sub AES_ECB_decrypt(Buf $ciphertext, Buf $key) {
  $py.call('AES', 'decrypt_aes_128_ecb', $ciphertext, $key);
}

our sub AES_ECB_Encrypt(Buf $plaintext, $key) {
  $py.call('AES', 'encrypt_aes_128_ecb', pkcs7pad($plaintext, 16), $key);
}
