use AES;
use S1C5;
use S1C7;
use S2C9;

my $BLOCKSIZE = 16;

our sub generateAESKey() {
  Buf.new((1..$BLOCKSIZE).map:  { 256.rand.Int; });
}

my $key = generateAESKey();

sub encryptProfile(Str $email) {
  AES_ECB_Encrypt(asciiToBuf(profileFor($email)), $key);
}

sub decryptProfile(Buf $ciphertext) {
  parsekv(AES_ECB_Decrypt($ciphertext, $key).decode);
}

sub parsekv(Str $input) {
  ($_[0] => $_[1] for $input.split("&").map: { $_.split('=') });
}

sub encodekv(Hash $input) {
  $input.sort(*.key).pairs.map({"{$_.value.key}={$_.value.value}"}).join("&") ;
}

sub profileFor(Str $email) {
  "email=$email&uid=10&role=user"
  #encodekv({ email => $email, uid => 10, role => "user" });
}

sub cutAndPasteattackECB() {
  my Int $prefix = $BLOCKSIZE - "email=".chars;
  my Str $attack = ("x" x $prefix ) ~ (pkcs7pad(asciiToBuf("admin"), $BLOCKSIZE).decode);
  my Buf $block1 = encryptProfile('thirteen@.com');
  my Buf $block2 = encryptProfile($attack);
  return decryptProfile(Buf.new($block1[0..^32]) ~ Buf.new($block2[16..^32]));
}

sub MAIN() {
  say parsekv("foo=bar&baz=qux&zap=zazzle");
  my $text = profileFor("foo@bar.com");
  say $text;
  my $ciphertext = encryptProfile("foo@bar.com");
  say $ciphertext;
  say decryptProfile($ciphertext);
  say cutAndPasteattackECB();
}
