use S1C5;

our sub pkcs7pad(Buf $s, Int $blocksize) {
  return $s if $s.bytes == $blocksize;
  my $padlength = $blocksize - ($s.bytes % $blocksize);
  my @pad = $padlength xx $padlength;
  $s.push(|@pad);
}

sub MAIN () {
  say pkcs7pad(asciiToBuf("YELLOW SUBMARINE"), 20);
}
