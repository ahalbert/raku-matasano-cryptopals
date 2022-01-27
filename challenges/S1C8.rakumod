use S1C1;

our sub hasRepeatedBlocks(Buf $ciphertext) {
  my $blocksize  = 16; #128 bits = 16 bytes
  my $block_count = ($ciphertext.bytes / $blocksize).floor - 1;
  my @blocklist = (0..$block_count).map: {$ciphertext[$_*$blocksize..(($_+1)*$blocksize)-1] }
  for @blocklist.combinations(2) { if $_[0] eqv $_[1] { return True; }}
  False;
}

our sub detectECBEncryption(Buf $ciphertext) {
  return True if hasRepeatedBlocks($ciphertext);
  False;
}


sub MAIN () {
  # "".IO.lines.map: { detectECBEncryption};
  for "8.txt".IO.lines {
    say $_ if detectECBEncryption(hexStrToBuf($_));
  }
}
