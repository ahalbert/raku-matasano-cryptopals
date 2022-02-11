use S1C5;
use S1C3;
use Base64;

sub repeatingKeyXORSolver(Buf $ciphertext) {
  my %keysizes = getCandidateKeySizes($ciphertext);
  my @bestSolutionForKeySize;
  for %keysizes.sort(*.value) { 
    my @transposedCiphertext = transposeCiphertext($ciphertext, $_.key.Int);
    my @solvedBlocks;
    for @transposedCiphertext {
      @solvedBlocks.push: singleByteXORSolver($_)<key>;
    }
    my Str $bestKey = @solvedBlocks.join;
    my $plaintext = repeatingKeyXOR($ciphertext, asciiToBuf($bestKey));
    my $score = scoreEnglishFrequency($plaintext);
    my %hash = len => $_.key, key => $bestKey, solution => $plaintext, score => $score;
    @bestSolutionForKeySize.push: %hash;
  }
  @bestSolutionForKeySize = @bestSolutionForKeySize.sort: {.<score>};
  @bestSolutionForKeySize[*-1];
}


sub getCandidateKeySizes(Buf $ciphertext) returns Hash {
  my @ciphertextBits = $ciphertext.List;
  my %keysizes;
  for 2..40 -> $keysize {
    last if @ciphertextBits.elems < $keysize*4;
    #TODO How to reduce;
    #say @ciphertextBits[0..$keysize-1].reduce(&infix:<~>);
    my $first =  Buf.new($ciphertext[0..$keysize-1]);
    my $second =  Buf.new($ciphertext[$keysize..2*$keysize-1]);
    my $third =  Buf.new($ciphertext[2*$keysize..3*$keysize-1]);
    my $fourth = Buf.new($ciphertext[3*$keysize..4*$keysize-1]);
    my $average = (hammingDistance($first, $second) + hammingDistance($first, $third) + hammingDistance($first, $fourth) + hammingDistance($second, $third) + hammingDistance($second, $fourth) + hammingDistance($third, $fourth))/6.0;
    %keysizes{$keysize} = $average/$keysize;
  }
  %keysizes;
}

sub transposeCiphertext (Buf $ciphertext, Int $keysize) {
  my @ciphertextBits = $ciphertext;
  my @result;
  for 0..$keysize-1 {
      @result.push: Buf.new($ciphertext[$_, $_+$keysize ... *]);
  }
  @result;
}


sub hammingDistance(Buf $a, Buf $b) {
  my @left = $a.List.map:{ leftpad($_.Int.base(2).Str, "0", 8); };
  my @right = $b.List.map:{ leftpad($_.Int.base(2).Str, "0", 8); };
  my $distance = 0;
  for zip(@left, @right) -> $byte {
    for zip($byte[0].comb, $byte[1].comb) -> $bit {
      $distance++ if $bit[0] ne $bit[1];
    }
  }
  $distance;
}

sub leftpad(Str $val is copy, Str $pad, Int $len) is export {
  until $val.chars >= $len {
    $val = $pad ~ $val;
  }
  return $val;
}

sub MAIN () {
  say hammingDistance(asciiToBuf("this is a test"), asciiToBuf("wokka wokka!!!"));
  my %hash  = repeatingKeyXORSolver(decode-base64("6.txt".IO.slurp, :bin));
  dd %hash;
}
