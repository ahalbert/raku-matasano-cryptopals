use S1C1;

my %CHARACTER_FREQ = 'a' => 0.0651738, 'b' => 0.0124248, 'c' => 0.0217339, 'd' => 0.0349835, 'e' => 0.1041442, 'f' => 0.0197881, 'g' => 0.0158610, 
'h' => 0.0492888, 'i' => 0.0558094, 'j' => 0.0009033, 'k' => 0.0050529, 'l' => 0.0331490, 'm' => 0.0202124, 'n' => 0.0564513,
'o' => 0.0596302, 'p' => 0.0137645, 'q' => 0.0008606, 'r' => 0.0497563, 's' => 0.0515760, 't' => 0.0729357, 'u' => 0.0225134,
'v' => 0.0082903, 'w' => 0.0171272, 'x' => 0.0013692, 'y' => 0.0145984, 'z' => 0.0007836, ' ' => 0.1918182,
'A' => 0.0651738, 'B' => 0.0124248, 'C' => 0.0217339, 'D' => 0.0349835, 'E' => 0.1041442, 'F' => 0.0197881, 'G' => 0.0158610, 
'H' => 0.0492888, 'I' => 0.0558094, 'J' => 0.0009033, 'K' => 0.0050529, 'L' => 0.0331490, 'M' => 0.0202124, 'N' => 0.0564513,
'O' => 0.0596302, 'P' => 0.0137645, 'Q' => 0.0008606, 'R' => 0.0497563, 'S' => 0.0515760, 'T' => 0.0729357, 'U' => 0.0225134,
'V' => 0.0082903, 'W' => 0.0171272, 'X' => 0.0013692, 'Y' => 0.0145984, 'Z' => 0.0007836;

our sub singleByteXORSolver(Buf $ciphertext) { 
  my @solutions;
  for 1..127 {
      my $operand  = Buf[uint8].new($_ xx $ciphertext.bytes);
      my $solution = $ciphertext ~^ $operand;
      $solution = Buf.new($solution.rotor(1).flat.grep({ $_.Int < 127; }).flat); #Delete non ascii chars
      my $score = scoreEnglishFrequency($solution);
      my %hash = key => chr($_), solution => $solution.decode, score => $score;
      @solutions.push(%hash) ;
  }
  @solutions = @solutions.sort: {.<score>};
  @solutions[*-1];
}

sub scoreEnglishFrequency (Buf $text) is export {
  [+] $text.decode('ascii').comb.map: { 1*(%CHARACTER_FREQ{$_} || 0); };
}

sub MAIN() {
  say singleByteXORSolver(hexStrToBuf("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));
}
