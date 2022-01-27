use S1C1;
use S1C3;

sub MAIN () {
  my @solns = ("4.txt".IO.lines.map: { singleByteXORSolver(Buf[uint8].new(hexStrToBuf($_))) }).sort: {.<score>}
  say @solns[*-1];
}
