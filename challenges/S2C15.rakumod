use S2C9;
use S1C5;


sub pkcs7unpad(Buf $in) is export {
  my $padding = $in[*-1];
  my @subset = $in.reverse[0..$padding-1];
  return Buf.new($in[0..$in.bytes-$padding-1]) if @subset.List eqv ($padding xx $padding).List;
  False;
}

