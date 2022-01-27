use Base64;

our sub hexStrToBuf(Str $hex) { Buf.new($hex.comb(2).map: {"0x$_".Int;}); }

sub MAIN() {
say encode-base64(hexStrToBuf("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")).join;
}
