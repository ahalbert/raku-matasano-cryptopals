use S1C1;
use S1C3;

our sub repeatingKeyXOR(Buf $ciphertext, Buf $key) {
  my $repeatingkey = Buf.new(cycle($key.rotor(1))[^$ciphertext.bytes].flat);
  $ciphertext ~^ $repeatingkey;
}

sub cycle(@elements) {
    die "elements must be a list" unless @elements;
    gather {
        while True {
            take $_ for @elements; 
        }
    }
}

our sub asciiToBuf(Str $text) {
  Buf.new($text.ords);
}

sub MAIN () {
  say repeatingKeyXOR(asciiToBuf("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), Buf.new("ICE".ords));
}
