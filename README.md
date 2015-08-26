A very simple example of a Private Set Intersection (PSI) protocol that is usable to compare your interests privately.
Built on [NaCL](http://nacl.cr.yp.to/), using SHA256 hashing and curve 25519 to implement the Diffie-Hellman based PSI protocol on elliptic curves.

The protocol is explained in [this paper](http://www.cs.cornell.edu/aevf/research/sigmod_2003.pdf).

Building
========
    gcc -o poc poc.c -L $NACLDIR/build/token/lib/amd64/ -I $NACLDIR/build/token/include/amd64/ $NACLDIR/randombytes/devurandom.c -lnacl && ./poc
