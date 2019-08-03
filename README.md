# Occlude

This is intended to be a lightweight C++ TLS 1.3 library with a modern C++ interface.

* Value semantics
* Views
* Ranges

# Plan

The first goal is: to get an outgoing connection working with cipher suite 0x1301, TLS13-AES-128-GCM-SHA256, without verification to start with.
This requires:
* AES-128
* SHA-256
* Elliptic Curve encrypt/decrypt (P256, Ed25519)
* GCM's GHASH
* ECDHE
* Sign/Verify
* GCM
* TLS 1.3 packet parser
