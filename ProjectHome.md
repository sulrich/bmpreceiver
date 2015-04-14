bmpreceiver is a receiver-side implementation of the BMP in the Python language. It serves as a reference for how to step through the messages and print their contents. Many of the corner cases of BGP UPDATE processing, especially where L3 VPNs are concerned, are incomplete, but the implementation does its best to parse past them and continue processing.

This implementation covers draft-ietf-grow-bmp-02.txt and draft-ietf-grow-bmp-07.txt; in other words, BMP versions 1 and 3.

The current draft is draft-ietf-grow-bmp-07.txt.

RFCs to read to help you understand the code better (see the README for a more complete list):
  * RFC1863 - A BGP/IDRP Route Server alternative to a full mesh routing
  * RFC1997 - BGP Communities Attribute
  * RFC2042 - Registering New BGP Attribute Types
  * RFC2858 - Multiprotocol Extensions for BGP-4
  * RFC4271 - A Border Gateway Protocol 4 (BGP-4)
  * RFC4893 - BGP Support for Four-octet AS Number Space