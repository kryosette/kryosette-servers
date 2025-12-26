- The length of the Pad field required for MAC Client Data that is clientDatasize/8 octets long is 
max [0, minFrameSize – (clientDatasize + 2 addressSize + 48)] bits.

---

3.2.6 Length/Type field
This two-octet field takes one of two meanings, depending on its numeric value. For numerical evaluation,
the first octet is the most significant octet of this field.
a) If the value of this field is less than or equal to 1500 decimal (05DC hexadecimal), then the Length/
Type field indicates the number of MAC client data octets contained in the subsequent MAC Client
Data field of the basic frame (Length interpretation).
b) If the value of this field is greater than or equal to 1536 decimal (0600 hexadecimal), then the
Length/Type field indicates the EtherType of the MAC client protocol (Type interpretation).34
The Length and Type interpretations of this field are mutually exclusive.
When used as a Type field, it is the responsibility of the MAC client to ensure that the MAC client
operates properly when the MAC sublayer pads the supplied MAC Client data, as discussed in 3.2.7.
Regardless of the interpretation of the Length/Type field, if the length of the MAC Client Data field is less
than the minimum required for proper operation of the protocol, a Pad field (a sequence of octets) will be
added after the MAC Client Data field but prior to the FCS field, specified below. The procedure that
determines the size of the Pad field is specified in 4.2.8. The Length/Type field is transmitted and received
with the high order octet first.
NOTE—Clause 2 of IEEE Std 802 defines a set of EtherType values and associated mechanisms for use in prototype and
vendor-specific protocol development.

---

3.4 Invalid MAC frame
An invalid MAC frame shall be defined as one that meets at least one of the following conditions:
- The frame length is inconsistent with a length value specified in the length/type field. If the length/
type field contains a type value as defined by 3.2.6, then the frame length is assumed to be consistent
with this field and should not be considered an invalid frame on this basis.
- It is not an integral number of octets in length.
- The bits of the incoming frame (exclusive of the FCS field itself) do not generate a CRC value
identical to the one received.

The contents of invalid MAC frames shall not be passed to the LLC or MAC Control sublayers. Invalid
MAC frames may be ignored, discarded, or used in a private manner. The use of such frames by clients other
than LLC or MAC control is beyond the scope of this standard. The occurrence of invalid MAC frames may
be communicated to network management.