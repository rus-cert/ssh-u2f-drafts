%%%
ipr = "trust200902"
category = "std"
docName = "draft-josefsson-secsh-u2f-00"
abbrev = "U2F Authentication for SSH"
title = "Universal 2nd Factor (U2F) Authentication for Secure Shell (SSH)"

[[author]]
initials = "M."
surname = "Stapelberg"
fullname = "Michael Stapelberg"
[author.address]
email = "michael+mindrot@stapelberg.de"

[[author]]
initials="S."
surname="Bühler"
fullname="Stefan Bühler"
[author.address]
email = "stbuehler@web.de"
%%%

.# Abstract

Universal 2nd Factor is an authentication factor intended to strengthen
other authentication mechanisms.  This document describes how U2F can be
used to strengthen Secure Shell authentication mechanisms.

{mainmatter}

# Introduction

Universal 2nd Factor (U2F) [@U2F-Overview] is an authentication factor
intended to strengthen other authentication mechanisms.  This document
describe how U2F can be used to strengthen Secure Shell authentication
(SSH) [@RFC4251] mechanisms.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
[@!RFC2119].

The reader is assumed to be familiar with the U2F and SSH terminology.

# U2F facetID and appID {#facetAndAppID}

The facetID (also known as origin) is build from hostname and port; the
port is only included if it is not the standard port (22).

F> ~~~abnf2616
F> reg-name  = <reg-name, defined in [RFC3986], Section 3.2.2>
F> host      = <host, defined in [RFC3986], Section 3.2.2>
F> port      = <port, defined in [RFC3986], Section 3.2.3>
F> userinfo  = <userinfo, defined in [RFC3986], Section 3.2.3>
F> facetId   = "ssh://" userinfo "@" host [ ":" port ]
F> ~~~

The appID has similar syntax, but also allows wildcards:

F> ~~~abnf2616
F> appIdExact = "ssh://" [ userinfo "@" ]      host     [ ":" port ]
F> appIdAll   = "ssh://" [ userinfo "@" ] "."  reg-name [ ":" port ]
F> appIdSub   = "ssh://" [ userinfo "@" ] "*." reg-name [ ":" port ]
F> appId      = appIdExact / appIdAll / appIdSub
F> ~~~

A `facetId` matches an `appId` if the `appId` doesn't contain `userinfo`
or the `userinfo` matches exactly, and:
- the `appId` is an `appIdExact` and they are equal by simple string
  comparison
- or the `appId` is an `appIdAll`, the ports are equal and `reg-name` is
  either the same as `host` or `"." reg-name` is a suffix of `host`.
- or the `appId` is an `appIdSub`, the ports are equal `"." reg-name` is a
  suffix of `host`.

# U2F Authentication public key {#key}

The "ssh-u2f" public key represents the server side registration object
which will usually be stored in an `authorized_keys` file.

It consists of:

F> ~~~artwork
F> string    "ssh-u2f"
F> string    keyHandle
F> string    appId
F> string    u2f_version
F> string    public key blob (contents u2f_version specific)
F> ~~~

TBD: Define IANA registry for U2F version names. Each version needs to
define the contents of the public key blob.

# U2F version "U2F_V2"

The content of the public key blob encodes an ECDSA key over P-256 as an
uncompressed x,y-representation of a curve point and is 65 bytes long:

F> ~~~artwork
F> byte      point_format 0x04 (uncompressed)
F> byte[32]  x
F> byte[32]  y
F> ~~~

This is the same format as is used in the raw protocol.

# U2F Authentication Method: "u2f-register"

Registration leads to creation of a new public key which needs to be
stored on the server some other way.  The server usually only provides
basic sanity checks, and might refuse cooperation.

If an implementation decides to trust a U2F factor on first use the
authentication method can succeed.  Otherwise it MUST fail, but MUST
signal successful registration by setting `partial success` to true.

## Exchanged messages

This section is modeled after the authentication methods described in
[@!RFC4252].

When the client starts the U2F authentication it sends:

F> ~~~artwork
F> byte      SSH_MSG_USERAUTH_U2F_REGISTER_INIT
F> string    user name in ISO-10646 UTF-8 encoding [RFC3629]
F> string    service name in US-ASCII
F> string    method name "u2f-register"
F> string    register appId
F> ~~~

The server can reject a specific appId or registration in general for a
specific user by responding with a SSH_MSG_USERAUTH_FAILURE message
instead (partial success MUST be false in this case).

Otherwise the server MUST reply with:

F> ~~~artwork
F> byte      SSH_MSG_USERAUTH_U2F_REGISTER_REQUEST
F> byte[16]  random value
F> uint32    RegisterRequestsNumber N
F> string[N] RegisterRequests (each as serialized JSON)
F> ~~~

Each entry in `RegisterRequests` represents a "RegisterRequest" object
as specified in section 4.1.1 of [@!U2F-JavaScript].  The value for the
"appId" (application id) field MUST be copied from `register appId` in
the SSH_MSG_USERAUTH_REQUEST message.  The "challenge" field MUST be the
SHA2-256 checksum of the concatentation of the `random value` and the
session identifier.

The client MUST check the "appId" and the "challenge" field values.

A server can send multiple "RegisterRequest" objects to support
different U2F protocol versions.

The client sends a "RegisterRequest" and the locally determined origin
(facetId) to U2F tokens.  The client can pick any order of requests to
try, but it can send only one response.

If the client cannot (or doesn't want to) respond to any of the register
requests it MUST disconnect the connection with
`SSH_DISCONNECT_AUTH_CANCELLED_BY_USER`.

Otherwise it sends the "RegisterResponse" (see section 4.1.2 of
[@!U2F-JavaScript]):

F> ~~~artwork
F> byte      SSH_MSG_USERAUTH_U2F_REGISTER_RESPONSE
F> string    RegisterResponse (serialized JSON)
F> ~~~

Once the server verified the "RegisterResponse" signed the original
challenge, it extracts the user’s U2F public key and sends back a public
key which the user should add to her authorized_keys file on the server
via other means.

A> The server SHOULD also check whether the "origin" facetId matches the
A> "appId" according to the rules in (#facetAndAppID).

F> ~~~artwork
F> byte      SSH_MSG_USERAUTH_U2F_REGISTER_RESULT
F> string    key type "ssh-u2f"
F> string    public key
F> ~~~

Key type MUST be "ssh-u2f".

The server MUST send a SSH_MSG_USERAUTH_SUCCESS or
SSH_MSG_USERAUTH_FAILURE to finish the registration.

# U2F Authentication Method: "u2f"

This section is modeled after the authentication methods described in
[@!RFC4252].

A> Registration leads to creation of a new public key which needs to be
A> stored on the server some other way.  The server usually only provides
A> basic sanity checks, and might refuse cooperation.

When the client starts the U2F authentication, it sends:

F> ~~~artwork
F> byte      SSH_MSG_USERAUTH_U2F_INIT
F> string    user name in ISO-10646 UTF-8 encoding [RFC3629]
F> string    service name in US-ASCII
F> string    method name "u2f"
F> string    origin
F> ~~~

The server replies with:

F> ~~~artwork
F> byte      SSH_MSG_USERAUTH_U2F_REQUEST
F> byte[16]  random value
F> uint32    SignRequestsNumber N
F> string[N] SignRequests (each as serialized JSON)
F> ~~~

The server MUST only send "SignRequest"s with an appId matched by
`origin` according to the rules in (#facetAndAppID).  The list may be
empty if there is no such public key.

The challenge in each SignRequest MUST be the SHA2-256 checksum of the
concatentation of the `random value` and the session identifier.

The client MUST ignore any SignRequest if the origin doesn't match the
appId according to the rules in (#facetAndAppID) or the challenge isn't
the expected value.

The client will try to get a response for one of the requests and
returns the response with:

F> ~~~artwork
F> byte      SSH_MSG_USERAUTH_U2F_RESPONSE
F> string    SignResponse (serialized JSON)
F> ~~~

The authentication is successful if the server successfully verifies the
signature on the "SignResponse" (see section 4.2.2 of
[@!U2F-JavaScript]) with a trusted public key.

A> The server SHOULD also check whether the "origin" facetId matches the
A> "appId" according to the rules in (#facetAndAppID).

# Registration possibilities outside the scope of this document

The client doesn't actually need the server to create the public key.

By using the registration protocol defined in this document a server
might perform additional checks.

A server might store registrations server side too (and might also
verify the Attestation certificate against a chosen set).  When the user
then tries to "activate" the registration through some other channel
(web interface, user support, ...), the server can check whether the
registration was done using the protocol defined in this document.

Also Trust on First Registration can be implemented on the server when
users are migrated to Two Factor Authentication.

# Acknowledgments

TBA

# Security Considerations

TBA

# IANA Considerations

## Authentication Method Names and Messages

The userauth types "u2f-register" and "u2f" are used for this
authentication method.

The following method-specific constants are used with the authentication
method "u2f-register":

F> ~~~artwork
F> SSH_MSG_USERAUTH_U2F_REGISTER_INIT      60
F> SSH_MSG_USERAUTH_U2F_REGISTER_REQUEST   61
F> SSH_MSG_USERAUTH_U2F_REGISTER_RESPONSE  62
F> SSH_MSG_USERAUTH_U2F_REGISTER_RESULT    63
F> ~~~

The following method-specific constants are used with the authentication
method "u2f":

F> ~~~artwork
F> SSH_MSG_USERAUTH_U2F_INIT               60
F> SSH_MSG_USERAUTH_U2F_REQUEST            61
F> SSH_MSG_USERAUTH_U2F_RESPONSE           62
F> ~~~

## Public Key Algorithm Name

The "ssh-u2f" public key algorithm is used for the key type described in
section #key.

<reference anchor="U2F-JavaScript" target="http://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-javascript-api-ps-20141009.html">
    <front>
        <title>FIDO U2F Javascript API</title>
        <author initials="D." surname="Balfanz" fullname="Dirk Balfanz"/>
        <author initials="A." surname="Birgisson" fullname="Arnar Birgisson"/>
        <author initials="J." surname="Lang" fullname="Juan Lang"/>
        <date month="October" year="2014" />
    </front>
</reference>

<reference anchor="U2F-Overview" target="http://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-overview-ps-20141009.html">
    <front>
        <title>Universal 2nd Factor (U2F) Overview</title>
        <author initials="S." surname="Srinivas" fullname="Sampath Srinivas"/>
        <author initials="D." surname="Balfanz" fullname="Dirk Balfanz"/>
        <author initials="E." surname="Tiffany" fullname="Eric Tiffany"/>
        <date month="October" year="2014" />
    </front>
</reference>

{backmatter}
