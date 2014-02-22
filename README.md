# TestableSecurity
This is a small proof-of-concept that lifts out the [vulnerable SSLVerifySignedServerKeyExchange()](http://support.apple.com/kb/HT6147) from Apple's libsecurity_ssl to demonstrate that the signing code is readily unit testable in isolation.

While there's been some talk that this bug wasn't easily tested, the code in question verifies signatures based on straight-forward preconditions, and is readily testable for both positive and negative validation cases; there's no reason or excuse for it not being fully tested for:

* Incorrect clientRandom.
* Incorrect serverRandom.
* Incorrect signedParams
* Incorrect signature (which is essentially equivalent to any of the above)

Try running the unit tests yourself, and then simply comment out the errant 'goto' to see the tests pass:

    if ((err = SSLHashSHA1.update(&hashCtx, &signedParams)) != 0)
        goto fail;
    // goto fail;
