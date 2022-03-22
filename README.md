# Xcb.Net

This is a client library of core-coin blockchain in .Net for managing Private/Public keys, creating and signing transactions of the blockchain.

## Usage of keys

```
//can be byte array as well
var privateKey =
    "69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e";

var networkId = 1;

//import key from stored private key
var key = new XcbECKey(privateKey, networkId);

//generate new key randomely
var newKey = XcbECKey.GenerateKey(networkId);

//generate wallet address from the key
var address = key.GetAddressHex();

Assert.Equal("cb82a5fd22b9bee8b8ab877c86e0a2c21765e1d5bfc5",address);

//getting the public key bytes
var publicKey = key.GetPublicKeyBytes();

//getting the public key hex
var publicKey = key.GetPublicKeyHex();

//"hello" in hex without "0x" prefix
var message = "666f6f"

//signing the message (it will prehash the message with SHA3NIST)
var signatureBytes = key.SignHashOfMessage(message.HexToByteArray());

//public key can be recovered from the signature
var recoveredPublicKey = XcbECKey.GetPublicKeyFromSignature(signatureBytes).ToHex();

Assert.Equal(publicKey.ToHex(),recoveredPublicKey);
```

## License

[CORE License](LICENSE)
