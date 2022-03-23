# Xcb.Net

This is a client library of core-coin blockchain in .Net for managing Private/Public keys, creating and signing transactions of the blockchain.

## Usage of keys

```C#
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

//"hello" in hex is "0x666f6f"
var message = "666f6f"

//signing the message (it will prehash the message with SHA3NIST)
var signatureBytes = key.SignHashOfMessage(message.HexToByteArray());

//public key can be recovered from the signature
var recoveredPublicKey = XcbECKey.GetPublicKeyFromSignature(signatureBytes).ToHex();

Assert.Equal(publicKey.ToHex(),recoveredPublicKey);

//wallet address can be recovered from public key
var recoveredAddress = XcbECKey.GetAddressFromPublicKey(publicKey,networkId);

Assert.Equal(address, recoveredAddress);

```

## Usage of transactions

```C#
var networkId = 11;

// creating the XcbECKey with the provided private-key
XcbECKey key = new XcbECKey("69bb68c3a00a0cd9cbf2cab316476228c758329bbfe0b1759e8634694a9497afea05bcbf24e2aa0627eac4240484bb71de646a9296872a3c0e", networkId);

// creating a simple transaction
// the destination address (the fund receiver) is ce276773ac97d16855a3c8faa45399136b56d4194860
// the fund amount which will be sent is 200 units
// nonce is zero (this is the first transaction from this private key)
Transaction transaction = new Transaction(to: "ce276773ac97d16855a3c8faa45399136b56d4194860",
amount: BigInteger.Parse("200"),
nonce: BigInteger.Parse("0"),
energyLimit: BigInteger.Parse("999999"),
energyPrice: BigInteger.Parse("10"),
data: "");

//When

// signing the transaction with XcbECKey
transaction.Sign(key, 0);

// getting the rlp encoding of the signed trasnaction
var encoded = transaction.GetRlpEncoding();

// getting the hex of the encoded data
var encodedHex = encoded.ToHex(true);

// parse a transaction from encoded data
var transaction2 = Transaction.Decode(encoded);

// re-encode the transaction
var reEncode = transaction2.GetRlpEncoding();

//Then

// assert checking if everything is fine
Assert.Equal(encoded, reEncode);
Assert.Equal("0xf8ce800a830f423f8096ce276773ac97d16855a3c8faa45399136b56d419486081c880b8ab448eafc4ad76f52262dc04c09738e017dbf7dac5cee6d7bf0a8c0b60aaa1403d10e3d3a28f2d0ce9a9ffb64ebb9e0a59a3637f0f48aa597f80722d2c29acab15b7e2677f3df91ea86ecbb0f6cc871fdf39a154262ed467ae6e2996cdc09dbce205c318b7581d28bae84c0eb3d118edf61000315484db568379ce94f9c894e3e6e4c7ee216676b713ca892d9b26746ae902a772e217a6a8bb493ce2bb313cf0cb66e76765d4c45ec6b68600",
    encodedHex);

```

## License

[CORE License](LICENSE)
