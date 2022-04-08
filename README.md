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
var address = key.GetAddress();

Assert.Equal("cb82a5fd22b9bee8b8ab877c86e0a2c21765e1d5bfc5",address);

//getting the public key bytes
var publicKey = key.GetPublicKey();

//getting the public key hex
var publicKeyHex = publicKey.ToHex();

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

## Usage of Usage of Hierarchical Deterministic Wallet (HD-Wallet)
``` C#
// suppose you have an master extended private key
var masterExtPrivateKey = (ExtendedPrivateKey)"004e843c2991930124e5a0711c6a8be763f5b605ee80f089dfa9cbec5ebb20123dcc787b162a7baf37b0251f6bdd4ac14ae111491ef391cf0d1413821ed67083c855c6db4405dd4fa5fdec39e1c761be1415623c1c202c5cb5176e578830372b7e07eb1ef9cf71b19518815c4da0fd2d3594"
.FromHexToByteArray();

// you can also generate a new random master extended private key
var masterExtPrivateKey = ExtendedPrivateKey.GenerateRandomMaster();

// or generate a deterministic master extended private key using a seed
var seed = byte[64];
var masterExtPrivateKey = ExtendedPrivateKey.SeedToMaster(seed);

// with an master extended private key you are able to create an private hd wallet
// "m/84'/0'/0'" is the derivation path
var privateWallet = new HDWallet.PrivateWallet(masterExtPrivateKey, "m/84'/0'/0'");

// you can derive a child private key
// this private key derivation path will be "m/84'/0'/0'/20'"
var derivedPrivateKey = privateWallet.GetPrivateKey(20);

// this private key derivation path will be "m/84'/0'/0'/14'/36'/15'"
var derivedPrivateKey = privateWallet.GetPrivateKey(14,36,15);

//you can also get public key or address from private hd wallet
// this public key derivation path will be "m/84'/0'/0'/14'/36'/15'"
var derivedPublicKey = privateWallet.GetPublicKey(14,36,15);

var networkId = 1;
// this address derivation path will be "m/84'/0'/0'/14'/36'/15'"
var derivedAddress = privateWallet.GetAddress(networkId, 14, 36, 15)


// you can also have public hd wallet, which they only have access to public key and address not private keys
// mostly they are used for watch-only wallets

// for creating a public hd wallet you need to have a master extended public key
// simply you can generate it from a master extended private key
var masterExtPublicKey = masterExtPrivateKey.ToExtendedPublicKey();

// with a master public key and a derivation path you can create a public hd wallet
var publicWallet = new PublicWallet(masterPublicKey, "m/84'/0'/0'");

// same as private hd wallet you can derive public keyes or addresses at any derivation path after "m/84'/0'/0'"
// this public key derivation path will be "m/84'/0'/0'/14'/36'/15'"
var derivedPublicKey = publicWallet.GetPublicKey(14, 36, 15);

var networkId = 1;
// this address derivation path will be "m/84'/0'/0'/14'/36'/15'"
var derivedAddress = publicWallet.GetAddress(networkId, 14, 36, 15)

// public hd wallets cannot derive private keys

```
Notice: if you create public/private hd wallet from a pair of `master extended keys`
they will be associated with each other, which means a private key derived at `m/0'/0'/0'/8'` can sign a message
which a public key derived from public hd wallet at `m/0'/0'/0'/8'` can verify it.

## License

[CORE License](LICENSE)
