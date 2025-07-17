// See https://aka.ms/new-console-template for more information

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

const string privateKeyDer = "MC4CAQAwBQYDK2VwBCIEIIYGTpWE+vd2n2zN4GV0uNE8wXtVn0GhuHQwWegoZfc1";
var privKey = (Ed25519PrivateKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKeyDer));

var v = new Asn1EncodableVector
{
    new DerInteger(0),
    new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
    new DerOctetString(new DerOctetString(privKey.GetEncoded()))
};

var pkcs8Seq = new DerSequence(v);
var actual = Convert.ToBase64String(pkcs8Seq.GetDerEncoded());
Console.WriteLine(actual == privateKeyDer);