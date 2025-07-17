using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace WebhookValidation;

public class WebhookValidator
{
    private readonly Ed25519PublicKeyParameters _publicKey;
    private readonly Ed25519PrivateKeyParameters? _privateKey;

    public WebhookValidator(string publicKeyDerBase64)
    {
        var decoded = Convert.FromBase64String(publicKeyDerBase64);
        _publicKey = (Ed25519PublicKeyParameters)PublicKeyFactory.CreateKey(decoded);
    }

    private WebhookValidator(Ed25519PrivateKeyParameters privateKey)
    {
        _privateKey = privateKey;
        _publicKey = privateKey.GeneratePublicKey();
    }

    public static WebhookValidator FromPrivateKeyDerBase64(string privateKeyDerBase64)
    {
        var decoded = Convert.FromBase64String(privateKeyDerBase64);
        var privateKey = (Ed25519PrivateKeyParameters)PrivateKeyFactory.CreateKey(decoded);
        return new WebhookValidator(privateKey);
    }

    public string PublicKey
    {
        get
        {
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_publicKey);
            return Convert.ToBase64String(spki.GetDerEncoded());
        }
    }

    public bool ValidateSignature(byte[] payload, byte[] signature)
    {
        var signer = SignerUtilities.GetSigner("Ed25519");
        signer.Init(false, _publicKey);
        signer.BlockUpdate(payload, 0, payload.Length);
        return signer.VerifySignature(signature);
    }

    public byte[] SignPayload(byte[] payload)
    {
        if (_privateKey == null)
        {
            throw new InvalidOperationException("Cannot generate a signature: no private key is available.");
        }

        var signer = SignerUtilities.GetSigner("Ed25519");
        signer.Init(true, _privateKey);
        signer.BlockUpdate(payload, 0, payload.Length);
        return signer.GenerateSignature();
    }
}