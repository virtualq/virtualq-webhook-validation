using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace WebhookValidation;

public class WebhookValidator
{
    private readonly Ed25519PublicKeyParameters _publicKey;
    private readonly Ed25519PrivateKeyParameters? _privateKey;

    private WebhookValidator(Ed25519PrivateKeyParameters privateKey)
    {
        _privateKey = privateKey;
        _publicKey = privateKey.GeneratePublicKey();
    }

    private WebhookValidator(Ed25519PublicKeyParameters publicKey)
    {
        _publicKey = publicKey;
    }

    public static WebhookValidator FromPublicKeyDerBase64(string publicKeyDerBase64)
    {
        var decoded = Convert.FromBase64String(publicKeyDerBase64);
        var publicKey = (Ed25519PublicKeyParameters)PublicKeyFactory.CreateKey(decoded);
        if (publicKey == null)
        {
            throw new InvalidOperationException("Failed to parse key as Ed25519 public key!");
        }

        return new WebhookValidator(publicKey!);
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

    public async ValueTask<object?> Filter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        using var reader = new StreamReader(context.HttpContext.Request.Body);
        var payload = await reader.ReadToEndAsync();
        var signature = GetSignatureFromHeaders(context.HttpContext);
        if (signature == null)
        {
            return Results.Unauthorized();
        }

        var valid = ValidateSignature(Encoding.UTF8.GetBytes(payload), signature);
        if (!valid)
        {
            return Results.Unauthorized();
        }

        return await next(context);
    }

    private static byte[]? GetSignatureFromHeaders(HttpContext context)
    {
        var signatureHeader = context.Request.Headers["X-Body-Signature"].First();
        if (string.IsNullOrEmpty(signatureHeader))
        {
            return null;
        }

        try
        {
            var decoded = Convert.FromBase64String(signatureHeader);
            return decoded;
        }
        catch (FormatException)
        {
            return null;
        }
    }
}