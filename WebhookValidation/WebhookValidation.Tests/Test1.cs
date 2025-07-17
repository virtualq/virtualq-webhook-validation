using System.Text;
using WebhookValidation;

namespace WebhookValidation.Tests;

[TestClass]
public sealed class WebhookValidationConstructors
{
    [TestMethod]
    public void TestTheTruth()
    {
        Assert.IsTrue(true);
        Assert.IsFalse(false);
        Assert.AreEqual(2 + 2, 4);
    }

    [TestMethod]
    public void TestConstructor()
    {
        const string pubKeyDerBase64 = "MCowBQYDK2VwAyEA+6AXassBxLfnY3gXCLLEfP8RuiVJCyLvFwqOdeotrHw=";
        var validator = WebhookValidator.FromPublicKeyDerBase64(pubKeyDerBase64);
        var actual = validator.PublicKeyDerBase64;
        Assert.AreEqual(pubKeyDerBase64, actual);
    }

    [TestMethod]
    public void TestSignAndVerify()
    {
        const string privKeyDerBase64 = "MC4CAQAwBQYDK2VwBCIEILv3rSHWwkhf6hAoB47abEUZC9W0SEl15oZ+k3J4s4X2";
        const string msg = "All your base are belong to us!";
        var validator = WebhookValidator.FromPrivateKeyDerBase64(privKeyDerBase64);
        var payload = Encoding.UTF8.GetBytes(msg);

        // with valid signature
        var validSig = validator.SignPayload(payload);
        Assert.IsTrue(validator.ValidateSignature(payload, validSig));

        // with tampered payload
        var invalidPayload = Encoding.UTF8.GetBytes(msg + " invalid");
        Assert.IsFalse(validator.ValidateSignature(invalidPayload, validSig));

        // with tampered signature
        validSig[10] = (byte)~validSig[10];
        Assert.IsFalse(validator.ValidateSignature(payload, validSig));
    }
}