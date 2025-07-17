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
}