using Microsoft.AspNetCore.Mvc;
using WebhookValidation;

namespace WebApi.Controllers;

[ApiController]
public class WebhookController : Controller
{
    [HttpPost("/api/v1/webhook")]
    [ServiceFilter<WebhookSignatureValidationFilter>]
    public async Task Webhook()
    {
        using var reader = new StreamReader(HttpContext.Request.Body);
        var body = await reader.ReadToEndAsync();

        HttpContext.Response.ContentType = HttpContext.Request.ContentType ?? "application/json; charset=UTF-8";
        await HttpContext.Response.WriteAsync(body);
    }
}