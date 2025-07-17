using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace WebhookValidation;

public class WebhookSignatureValidationFilter(WebhookValidator validator) : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        if (!await validator.ValidateSignature(context.HttpContext))
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        await next();
    }
}