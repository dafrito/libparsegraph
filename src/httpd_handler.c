#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <ap_config.h>

static int parsegraph_common_handler(request_rec *r)
{
    if (strcmp(r->handler, "parsegraph_common")) {
        return DECLINED;
    }
    r->content_type = "text/html";

    if (!r->header_only) {
        ap_rputs("The sample page from parsegraph_common.c\n", r);
        ap_rputs("<br>", r);
        ap_rputs("You gave ", r);
        ap_rputs(r->uri, r);
    }
    return OK;
}

static void parsegraph_common_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(parsegraph_common_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA parsegraph_common_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    parsegraph_common_register_hooks
};
