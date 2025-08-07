local redhunter = require("redhunter")

ngx.req.read_body()
local request = {
    uri = ngx.var.request_uri,
    method = ngx.req.get_method(),
    headers = ngx.req.get_headers(),
    body = ngx.req.get_body_data() or ""
}

local result = redhunter.analyze(request)

if result.action == "block" then
    ngx.status = 403
    ngx.say('{"error": "Request blocked by RedHunter WAF"}')
    ngx.exit(403)
elseif result.action == "captcha" then
    ngx.redirect("/captcha-verify?token=" .. ngx.time())
end