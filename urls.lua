-- urls.lua for httpbin
wrk.method = "GET"
local paths = {
  "/get",
  "/ip",
  "/user-agent",
  "/headers",
  "/uuid",
  "/delay/1"
}

request = function()
  local path = paths[math.random(#paths)]
  return wrk.format(nil, "http://httpbin.org" .. path)
end

