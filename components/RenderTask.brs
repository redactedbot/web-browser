sub init()
    m.top.control = "IDLE"
    m.top.response = {}
end sub

sub onFieldChanged(fieldName as String)
    ' optional hook (not used here)
end sub

function Run() as Object
    ' This function will be executed on the Task thread when control="RUN"
    url = m.top.targetUrl
    server = m.top.serverEndpoint
    apikey = m.top.clientApiKey

    if server = "" or url = "" then
        m.top.response = { error: "missing server or url" }
        return m.top.response
    end if

    ' Step 1: exchange API key for JWT (if api key provided)
    token = ""
    if apikey <> "" then
        xfer = CreateObject("roUrlTransfer")
        xfer.SetUrl(server + "/auth/token")
        xfer.SetRequest("POST")
        xfer.SetHeaders({ "Content-Type":"application/json", "x-api-key": apikey })
        xfer.SetPostFromString("{}")
        tokenResp = xfer.GetToString()
        if tokenResp = invalid or tokenResp = "" then
            m.top.response = { error: "auth error" }
            return m.top.response
        end if
        t = ParseJson(tokenResp)
        if t.token <> invalid then
            token = t.token
        end if
    end if

    ' Step 2: call /render with Authorization or x-api-key fallback
    xfer2 = CreateObject("roUrlTransfer")
    xfer2.SetUrl(server + "/render")
    xfer2.SetRequest("POST")
    headers = { "Content-Type":"application/json" }
    if token <> "" then
        headers["Authorization"] = "Bearer " + token
    else if apikey <> "" then
        headers["x-api-key"] = apikey
    end if
    xfer2.SetHeaders(headers)
    xfer2.SetPostFromString(FormatJson({ url: url }))
    respStr = xfer2.GetToString()
    if respStr = invalid or respStr = "" then
        m.top.response = { error: "render request failed" }
        return m.top.response
    end if
    parsed = ParseJson(respStr)
    m.top.response = parsed
    return m.top.response
end function
