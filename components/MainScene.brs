sub init()
    m.task = m.top.findNode("renderTask")
    m.screenshot = m.top.findNode("screenshot")
    m.article = m.top.findNode("articleText")
    m.title = m.top.findNode("title")
    m.fav1 = m.top.findNode("fav1")
    m.fav2 = m.top.findNode("fav2")

    ' observe task response field
    m.task.observeField("response", "onResponse")

    ' set required inputs on the task
    m.task.serverEndpoint = m.top.serverEndpoint
    m.task.clientApiKey = m.top.clientApiKey

    ' start with first favorite
    url = ""
    if m.top.favorites <> invalid and m.top.favorites.count() > 0 then
        url = m.top.favorites[0]
    else
        url = "https://example.com"
    end if

    m.task.targetUrl = url
    m.task.control = "RUN"
end sub

sub onResponse()
    resp = m.task.response
    if resp = invalid then
        m.article.text = "No response"
        return
    end if
    if resp.error <> invalid then
        m.article.text = "Server error: " + resp.error
        return
    end if
    m.screenshot.uri = resp.imageUrl
    if resp.title <> invalid and resp.title <> "" then
        m.title.text = resp.title
    end if
    if resp.text <> invalid then
        m.article.text = resp.text
    else if resp.articleHtml <> invalid then
        ' fallback to plain HTML-to-text conversion here in a simple way
        m.article.text = resp.articleHtml
    end if
end sub
