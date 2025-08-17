sub Main()
    screen = CreateObject("roSGScreen")
    port = CreateObject("roMessagePort")
    screen.SetMessagePort(port)
    scene = screen.CreateScene("MainScene")
    screen.Show()

    ' NOTE: update these before packaging or embed your server address in a safer config
    scene.SetField("serverEndpoint", "http://192.168.1.100:80") ' your nginx host reachable by Roku
    scene.SetField("clientApiKey", "") ' optionally put API key here (not recommended)
    scene.SetField("favorites", [
        "https://example.com",
        "https://news.example/interesting-article"
    ])
    while true
        msg = wait(0, port)
        if type(msg) = "roSGScreenEvent" then
            if msg.isScreenClosed() then return
        end if
    end while
end sub
