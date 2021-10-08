package upstream

default allow = false

allow = true {
    input.iss == "https://accounts.google.com"
    input.email == "lincoln.stoll@gmail.com"
}
