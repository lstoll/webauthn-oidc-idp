class WebAuthn {
    // Decode a base64 string into a Uint8Array.
    static _decodeBuffer(value) {
        return Uint8Array.from(atob(value
            .replace(/\-/g, "+")
            .replace(/_/g, "/")
        ), c => c.charCodeAt(0));
    }

    // Encode an ArrayBuffer into a urlbase64 string.
    static _encodeBuffer(value) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=/g, "");;
    }

    // Checks whether the status returned matches the status given.
    static _checkStatus(status) {
        return res => {
            if (res.status === status) {
                return res;
            }
            throw new Error(res.statusText);
        };
    }

    register(data) {
        return fetch('/registration/begin?key_name=' + data.keyName, {
            method: 'POST',
            body: JSON.stringify(data)
        })
            .then(WebAuthn._checkStatus(200))
            .then(res => res.json())
            .then(res => {
                res.publicKey.challenge = WebAuthn._decodeBuffer(res.publicKey.challenge);
                res.publicKey.user.id = WebAuthn._decodeBuffer(res.publicKey.user.id);
                if (res.publicKey.excludeCredentials) {
                    for (var i = 0; i < res.publicKey.excludeCredentials.length; i++) {
                        res.publicKey.excludeCredentials[i].id = WebAuthn._decodeBuffer(res.publicKey.excludeCredentials[i].id);
                    }
                }
                return res;
            })
            .then(res => navigator.credentials.create(res))
            .then(credential => {
                return fetch('/registration/finish', {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        id: credential.id,
                        rawId: WebAuthn._encodeBuffer(credential.rawId),
                        response: {
                            attestationObject: WebAuthn._encodeBuffer(credential.response.attestationObject),
                            clientDataJSON: WebAuthn._encodeBuffer(credential.response.clientDataJSON)
                        },
                        type: credential.type
                    }),
                })
            })
            .then(WebAuthn._checkStatus(200));
    }

    login() {
        let email = $("#email").val()
        if (email === "") {
            alert("Please enter a email");
            return;
        }

        return fetch('/start?email=' + email + '&sessionID={{ .SessionID }}', {
            method: 'POST',
            body: JSON.stringify({}) // TODO - better than query string
        })
            .then(WebAuthn._checkStatus(200))
            .then(res => res.json())
            .then(res => {
                res.publicKey.challenge = WebAuthn._decodeBuffer(res.publicKey.challenge);
                if (res.publicKey.allowCredentials) {
                    for (let i = 0; i < res.publicKey.allowCredentials.length; i++) {
                        res.publicKey.allowCredentials[i].id = WebAuthn._decodeBuffer(res.publicKey.allowCredentials[i].id);
                    }
                }
                return res;
            })
            .then(res => navigator.credentials.get(res))
            .then(credential => {
                return fetch('/finish?email=' + email + '&sessionID={{ .SessionID }}', {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        id: credential.id,
                        rawId: WebAuthn._encodeBuffer(credential.rawId),
                        type: credential.type,
                        response: {
                            clientDataJSON: WebAuthn._encodeBuffer(credential.response.clientDataJSON),
                            authenticatorData: WebAuthn._encodeBuffer(credential.response.authenticatorData),
                            signature: WebAuthn._encodeBuffer(credential.response.signature),
                            userHandle: WebAuthn._encodeBuffer(credential.response.userHandle)
                        }
                    }),
                })
            })
            .then(WebAuthn._checkStatus(200));
    }
}

let w = new WebAuthn();

let registrationPending = false;

function doRegister() {
    if (registrationPending) return;
    registrationPending = true;
    // document.getElementById("loginLoading").classList.remove("hide");
    w.register({ "keyName": document.getElementById("keyName").value })
        // .then(res => res.json())
        .then(res => {
            location.reload();
        })
        .catch(err => {
            console.error(err);
            alert('Failed to register key: ' + err);
        })
        .then(() => {
            registrationPending = false;
            // document.getElementById("loginLoading").classList.add("hide");
        });
}

let loginPending = false;

function doLogin() {
    if (loginPending) return;
    loginPending = true;
    // document.getElementById("loginLoading").classList.remove("hide");
    // w.login({ "username": document.getElementById("email").value })
    w.login()
        // .then(res => res.json())
        .then(res => {
            window.location.href = '/loggedin';
        })
        .catch(err => {
            console.error(err);
            alert('Failed to login: ' + err);
        })
        .then(() => {
            loginPending = false;
            // document.getElementById("loginLoading").classList.add("hide");
        });
}
