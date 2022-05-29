class WebAuthn {
    // Decode a base64 string into a Uint8Array.
    static _decodeBuffer(value) {
        return Uint8Array.from(atob(value), c => c.charCodeAt(0));
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
        return fetch('{{ pathFor "/registration/begin" }}?key_name=' + data.keyName + '&{{ .WebauthnQuery }}', {
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
                return fetch('{{ pathFor "/registration/finish?" }}{{ .WebauthnQuery }}', {
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
