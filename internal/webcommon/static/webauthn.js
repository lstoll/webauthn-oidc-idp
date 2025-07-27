/**
 * Modern WebAuthn implementation for browser-based authentication
 * @typedef {Object} RegistrationData
 * @property {string} keyName - The name for the key being registered
 *
 * @typedef {Object} CredentialResponse
 * @property {string} id - The credential ID
 * @property {string} rawId - Base64 encoded raw ID
 * @property {string} type - The credential type
 * @property {Object} response - The credential response data
 */

class WebAuthn {
    /**
     * Decode a base64 string into a Uint8Array
     * @param {string} value - Base64 encoded string
     * @returns {Uint8Array} Decoded buffer
     */
    static _decodeBuffer(value) {
        return Uint8Array.from(atob(value
            .replace(/-/g, "+")
            .replace(/_/g, "/")
        ), c => c.charCodeAt(0));
    }

    /**
     * Encode an ArrayBuffer into a url-safe base64 string
     * @param {ArrayBuffer} value - Buffer to encode
     * @returns {string} URL-safe base64 string
     */
    static _encodeBuffer(value) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=/g, "");
    }

    /**
     * Check if the response status matches the expected status
     * @param {number} status - Expected HTTP status code
     * @returns {Function} Response handler function
     */
    static _checkStatus(status) {
        return res => {
            if (res.status === status) {
                return res;
            }
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        };
    }

    /**
     * Register a new WebAuthn credential
     * @param {RegistrationData} data - Registration data
     * @returns {Promise<Response>} Registration response
     */
    async register(data) {
        const response = await fetch('/registration/begin?key_name=' + encodeURIComponent(data.keyName), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        const res = await WebAuthn._checkStatus(200)(response);
        const registrationData = await res.json();

        // Decode challenge and user ID
        registrationData.publicKey.challenge = WebAuthn._decodeBuffer(registrationData.publicKey.challenge);
        registrationData.publicKey.user.id = WebAuthn._decodeBuffer(registrationData.publicKey.user.id);

        // Decode exclude credentials if present
        if (registrationData.publicKey.excludeCredentials) {
            registrationData.publicKey.excludeCredentials.forEach(credential => {
                credential.id = WebAuthn._decodeBuffer(credential.id);
            });
        }

        const credential = await navigator.credentials.create(registrationData);

        const finishResponse = await fetch('/registration/finish', {
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
        });

        return WebAuthn._checkStatus(200)(finishResponse);
    }

    /**
     * Authenticate with WebAuthn using discoverable credentials
     * @param {string} sessionID - Session identifier
     * @returns {Promise<Response>} Authentication response
     */
    async login(sessionID) {
        const response = await fetch(`/start?sessionID=${encodeURIComponent(sessionID)}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})
        });

        const res = await WebAuthn._checkStatus(200)(response);
        const authData = await res.json();

        // Decode challenge
        authData.publicKey.challenge = WebAuthn._decodeBuffer(authData.publicKey.challenge);

        // Decode allow credentials if present
        if (authData.publicKey.allowCredentials) {
            authData.publicKey.allowCredentials.forEach(credential => {
                credential.id = WebAuthn._decodeBuffer(credential.id);
            });
        }

        const credential = await navigator.credentials.get(authData);

        const finishResponse = await fetch(`/finish?sessionID=${encodeURIComponent(sessionID)}`, {
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
        });

        return WebAuthn._checkStatus(200)(finishResponse);
    }
}

/**
 * WebAuthn UI Manager - Handles DOM interactions and event binding
 */
class WebAuthnUI {
    constructor() {
        this.webauthn = new WebAuthn();
        this.registrationPending = false;
        this.loginPending = false;
        this.sessionID = this.getSessionID();
        this.bindEvents();

        // Auto-login on page load (like the original onload="doLogin()")
        this.autoLogin();
    }

    /**
     * Extract session ID from template variables or data attributes
     * @returns {string} Session ID
     */
    getSessionID() {
        // Try to get from data attribute first
        const sessionElement = document.querySelector('[data-session-id]');
        if (sessionElement) {
            return sessionElement.dataset.sessionId;
        }

        // Fallback to template variable (if available)
        // This would be replaced by the server-side template engine
        return '{{ .SessionID }}';
    }

    /**
     * Auto-login on page load
     */
    async autoLogin() {
        // Only auto-login if we're on a login page (has login form or button)
        const loginForm = document.getElementById('login-form');
        const loginButton = document.getElementById('login-button');

        if (loginForm || loginButton) {
            // Small delay to ensure page is fully loaded
            setTimeout(() => {
                this.handleLogin();
            }, 100);
        }
    }

    /**
     * Bind event listeners to DOM elements
     */
    bindEvents() {
        // Registration button
        const registerButton = document.getElementById('register-button');
        if (registerButton) {
            registerButton.addEventListener('click', () => this.handleRegister());
        }

        // Login button
        const loginButton = document.getElementById('login-button');
        if (loginButton) {
            loginButton.addEventListener('click', () => this.handleLogin());
        }

        // Form submission handlers
        const registerForm = document.getElementById('register-form');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleRegister();
            });
        }

        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin();
            });
        }
    }

    /**
     * Handle registration process
     */
    async handleRegister() {
        if (this.registrationPending) return;

        const keyNameInput = document.getElementById('keyName');
        if (!keyNameInput || !keyNameInput.value.trim()) {
            this.showError('Please enter a key name');
            return;
        }

        this.registrationPending = true;
        this.setLoadingState('register', true);

        try {
            await this.webauthn.register({
                keyName: keyNameInput.value.trim()
            });

            // Success - reload page or redirect
            window.location.reload();
        } catch (error) {
            console.error('Registration failed:', error);
            this.showError(`Failed to register key: ${error.message}`);
        } finally {
            this.registrationPending = false;
            this.setLoadingState('register', false);
        }
    }

    /**
     * Handle login process
     */
    async handleLogin() {
        if (this.loginPending) return;

        this.loginPending = true;
        this.setLoadingState('login', true);

        try {
            await this.webauthn.login(this.sessionID);

            // Success - redirect to logged in page
            window.location.href = '/loggedin';
        } catch (error) {
            console.error('Login failed:', error);
            this.showError(`Failed to login: ${error.message}`);
        } finally {
            this.loginPending = false;
            this.setLoadingState('login', false);
        }
    }

    /**
     * Show error message to user
     * @param {string} message - Error message
     */
    showError(message) {
        console.error("WebAuthnUI.showError", message);
        // Try to find an error display element
        const errorElement = document.getElementById('error-message') ||
                           document.querySelector('.error-message');

        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';

            // Auto-hide after 5 seconds
            setTimeout(() => {
                errorElement.style.display = 'none';
            }, 5000);
        } else {
            // Fallback to alert
            alert(message);
        }
    }

    /**
     * Set loading state for buttons
     * @param {string} action - 'register' or 'login'
     * @param {boolean} isLoading - Whether to show loading state
     */
    setLoadingState(action, isLoading) {
        const button = document.getElementById(`${action}-button`);
        const loadingElement = document.getElementById(`${action}-loading`);

        if (button) {
            button.disabled = isLoading;
            if (isLoading) {
                button.dataset.originalText = button.textContent;
                button.textContent = 'Processing...';
            } else if (button.dataset.originalText) {
                button.textContent = button.dataset.originalText;
            }
        }

        if (loadingElement) {
            loadingElement.style.display = isLoading ? 'block' : 'none';
        }
    }
}

// Initialize WebAuthn UI when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new WebAuthnUI();
});

// Export for potential module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { WebAuthn, WebAuthnUI };
}
