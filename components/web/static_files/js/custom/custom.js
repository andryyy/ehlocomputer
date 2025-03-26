htmx.on("body", "startReg", async function(evt){
  const { startRegistration } = SimpleWebAuthnBrowser
  var reg_button = htmx.find("#register")
  reg_button.textContent = "Processing..."
  reg_button.disabled = true
  reg_opts = JSON.parse(evt.detail.value)
  try {
    reg_response = await startRegistration(reg_opts)
    reg_button.setAttribute("hx-ext", "json-enc")
    reg_button.setAttribute("hx-vals", JSON.stringify(reg_response))
    reg_button.setAttribute("hx-post", "/auth/register/webauthn")
    htmx.process("#register")
    htmx.trigger("#register", "click")
  } catch (err) {
    htmx.trigger("body", "notification", {
	  	level: "error",
	    title: "WebAuthn Error",
	    message: err
    })
    htmx.trigger("body", "authRegFailed")
  }
})

htmx.on("body", "regCompleted", async function(evt){
    htmx.trigger(".login-register:not([hidden])", "click")
  	htmx.find("#webauthn-login").value = evt.detail.value
})

htmx.on("body", "startAuth", async function(evt){
  const { startAuthentication } = SimpleWebAuthnBrowser
  var login_button = htmx.find("#authenticate")
  login_button.textContent = "Processing..."
  login_button.disabled = true
  auth_opts = JSON.parse(evt.detail.value)
  try {
    auth_response = await startAuthentication(auth_opts)
    login_button.setAttribute("hx-ext", "json-enc")
    login_button.setAttribute("hx-vals", JSON.stringify(auth_response))
    login_button.setAttribute("hx-post", "/auth/login/webauthn")
    htmx.process("#authenticate")
    htmx.trigger("#authenticate", "click")
  } catch (err) {
    htmx.trigger("body", "notification", {
	  	level: "error",
	    title: "WebAuthn Error",
	    message: err
    })
    htmx.trigger("body", "authRegFailed")
  }
})

htmx.on("body", "authRegFailed", async function(evt){
	htmx.ajax("GET", "/", "#body-main")
})

function datetime_local(add_minutes) {
	var now = new Date();
	minutes = (now.getMinutes() + add_minutes)
	now.setMinutes(minutes - now.getTimezoneOffset());
	return now.toISOString().slice(0,16);
}
