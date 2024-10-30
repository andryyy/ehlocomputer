htmx.on("body", "startReg", async function(evt){
  const { startRegistration } = SimpleWebAuthnBrowser
  var reg_button = htmx.find("#register")
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

htmx.on("body", "startAuth", async function(evt){
  const { startAuthentication } = SimpleWebAuthnBrowser
  var login_button = htmx.find("#authenticate")
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
	htmx.findAll("#register,#auth").forEach((element) => {
			element.removeAttribute("hx-ext")
			element.removeAttribute("hx-vals")
	    	element.removeAttribute("hx-post")
	    	htmx.process(element)
    	}
	)
})
