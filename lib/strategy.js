const Url = require("url");

const { Issuer } = require("openid-client");
const Hoek = require("@hapi/hoek");
const jwtDecode = require('jwt-decode');

const pkg = require("../package.json");
const scheme = require("./scheme");

const MANUAL_SETTINGS = [
	"issuer",
	"authorization",
	"token",
	"userinfo",
	"jwks",
];
const PLUGIN_DEFAULTS = {
	cookie: "hapi-oidc",
	scope: "openid",
};

exports.plugin = {
	pkg,
	register: async (server, options) => {
		const { store, loginValidation } = options;
		const config = Hoek.applyToDefaults(PLUGIN_DEFAULTS, options);

		// Validate config
		if (!config.clientId || !config.clientSecret)
			throw new Error("You must provide a clientId and a clientSecret");
		if (!config.callbackUrl) throw new Error("You must provide a callbackUrl");
		if (!config.discoverUrl && MANUAL_SETTINGS.some((k) => !(k in config)))
			throw new Error(
				"You must provide a discoverUrl or a valid manual settings"
			);

		const cookieName = config.cookie;
		const issuer = config.discoverUrl
			? await Issuer.discover(config.discoverUrl)
			: new Issuer({
					issuer: config.issuer,
					authorization_endpoint: config.authorization,
					token_endpoint: config.token,
					userinfo_endpoint: config.userinfo,
					jwks_uri: config.jwks,
			  });
		const client = new issuer.Client({
			client_id: config.clientId,
			client_secret: config.clientSecret,
		});

		server.route({
			method: "GET",
			path: Url.parse(config.callbackUrl).path,

			handler: async (request, h) => {
				const { state } = request.state[cookieName];
				try {
					const token = await client.callback(
						request.headers['x-requested-with'] !== 'XMLHttpRequest' ? config.callbackUrl : config.xhrCallbackUrl,
						request.query,
						{ state }
					);
					const userInfos = await client.userinfo(token);
					if (store) {
						await store.save([
							[`${token.access_token}userInfos`, userInfos],
							[`${token.access_token}token`, token],
						]);
					}
					const credentials = jwtDecode(token.access_token)

					if(typeof(loginValidation) === 'function'
							&& !(await loginValidation(credentials, userInfos))) {
						throw new Error("Login failed login validation.")
					}

					h.state(cookieName, {
						credentials,
					});
					return h.redirect(state).takeover();
				} catch (err) {
					request.log(["error", "auth"], err.error_description);
					throw err;
				}
			},
		});
		server.auth.scheme(
			"oidc",
			scheme({
				cookieName,
				callbackUrl: config.callbackUrl,
				xhrCallbackUrl: config.xhrCallbackUrl,
				scope: config.scope,
				client,
			})
		);
	},
};
