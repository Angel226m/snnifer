const manifest = (() => {
function __memo(fn) {
	let value;
	return () => value ??= (value = fn());
}

return {
	appDir: "_app",
	appPath: "_app",
	assets: new Set(["favicon.svg"]),
	mimeTypes: {".svg":"image/svg+xml"},
	_: {
		client: {start:"_app/immutable/entry/start.C2v8kO7w.js",app:"_app/immutable/entry/app.1pCWmX8g.js",imports:["_app/immutable/entry/start.C2v8kO7w.js","_app/immutable/chunks/C0Mi_tZT.js","_app/immutable/chunks/BC89KWPb.js","_app/immutable/chunks/CZdkY60O.js","_app/immutable/entry/app.1pCWmX8g.js","_app/immutable/chunks/BC89KWPb.js","_app/immutable/chunks/Db55wh2Y.js"],stylesheets:[],fonts:[],uses_env_dynamic_public:false},
		nodes: [
			__memo(() => import('./chunks/0-BE2kft_m.js')),
			__memo(() => import('./chunks/1-Cd-1eNCa.js')),
			__memo(() => import('./chunks/2-C5pbzVhI.js')),
			__memo(() => import('./chunks/3-tyZ0fsa-.js'))
		],
		remotes: {
			
		},
		routes: [
			{
				id: "/",
				pattern: /^\/$/,
				params: [],
				page: { layouts: [0,], errors: [1,], leaf: 2 },
				endpoint: null
			},
			{
				id: "/dashboard",
				pattern: /^\/dashboard\/?$/,
				params: [],
				page: { layouts: [0,], errors: [1,], leaf: 3 },
				endpoint: null
			}
		],
		prerendered_routes: new Set([]),
		matchers: async () => {
			
			return {  };
		},
		server_assets: {}
	}
}
})();

const prerendered = new Set([]);

const base = "";

export { base, manifest, prerendered };
//# sourceMappingURL=manifest.js.map
