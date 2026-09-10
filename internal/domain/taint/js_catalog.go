package taint

// JSCallablePattern matches semantically-resolved package callables plus a deliberately small
// raw-suffix allow-list for framework receiver objects (req/res/ctx) that cannot be identified by
// an import alone. Generic method names such as query/find are never raw matches.
type JSCallablePattern struct {
	Modules     []string
	Names       []string
	RawSuffixes []string
}

type JSSourceModel struct {
	Pattern JSCallablePattern
	Classes []TaintClass
}

type JSSinkModel struct {
	Pattern         JSCallablePattern
	Class           TaintClass
	CWE             string
	Rule            string
	ArgumentIndexes []int
	Receiver        bool
}

type JSSanitizerModel struct {
	Pattern JSCallablePattern
	Classes []TaintClass
}

type JSCatalog struct {
	Sources          []JSSourceModel
	Sinks            []JSSinkModel
	Sanitizers       []JSSanitizerModel
	ReferenceSources []string
}

func DefaultJSCatalog() JSCatalog {
	all := []TaintClass{
		TaintSQL, TaintCommand, TaintPathTraversal, TaintSSRF, TaintXSS,
		TaintDeserialization, TaintRedirect, TaintSSTI,
	}
	return JSCatalog{
		ReferenceSources: []string{
			"req.body", "req.query", "req.params", "req.headers", "req.cookies",
			"request.body", "request.query", "request.params", "request.headers",
			"ctx.request.body", "ctx.query", "ctx.params", "ctx.headers",
		},
		Sources: []JSSourceModel{
			{Pattern: jsRawCall("req.get", "req.header", "request.get", "request.header"), Classes: all},
			{Pattern: jsRawCall("ctx.get", "ctx.request.get"), Classes: all},
		},
		Sinks: []JSSinkModel{
			// CWE-78: command execution. Aliases/destructuring are resolved back to the package.
			{Pattern: jsModuleCall([]string{"child_process", "node:child_process"}, []string{"exec", "execSync"}), Class: TaintCommand, CWE: "CWE-78", Rule: "javascript-taint-command", ArgumentIndexes: []int{0}},

			// CWE-95: eval-like execution. eval is represented as global.eval by the resolver.
			{Pattern: jsModuleCall([]string{"global"}, []string{"eval"}), Class: TaintCommand, CWE: "CWE-95", Rule: "javascript-taint-eval", ArgumentIndexes: []int{0}},
			{Pattern: jsModuleCall([]string{"vm", "node:vm"}, []string{"runInThisContext", "runInNewContext", "runInContext", "compileFunction"}), Class: TaintCommand, CWE: "CWE-95", Rule: "javascript-taint-eval", ArgumentIndexes: []int{0}},

			// CWE-89: SQL program text only. Parameter/value arguments after the query text are not sinks.
			{Pattern: jsModuleAndRawCall(
				[]string{"pg", "mysql", "mysql2", "mysql2/promise", "knex", "sequelize", "@prisma/client"},
				[]string{"query", "raw", "$queryRaw", "$executeRaw"},
				"db.query", "pool.query", "client.query", "connection.query", "sequelize.query", "knex.raw", "prisma.$queryRaw", "prisma.$executeRaw",
			), Class: TaintSQL, CWE: "CWE-89", Rule: "javascript-taint-sqli", ArgumentIndexes: []int{0}},

			// CWE-943: NoSQL query-object injection. Raw fallbacks are restricted to conventional DB receivers.
			{Pattern: jsModuleAndRawCall(
				[]string{"mongodb", "mongoose"},
				[]string{"find", "findOne", "findOneAndUpdate", "updateOne", "updateMany", "deleteOne", "deleteMany"},
				"collection.find", "collection.findOne", "collection.findOneAndUpdate", "collection.updateOne", "collection.updateMany", "model.find", "model.findOne", "model.findOneAndUpdate",
			), Class: TaintSQL, CWE: "CWE-943", Rule: "javascript-taint-nosql", ArgumentIndexes: []int{0}},

			// CWE-22: filesystem paths.
			{Pattern: jsModuleCall(
				[]string{"fs", "node:fs", "fs/promises", "node:fs/promises"},
				[]string{"readFile", "readFileSync", "writeFile", "writeFileSync", "createReadStream", "createWriteStream", "open", "openSync", "unlink", "unlinkSync", "rm", "rmSync", "readdir", "readdirSync"},
			), Class: TaintPathTraversal, CWE: "CWE-22", Rule: "javascript-taint-path", ArgumentIndexes: []int{0}},

			// CWE-918: outbound URLs.
			{Pattern: jsModuleCall([]string{"global"}, []string{"fetch"}), Class: TaintSSRF, CWE: "CWE-918", Rule: "javascript-taint-ssrf", ArgumentIndexes: []int{0}},
			{Pattern: jsModuleCall([]string{"axios", "got", "node-fetch", "undici"}, []string{"get", "post", "put", "patch", "delete", "head", "request", "fetch"}), Class: TaintSSRF, CWE: "CWE-918", Rule: "javascript-taint-ssrf", ArgumentIndexes: []int{0}},
			{Pattern: jsModuleCall([]string{"http", "node:http", "https", "node:https"}, []string{"get", "request"}), Class: TaintSSRF, CWE: "CWE-918", Rule: "javascript-taint-ssrf", ArgumentIndexes: []int{0}},

			// Framework response objects are application-local values, so these are explicit raw receiver models.
			{Pattern: jsRawCall("res.send", "res.write", "response.send", "response.write", "ctx.body"), Class: TaintXSS, CWE: "CWE-79", Rule: "javascript-taint-xss", ArgumentIndexes: []int{0}},
			{Pattern: jsRawCall("res.redirect", "response.redirect", "ctx.redirect"), Class: TaintRedirect, CWE: "CWE-601", Rule: "javascript-taint-open-redirect", ArgumentIndexes: []int{0}},

			// CWE-1336: attacker-controlled template source, not ordinary render variables.
			{Pattern: jsModuleCall([]string{"ejs"}, []string{"render", "compile"}), Class: TaintSSTI, CWE: "CWE-1336", Rule: "javascript-taint-ssti", ArgumentIndexes: []int{0}},
			{Pattern: jsModuleCall([]string{"handlebars"}, []string{"compile"}), Class: TaintSSTI, CWE: "CWE-1336", Rule: "javascript-taint-ssti", ArgumentIndexes: []int{0}},
			{Pattern: jsModuleCall([]string{"nunjucks"}, []string{"renderString"}), Class: TaintSSTI, CWE: "CWE-1336", Rule: "javascript-taint-ssti", ArgumentIndexes: []int{0}},

			// CWE-502: known unsafe object deserializers.
			{Pattern: jsModuleCall([]string{"node-serialize"}, []string{"unserialize"}), Class: TaintDeserialization, CWE: "CWE-502", Rule: "javascript-taint-deserialization", ArgumentIndexes: []int{0}},
		},
		Sanitizers: []JSSanitizerModel{
			{Pattern: jsModuleAndRawCall([]string{"dompurify"}, []string{"sanitize"}, "DOMPurify.sanitize"), Classes: []TaintClass{TaintXSS}},
			{Pattern: jsModuleCall([]string{"sanitize-html"}, []string{"", "sanitize"}), Classes: []TaintClass{TaintXSS}},
			{Pattern: jsModuleCall([]string{"validator"}, []string{"escape"}), Classes: []TaintClass{TaintXSS}},
			{Pattern: jsModuleCall([]string{"path", "node:path"}, []string{"basename"}), Classes: []TaintClass{TaintPathTraversal}},
			{Pattern: jsModuleCall([]string{"global"}, []string{"encodeURIComponent"}), Classes: []TaintClass{TaintRedirect}},
		},
	}
}

func jsModuleCall(modules, names []string) JSCallablePattern {
	return JSCallablePattern{Modules: modules, Names: names}
}

func jsRawCall(raw ...string) JSCallablePattern {
	return JSCallablePattern{RawSuffixes: raw}
}

func jsModuleAndRawCall(modules, names []string, raw ...string) JSCallablePattern {
	return JSCallablePattern{Modules: modules, Names: names, RawSuffixes: raw}
}
