package rulecatalog

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// javascriptTaintRules documents findings emitted by the JavaScript/TypeScript semantic value-flow
// coordinator. Detection is classified as AST to fit the existing closed producer vocabulary; tags retain
// the stronger value-flow/interprocedural identity for clients and review tooling.
func javascriptTaintRules() []rule.Rule {
	return []rule.Rule{
		javascriptTaintRule("javascript-taint-command", "Interprocedural JavaScript command injection", "CWE-78", "A03:2021", shared.SeverityCritical,
			"Tracks request-controlled JavaScript and TypeScript values through local calls into child_process command execution APIs.",
			"Use a fixed executable and argument array, validate each argument, and avoid shell interpretation.",
			"execFile('/usr/bin/id', ['--user', validatedUser])", "exec(req.query.command)"),
		javascriptTaintRule("javascript-taint-eval", "Interprocedural JavaScript dynamic code injection", "CWE-95", "A03:2021", shared.SeverityCritical,
			"Tracks untrusted values into eval and Node.js vm code-evaluation APIs.",
			"Do not evaluate request-controlled source text; select behavior from fixed code paths or a constrained data format.",
			"handlers[action](validatedPayload)", "eval(req.body.expression)"),
		javascriptTaintRule("javascript-taint-sqli", "Interprocedural JavaScript SQL injection", "CWE-89", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted values into raw SQL statement text across JavaScript and TypeScript helper calls.",
			"Keep SQL text constant and use the driver's parameter binding or prepared-statement API.",
			"client.query('SELECT * FROM users WHERE id = $1', [id])", "client.query('SELECT * FROM users WHERE id=' + req.query.id)"),
		javascriptTaintRule("javascript-taint-nosql", "Interprocedural JavaScript NoSQL injection", "CWE-943", "A03:2021", shared.SeverityHigh,
			"Tracks request-controlled query objects into MongoDB/Mongoose-style find, update, and delete operations.",
			"Build query objects from allow-listed scalar fields and reject operator-bearing or unexpected object shapes.",
			"User.findOne({ id: validatedId })", "User.findOne(req.body.filter)"),
		javascriptTaintRule("javascript-taint-path", "Interprocedural JavaScript path traversal", "CWE-22", "A01:2021", shared.SeverityHigh,
			"Tracks untrusted paths into Node.js filesystem read/write APIs.",
			"Resolve beneath a fixed root and reject absolute or escaping paths; prefer opaque server-side identifiers.",
			"fs.readFile(path.join(uploadRoot, safeName))", "fs.readFile(req.query.file)"),
		javascriptTaintRule("javascript-taint-ssrf", "Interprocedural JavaScript server-side request forgery", "CWE-918", "A10:2021", shared.SeverityHigh,
			"Tracks request-controlled URLs into fetch, axios, got, request, and Node.js HTTP clients.",
			"Normalize and allow-list schemes and destinations, resolve DNS safely, and block private/link-local addresses.",
			"fetch('https://api.example.com/status')", "fetch(req.query.url)"),
		javascriptTaintRule("javascript-taint-xss", "Interprocedural JavaScript cross-site scripting", "CWE-79", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted web values into response APIs that can return attacker-controlled markup.",
			"Use contextual output encoding or an allow-list HTML sanitizer before returning user-controlled markup.",
			"res.send(DOMPurify.sanitize(input))", "res.send(req.query.html)"),
		javascriptTaintRule("javascript-taint-open-redirect", "Interprocedural JavaScript open redirect", "CWE-601", "A01:2021", shared.SeverityMedium,
			"Tracks request-controlled destinations into web-framework redirect responses.",
			"Use relative application routes or allow-list normalized destination hosts and schemes.",
			"res.redirect('/account')", "res.redirect(req.query.next)"),
		javascriptTaintRule("javascript-taint-ssti", "Interprocedural JavaScript server-side template injection", "CWE-1336", "A03:2021", shared.SeverityHigh,
			"Tracks untrusted template source text into EJS, Handlebars, and Nunjucks compilation/render-string APIs.",
			"Render a fixed template and pass request values only as data; never compile request-controlled template text.",
			"res.render('profile', { name })", "Handlebars.compile(req.body.template)"),
		javascriptTaintRule("javascript-taint-deserialization", "Interprocedural JavaScript unsafe deserialization", "CWE-502", "A08:2021", shared.SeverityCritical,
			"Tracks untrusted values into object deserializers that can reconstruct dangerous JavaScript objects.",
			"Use JSON plus schema validation and avoid executable/object-restoring serialization formats for untrusted data.",
			"schema.parse(JSON.parse(body))", "serialize.unserialize(req.body.payload)"),
	}
}

func javascriptTaintRule(key, name, cwe, owasp string, severity shared.Severity, description, remediation, compliant, noncompliant string) rule.Rule {
	return rule.Rule{
		Key: rule.Key(key), Name: name, Language: "JavaScript/TypeScript", Type: rule.TypeVulnerability,
		Qualities: []rule.Quality{rule.QualitySecurity}, DefaultSeverity: severity,
		Tags: []string{"javascript", "typescript", "taint", "interprocedural", "value-flow"}, CWE: []string{cwe}, OWASP: []string{owasp},
		Description: description,
		Rationale: "A source-to-sink value-flow witness shows attacker-controlled data can reach a security-sensitive operation without a class-appropriate neutralization step.\n\nSource: https://cwe.mitre.org/data/definitions/" + cwe[4:] + ".html",
		Remediation: remediation, CompliantExample: compliant, NoncompliantExample: noncompliant,
		RemediationEffort: 60, Detection: rule.DetectionAST,
	}
}
