from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"expected snippet not found in {path}")
    p.write_text(text.replace(old, new, 1))

replace_once(
    "internal/infrastructure/tools/secretscan/parity_rules.go",
    'assignedParityRule("mongodb-atlas-api-private-key", "MongoDB", "MongoDB Atlas API private key", high, []string{"mongodb", "atlas", "private_key"}, `(?:mongodb|atlas)[_-]?(?:api[_-]?)?private[_-]?key`, `[A-Za-z0-9_-]{24,64}`, 3.0),',
    'assignedParityRule("atlassian-api-token", "Atlassian", "Atlassian/Jira API token", high, []string{"atlassian", "jira", "api_token"}, `(?:atlassian|jira)[_-]?(?:api[_-]?)?(?:token|key)`, `[A-Za-z0-9._~-]{20,128}`, 3.0),',
)
replace_once(
    "internal/infrastructure/rulecatalog/secrets_parity.go",
    '{"mongodb-atlas-api-private-key", "MongoDB Atlas API private key", "mongodb", high, "https://www.mongodb.com/docs/atlas/configure-api-access/"},',
    '{"atlassian-api-token", "Atlassian/Jira API token", "atlassian", high, "https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/"},',
)
replace_once(
    "internal/infrastructure/tools/secretscan/parity_rules_test.go",
    '{"mongodb-atlas-api-private-key", assign("MONGODB_ATLAS_PRIVATE_KEY", "AbCdEfGhIjKlMnOp", "QrStUvWxYz123456"), assign("MONGODB_ATLAS_PRIVATE_KEY", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},',
    '{"atlassian-api-token", assign("ATLASSIAN_API_TOKEN", "ATATT3xFfGF0", "AbCdEfGhIjKlMnOpQrStUvWxYz"), assign("ATLASSIAN_API_TOKEN", "EXAMPLEEXAMPLE", "EXAMPLEEXAMPLE")},',
)

golden = Path("internal/infrastructure/rulecatalog/testdata/rule_keys.txt")
keys = {line.strip() for line in golden.read_text().splitlines() if line.strip()}
keys.discard("mongodb-atlas-api-private-key")
keys.add("atlassian-api-token")
golden.write_text("\n".join(sorted(keys)) + "\n")

changelog = Path("CHANGELOG.md")
text = changelog.read_text()
text = text.replace("adding coverage for Okta, Auth0, Cloudflare", "adding coverage for Atlassian/Jira, Okta, Auth0, Cloudflare", 1)
changelog.write_text(text)
