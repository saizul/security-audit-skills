# Safe patterns by vulnerability class and language

Each block: the risky shape, then the safe replacement. Fix the structure first; input
validation (types, lengths, allow-lists) is an extra layer, not the fix.

## SQL injection

Rule: values go in bound parameters. Identifiers (column, table, sort direction) cannot be
parameters - map them from an allow-list.

```python
# Python DB-API / psycopg / sqlite3
cur.execute("SELECT * FROM users WHERE email = %s", (email,))  # psycopg (%s), sqlite3 uses ?
# SQLAlchemy
session.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})
# Django ORM / raw
User.objects.filter(email=email)
User.objects.raw("SELECT * FROM app_user WHERE email = %s", [email])
# dynamic ORDER BY
SORTS = {"name": "name", "created": "created_at"}
order = SORTS.get(request.args.get("sort"), "created_at")
```

```js
// node-postgres
await pool.query("SELECT * FROM users WHERE email = $1", [email]);
// mysql2
await conn.execute("SELECT * FROM users WHERE email = ?", [email]);
// knex
knex("users").where({ email });                   knex.raw("lower(email) = ?", [email]);
// Prisma: tagged template is parameterized; *Unsafe variants are not
await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${email}`;
```

```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = ?');
$stmt->execute([$email]);
// WordPress
$wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->users} WHERE user_email = %s", $email));
// Laravel
DB::select('SELECT * FROM users WHERE email = ?', [$email]);   User::where('email', $email)->first();
```

```go
row := db.QueryRowContext(ctx, "SELECT id FROM users WHERE email = $1", email)
```

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE email = ?");
ps.setString(1, email);
// JPA
em.createQuery("SELECT u FROM User u WHERE u.email = :email", User.class).setParameter("email", email);
```

```ruby
User.where(email: email)
User.where("lower(email) = ?", email.downcase)
```

## OS command injection

Rule: avoid the shell. Call the program directly with an argument list; validate arguments
(allow-list, `--` before user-supplied positional arguments).

```python
subprocess.run(["convert", "--", src_path, out_path], check=True, timeout=30)  # shell=False
```
```js
const { execFile } = require("node:child_process");
execFile("convert", ["--", srcPath, outPath], { timeout: 30000 }, cb);
```
```php
// prefer a library; if a command is unavoidable:
$cmd = 'convert -- ' . escapeshellarg($src) . ' ' . escapeshellarg($out);
```
```go
cmd := exec.CommandContext(ctx, "convert", "--", src, out)
```
```java
new ProcessBuilder("convert", "--", src, out).start();
```
```ruby
system("convert", "--", src, out)     # multiple args: no shell
```

## XSS

Rule: let the template engine escape by context; only mark HTML safe after sanitising with an
allow-list sanitizer; add a CSP (`security-headers-check`) as defence in depth.

| Stack | Safe | Risky |
| --- | --- | --- |
| React/Vue/Svelte | `{value}`, `{{ value }}` | `dangerouslySetInnerHTML`, `v-html`, `{@html}` without DOMPurify |
| DOM | `el.textContent = v`, `setAttribute` for safe attrs | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` |
| Jinja2/Django | `{{ v }}` (autoescape on) | `|safe`, `mark_safe`, `Markup`, `{% autoescape false %}` |
| Blade/Twig | `{{ $v }}` / `{{ v }}` | `{!! $v !!}` / `|raw` |
| PHP | `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')`, WordPress `esc_html`, `esc_attr`, `esc_url` | `echo $v` |
| Go | `html/template` | `text/template` for HTML, `template.HTML(v)` |
| Rails ERB | `<%= v %>` | `raw`, `.html_safe`, `<%==` |

URLs in `href`/`src`: allow only `https:`/`http:`/relative (block `javascript:`). Data placed in
`<script>` blocks: serialise as JSON with the framework helper (`json_script`, `@json`).
Rich text: `DOMPurify.sanitize(html)` (browser) or a server-side allow-list sanitizer
(for example `nh3` for Python, `HTMLPurifier` for PHP, `sanitize-html` for Node).

## SSRF

Rule: decide where the server is allowed to connect, then check every request against it.

1. Allow-list schemes (`https`) and, where possible, hosts.
2. Resolve the hostname and reject private, loopback, link-local (169.254.0.0/16 including
   cloud metadata), multicast and reserved ranges for IPv4 and IPv6; connect to the checked IP
   to avoid DNS rebinding.
3. Disable redirects or re-validate each hop; set short timeouts and a response size limit.
4. Run URL fetchers in a network segment without access to internal services; on cloud VMs
   require IMDSv2 / metadata hop limits.

```python
import ipaddress, socket
from urllib.parse import urlsplit


def is_public_https(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return False
    for info in socket.getaddrinfo(parts.hostname, parts.port or 443):
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return False
    return True
```

## Path traversal

Rule: never build file paths from raw input. Map ids to files, or resolve and verify the
result stays inside the base directory.

```python
base = Path("/srv/uploads").resolve()
target = (base / name).resolve()
if not target.is_relative_to(base):  # Python 3.9+
    abort(404)
```
```js
const base = path.resolve("/srv/uploads");
const target = path.resolve(base, name);
if (!target.startsWith(base + path.sep)) return res.sendStatus(404);
res.sendFile(target);                       // or res.sendFile(name, { root: base })
```
```php
$base = realpath('/srv/uploads');
$target = realpath($base . '/' . basename($name));
if ($target === false || strpos($target, $base . DIRECTORY_SEPARATOR) !== 0) { http_response_code(404); exit; }
```
```go
root, _ := os.OpenRoot("/srv/uploads")   // Go 1.24+: confines access to the directory
f, err := root.Open(name)
```

Uploads: generate the stored file name yourself (UUID), keep the original name only as data,
check type by content, store outside the web root. Archives: check each entry path before
extracting (zip slip).

## Open redirect

Allow only relative paths (starting with a single `/`, not `//` or `/\`) or an allow-list of
hosts. Frameworks: Django `url_has_allowed_host_and_scheme`, WordPress `wp_safe_redirect`,
Rails 7 `redirect_to` raises on other hosts unless `allow_other_host: true`.

## Deserialization and code execution

- Never unpickle, `unserialize`, Java-deserialize or `Marshal.load` data from outside. Use JSON
  plus schema validation (pydantic, zod, JSON Schema).
- YAML: `yaml.safe_load` (Python), `YAML.safe_load` (Ruby), `js-yaml` `load` with the default
  schema in v4+.
- PHP `unserialize($s, ['allowed_classes' => false])` only for data you produced.
- Replace `eval`/`new Function`/`exec` with lookup tables or a real parser.

## XXE

Disable DTDs and external entities: Python `defusedxml`; Java
`factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`; PHP: do
not pass `LIBXML_NOENT`/`LIBXML_DTDLOAD`; .NET `DtdProcessing.Prohibit`.

## Validation at the boundary

- Parse into types early (int, UUID, enum, date) and reject the rest with 400.
- Allow-lists over blocklists; length limits on every string; normalise Unicode before
  comparison if identifiers are compared.
- Libraries: pydantic / marshmallow (Python), zod / joi (Node), Laravel validation, Bean
  Validation (Java), `go-playground/validator`, Rails strong parameters.
