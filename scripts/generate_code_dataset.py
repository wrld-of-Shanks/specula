import csv
import random
import os

from _paths import data_path

random.seed(42)

def gen_sql_injection():
    tables = ['users', 'products', 'orders', 'accounts', 'sessions', 'payments', 'admins', 'items', 'customers', 'employees']
    cols = ['id', 'name', 'email', 'password', 'balance', 'status', 'role', 'token', 'data', 'secret']
    ops = ['SELECT', 'INSERT INTO', 'UPDATE', 'DELETE FROM']
    var_names = ['user_id', 'uid', 'input', 'search', 'query', 'param', 'value', 'term', 'name', 'filter']

    templates = []
    for t in tables:
        for c1 in random.sample(cols, 3):
            for v in random.sample(var_names, 3):
                templates.append(f'query = "SELECT {c1} FROM {t} WHERE {c1}=" + {v}')
                templates.append(f'cursor.execute("SELECT * FROM {t} WHERE {c1}=\'" + {v} + "\'")')
                templates.append(f'cursor.execute("SELECT * FROM {t} WHERE {c1}=\'" + str({v}) + "\' AND active=1")')
                templates.append(f'q = "UPDATE {t} SET {c1}=\'" + {v} + "\' WHERE id=" + str(uid)')
                templates.append(f'q = "DELETE FROM {t} WHERE {c1}=\'" + {v} + "\'"')
                templates.append(f'sql = f"SELECT * FROM {t} WHERE {c1}={{{v}}}"')
                templates.append(f'q = "`SELECT * FROM {t} WHERE {c1}=${{{v}}}`"')
    random.shuffle(templates)
    return random.choice(templates[:200])

def gen_xss():
    sinks = ['innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML', 'insertAdjacentText']
    sources = ['userInput', 'queryParameter', 'location.hash', 'location.search', 'document.referrer',
               'window.name', 'document.cookie', 'localStorage.getItem', 'sessionStorage.getItem',
               'URLSearchParams.get', 'request.body', 'req.query', 'params.id', 'searchTerm',
               'req.body.name', 'req.params.id', 'req.query.search', 'req.cookies.session',
               'data.name', 'input.value', 'prompt("Enter name")', 'argv[2]',
               'os.Args[1]', 'process.argv[2]', 'stdin.readLine()']
    elements = ['element', 'div', 'span', 'p', 'section', 'article', 'container', 'output', 'result', 'target',
                'wrapper', 'content', 'body', 'main', 'header', 'footer', 'card', 'panel', 'box', 'frame']
    
    templates = []
    for s in sinks:
        for src in sources:
            for el in elements:
                if s == 'document.write':
                    templates.append(f'document.write({src})')
                    templates.append(f'document.write("<div>" + {src} + "</div>")')
                    templates.append(f'document.write("<p>" + decodeURIComponent({src}) + "</p>")')
                elif s == 'innerHTML':
                    templates.append(f'{el}.innerHTML = {src}')
                    templates.append(f'{el}.innerHTML = "<p>" + {src} + "</p>"')
                    templates.append(f'{el}.innerHTML = `<h1>${{{src}}}</h1>`')
                    templates.append(f'{el}.innerHTML = "<div class=\\"card\\">" + {src} + "</div>"')
                elif s == 'outerHTML':
                    templates.append(f'{el}.outerHTML = {src}')
                    templates.append(f'{el}.outerHTML = "<span>" + {src} + "</span>"')
                elif s == 'insertAdjacentHTML':
                    templates.append(f'{el}.insertAdjacentHTML("beforeend", {src})')
                    templates.append(f'{el}.insertAdjacentHTML("afterbegin", {src})')
    
    templates.extend([
        '$("#output").html(userInput)',
        '$("#result").append(queryString["data"])',
        '$(".content").html(decodeURIComponent(location.hash.substr(1)))',
        'eval(location.search.substring(6))',
        'eval(atob(queryString["d"]))',
        'eval(argv[0])',
        'setTimeout(userInput, 1000)',
        'setInterval(userInput, 5000)',
        'new Function("return " + userInput)()',
        'element.setAttribute("onclick", handler + "(\'" + data + "\')")',
        'element.setAttribute("onmouseover", userInput)',
        '<div dangerouslySetInnerHTML={{__html: props.content}} />',
        'ReactDOM.render(React.createElement("div", {dangerouslySetInnerHTML: {__html: userInput}}))',
        'renderToString(userComponent)',
        'el.insertAdjacentHTML("beforeend", "<li>" + itemName + "</li>")',
        'el.insertAdjacentHTML("afterend", "<div>" + extraContent + "</div>")',
        'document.documentElement.innerHTML = styles',
        'document.body.innerHTML = pageContent',
        'window.document.write(script)',
    ])
    random.shuffle(templates)
    return random.choice(templates[:300])

def gen_hardcoded_creds():
    prefixes = ['API_KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'PASS', 'AWS_SECRET', 'DB_PASSWORD',
                'REDIS_PASSWORD', 'MONGO_PASSWORD', 'JWT_SECRET', 'SIGNING_KEY', 'ENCRYPTION_KEY',
                'PRIVATE_KEY', 'ACCESS_TOKEN', 'CLIENT_SECRET', 'WEBHOOK_SECRET', 'STRIPE_KEY']
    values = [
        'sk-1234567890abcdef1234567890abcdef',
        'mysecretkey123',
        'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'ghp_placeholder_token_xxxxx',
        'admin123',
        'root',
        'changeme',
        'mongodb://admin:password@localhost:27017/prod',
        'postgres://user:secret@db-host:5432/myapp',
        'redis://:mypassword@redis-server:6379',
        'super-secret-jwt-signing-key',
        'SLACK-BOT-TOKEN-PLACEHOLDER',
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
        'AKIA0000000000000000',
        '-----BEGIN EXAMPLE PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2y',
        'password123',
        'letmein',
        'admin',
        'passw0rd',
        '12345678',
    ]
    templates = []
    for p in prefixes[:10]:
        for v in values[:8]:
            templates.append(f'{p} = "{v}"')
            templates.append(f'const {p.lower()} = "{v}"')
            templates.append(f'{p.lower()} = os.environ.get("{p}", "{v}")')
    random.shuffle(templates)
    return random.choice(templates[:80])

def gen_command_injection():
    cmds = ['ping', 'curl', 'wget', 'ls', 'cat', 'grep', 'find', 'convert', 'ffmpeg', 'tar', 'cp', 'mv', 'rm']
    var_names = ['host', 'url', 'filename', 'inputFile', 'target', 'endpoint', 'path', 'command', 'query', 'ip']
    shells = ['os.system', 'os.popen', 'subprocess.call', 'subprocess.run', 'subprocess.check_output']
    
    templates = []
    for cmd in cmds[:6]:
        for v in var_names[:5]:
            for sh in shells[:3]:
                templates.append(f'{sh}("{cmd} " + {v}, shell=True)')
                templates.append(f'{sh}("{cmd} " + str({v}))')
                templates.append(f'{sh}(f"{cmd} {{{v}}}", shell=True)')
    templates.extend([
        'exec(userProvidedCode)',
        'eval(queryString["expr"])',
        'compile(userInput, "<string>", "exec")',
        'os.system("echo " + msg + " | mail -s alert " + email)',
        'os.system("export TOKEN=" + token + " && ./deploy.sh")',
    ])
    random.shuffle(templates)
    return random.choice(templates[:100])

def gen_path_traversal():
    bases = ['/var/www/uploads', '/static', '/backups', '/data', '/files', '/reports', '/logs', '/shares', '/etc/app', '/tmp']
    var_names = ['filename', 'assetPath', 'backupDate', 'userPath', 'fileName', 'filePath', 'reportId', 'logFile', 'shareName', 'configName']
    funcs = ['open', 'readFile', 'readFileSync', 'os.listdir', 'fs.readdirSync', 'shutil.copy']
    
    templates = []
    for base in bases[:6]:
        for v in var_names[:6]:
            for fn in funcs[:3]:
                if 'read' in fn.lower() or fn == 'open':
                    templates.append(f'{fn}("{base}/" + {v})')
                    templates.append(f'{fn}("{base}/" + str({v}))')
                elif 'list' in fn.lower() or 'readdir' in fn.lower():
                    templates.append(f'{fn}("{base}/" + {v})')
                elif 'copy' in fn.lower():
                    templates.append(f'{fn}("{base}/" + {v}, "/tmp/output")')
    templates.extend([
        'open(os.path.join(base_dir, user_path))',
        'fs.readFileSync(path.join(uploadDir, fileName))',
        'open("/files/" + urllib.parse.unquote(request.args["file"]))',
        'readFile("/data/" + decodeURIComponent(urlParam))',
        'shutil.copy("/uploads/" + userInput, "/tmp/output")',
        'open("../../" + relativePath)',
    ])
    random.shuffle(templates)
    return random.choice(templates[:100])

def gen_insecure_deserialization():
    sinks = ['pickle.loads', 'pickle.load', 'jsonpickle.decode', 'yaml.load',
             'yaml.unsafe_load', 'objectinputstream.readObject', 'marshal.loads',
             'eval(pickle.loads', 'StringIO(pickle.load']
    sources = ['request.data', 'req.body.payload', 'userInput', 'base64decoded',
               'untrusted_bytes', 'incoming_payload', 'data_blob', 'rawInput']
    templates = []
    for s in sinks:
        for src in sources:
            templates.append(f'{s}({src})')
            templates.append(f'data = {s}(base64.b64decode({src}))')
            templates.append(f'obj = {s}(unpickle_bytes({src}))')
    templates.extend([
        'yaml.load(user_input, Loader=yaml.Loader)',
        'yaml.unsafe_load(incoming_yaml)',
        'obj = jsonpickle.decode(request.get_data())',
        'data = pickle.loads(untrusted_request)',
        'serialized = base64.b64decode(url_param); obj = pickle.loads(serialized)',
        'try: obj = pickle.loads(payload)\nexcept Exception: pass',
        'from io import BytesIO; resource = pickle.load(BytesIO(stream))',
        "o = loads(zlib.decompress(request.body))",
        'node = const unpack; unpack(payload)',
        'objectInputStream.readObject()',
    ])
    random.shuffle(templates)
    return random.choice(templates[:160])

def gen_not_vulnerable():
    templates = []
    # Parameterized queries
    for driver in ['cursor.execute', 'db.query', 'db.execute', 'session.query', 'conn.execute',
                    'pool.query', 'client.execute', 'stmt.execute', 'preparedStatement.execute']:
        for pattern in ['%s', '$1', '?', ':param', '{0}', '%(name)s', ':id', '?1']:
            templates.append(f'{driver}("SELECT * FROM users WHERE id={pattern}", (user_id,))')
            templates.append(f'{driver}("SELECT * FROM users WHERE id={pattern}", [user_id])')
            templates.append(f'{driver}("SELECT * FROM users WHERE id={pattern}", user_id)')
            templates.append(f'{driver}("INSERT INTO logs (msg) VALUES ({pattern})", (message,))')
            templates.append(f'{driver}("UPDATE users SET name={pattern} WHERE id={pattern}", (new_name, uid))')
    # Safe DOM
    for el in ['element', 'div', 'span', 'output', 'container', 'wrapper', 'panel', 'card', 'frame', 'section']:
        templates.append(f'{el}.textContent = userInput')
        templates.append(f'{el}.innerText = safeValue')
        templates.append(f'{el}.setAttribute("href", sanitizedUrl)')
        templates.append(f'{el}.setAttribute("src", validatedSrc)')
        templates.append(f'{el}.setAttribute("action", safeAction)')
        templates.append(f'{el}.className = sanitizedClassName')
        templates.append(f'{el}.style.cssText = validatedStyle')
        templates.append(f'{el}.dataset.value = cleanData')
    # Escaping
    templates.extend([
        'html.escape(userInput)',
        'bleach.clean(userContent)',
        'DOMPurify.sanitize(rawHtml)',
        'escapeHtml(userInput)',
        'markupsafe.escape(userInput)',
        'sanitize_html(userContent)',
        'xss.escape(userInput)',
        'HtmlSanitizer.sanitize(userInput)',
        'strip_tags(userInput)',
        'cgi.escape(userInput)',
    ])
    # Safe file ops
    for base in ['/uploads', '/static', '/data', '/files', '/reports', '/backups', '/logs', '/shares']:
        templates.append(f'os.path.join("{base}", os.path.basename(filename))')
        templates.append(f'path.join("{base}", path.basename(userFile))')
        templates.append(f'os.path.abspath(os.path.join("{base}", os.path.normpath(userFile)))')
    # Safe subprocess
    templates.extend([
        'subprocess.run(["ls", directory], shell=False)',
        'subprocess.run(["grep", pattern, filepath], capture_output=True)',
        'os.execvp("python3", ["python3", "-c", validatedScript])',
        'subprocess.Popen([cmd, arg1, arg2], shell=False)',
        'subprocess.call(["python3", script_path], shell=False)',
        'os.execv("/usr/bin/python3", ["python3", validated_script])',
    ])
    # Type casting
    templates.extend([
        'user_id = int(request.args["id"])',
        'amount = float(sanitized_amount)',
        'page = max(1, int(page_num))',
        'limit = min(100, max(1, int(limit_param)))',
        'offset = abs(int(offset_param))',
    ])
    # Env vars
    templates.extend([
        'db_password = os.environ.get("DB_PASS")',
        'api_key = os.getenv("API_KEY")',
        'secret = config["SECRET_KEY"]',
        'token = os.environ["AUTH_TOKEN"]',
        'db_url = os.environ.get("DATABASE_URL")',
    ])
    # Safe JSON
    templates.extend([
        'json.dumps(safe_data)',
        'json.loads(validated_input)',
        'orjson.dumps(clean_data)',
        'ujson.dumps(safe_result)',
    ])
    # Logging
    templates.extend([
        'logger.info(f"User {safe_uid} performed action")',
        'logging.debug("Request from %s", safe_ip)',
        'print("Result:", json.dumps(safe_result))',
    ])
    # Validation
    templates.extend([
        'if not re.match("^[a-zA-Z0-9_]+$", username): raise ValueError()',
        'if not email.endswith("@company.com"): raise ValueError()',
        'if amount < 0 or amount > 1000000: raise ValueError()',
        'if not uuid.is_valid(token): raise ValueError()',
        'validated = sanitizer.sanitize(raw_input)',
    ])
    random.shuffle(templates)
    return random.choice(templates[:500])

generators = {
    'sql_injection': gen_sql_injection,
    'xss': gen_xss,
    'hardcoded_credentials': gen_hardcoded_creds,
    'command_injection': gen_command_injection,
    'path_traversal': gen_path_traversal,
    'insecure_deserialization': gen_insecure_deserialization,
    'not_vulnerable': gen_not_vulnerable,
}

output_path = data_path('code', 'cve_dataset.csv')

rows = []
samples_per_class = 1500
for label, gen_func in generators.items():
    seen = set()
    count = 0
    attempts = 0
    while count < samples_per_class and attempts < samples_per_class * 5:
        code = gen_func()
        if code not in seen:
            seen.add(code)
            rows.append({'code': code, 'label': label})
            count += 1
        attempts += 1

random.shuffle(rows)

with open(output_path, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['code', 'label'])
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated {len(rows)} samples")
for label in generators:
    count = sum(1 for r in rows if r['label'] == label)
    print(f"  {label}: {count}")
