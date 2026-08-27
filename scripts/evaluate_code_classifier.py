#!/usr/bin/env python3
"""
Evaluate the Specula code vulnerability classifier on real-world data.

Tests:
1. Rule-based classifier on diverse vulnerable/safe code samples
2. Context-aware claims: parameterized vs string-concatenated SQL
"""

import sys
import os
import json
import re
from collections import defaultdict, Counter
from typing import List, Dict, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'code'))
from models.rule_classifier import RuleBasedClassifier, VULNERABILITY_CLASSES, CWE_MAPPING

# ---------------------------------------------------------------------------
# Test data: real-world inspired code samples
# ---------------------------------------------------------------------------

SQL_INJECTION_SAMPLES = [
    # Python
    'query = "SELECT * FROM users WHERE id = " + user_id',
    'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
    'db.execute(f"DELETE FROM orders WHERE order_id = {order_id}")',
    'query = "INSERT INTO logs (msg) VALUES (\'%s\')" % message',
    'sql = "UPDATE accounts SET balance = %s WHERE id = %s" % (amt, uid)',
    'cursor.execute("SELECT * FROM products WHERE search = \'" + search_term + "\' ORDER BY name")',
    'db.query("DELETE FROM sessions WHERE token = \'" + token + "\'")',
    'q = "SELECT * FROM orders WHERE user_id = " + str(user["id"])',
    'cursor.execute("INSERT INTO audit (action) VALUES (\'%s\')" % action)',
    'query = "SELECT password FROM admins WHERE username = \'" + username + "\'"',
    'db.execute("UPDATE users SET email = \'" + new_email + "\' WHERE id = " + str(uid))',
    'sql = "SELECT * FROM comments WHERE post_id = " + request.args["pid"]',
    'cursor.execute("DELETE FROM temp WHERE session = \'" + sid + "\'")',
    'q = "SELECT * FROM payments WHERE amount > " + str(min_amount)',
    'db.execute("INSERT INTO feedback (text) VALUES (\'%s\')" % feedback)',
    'query = "SELECT * FROM items WHERE category = \'" + cat + "\' AND status = \'" + status + "\'"',
    'cursor.execute("UPDATE inventory SET qty = qty - " + str(count) + " WHERE id = " + str(item_id))',
    'sql = "SELECT * FROM messages WHERE sender = \'" + user + "\' OR receiver = \'" + user + "\'"',
    'db.query("DELETE FROM notifications WHERE user_id = " + str(user_id) + " AND read = false")',
    'cursor.execute("INSERT INTO analytics (event, data) VALUES (\'%s\', \'%s\')" % (event, data))',
    # Java
    'String q = "SELECT * FROM users WHERE id=" + userId;',
    'stmt.executeQuery("SELECT * FROM orders WHERE name=\'" + name + "\'");',
    'PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE c=" + val);',
    'String sql = "DELETE FROM logs WHERE date < \'" + dateStr + "\'";',
    'Statement st = conn.createStatement(); st.executeUpdate("UPDATE users SET role=\'" + role + "\' WHERE id=" + uid);',
    # PHP
    '$result = mysqli_query($conn, "SELECT * FROM users WHERE id=" . $_GET["id"]);',
    '$q = "SELECT * FROM products WHERE name=\'" . $_POST["name"] . "\'";',
    'mysqli_query($conn, "DELETE FROM cart WHERE session=\'" . $sid . "\'");',
    '$sql = "UPDATE users SET email=\'" . $email . "\' WHERE id=" . $uid;',
    # JavaScript/Node
    'db.query("SELECT * FROM users WHERE id=" + req.params.id)',
    'connection.query("SELECT * FROM orders WHERE name=\'" + name + "\'", callback)',
    'pool.query("DELETE FROM sessions WHERE token=\'" + token + "\'")',
    'const q = `SELECT * FROM products WHERE search=\'${searchTerm}\'`',
    'db.execute(`UPDATE accounts SET balance=${balance} WHERE id=${accountId}`)',
    # Ruby
    'User.where("name = \'" + params[:name] + "\'").first',
    'ActiveRecord::Base.connection.execute("DELETE FROM logs WHERE id=" + log_id.to_s)',
    # Go
    'db.Query("SELECT * FROM users WHERE name=\'" + name + "\'")',
    'db.Exec("DELETE FROM orders WHERE id=" + orderId)',
    # Multiple lines
    '''
username = request.form['username']
password = request.form['password']
query = "SELECT * FROM users WHERE username = \'" + username + "\' AND password = \'" + password + "\'"
cursor.execute(query)
    ''',
    '''
search = request.args.get('q')
sql = "SELECT * FROM products WHERE name LIKE '%" + search + "%' OR description LIKE '%" + search + "%'"
results = db.execute(sql)
    ''',
    '''
user_id = get_user_id()
name = get_name()
db.execute("UPDATE users SET name='" + name + "' WHERE id=" + str(user_id))
    ''',
    'query = "SELECT * FROM customers WHERE country = \'" + request.json["country"] + "\'"',
    'cursor.execute("INSERT INTO audit_log (user_id, action) VALUES (" + str(uid) + ", \'" + action + "\')")',
    'db.execute("SELECT * FROM employees WHERE dept = \'" + dept + "\' AND salary > " + str(min_sal))',
    'q = "SELECT * FROM tickets WHERE status = \'" + status + "\' ORDER BY " + sort_by',
    'sql = "SELECT * FROM logs WHERE message LIKE \'" + pattern + "\' AND level = " + str(level)',
    'cursor.execute("DELETE FROM cache WHERE key = \'" + cache_key + "\'")',
    'query = "UPDATE products SET price = " + str(new_price) + " WHERE id = " + str(product_id)',
    'db.query("INSERT INTO events (type, payload) VALUES (\'" + event_type + "\', \'" + payload + "\')")',
    'cursor.execute("SELECT * FROM forum WHERE author = \'" + author + "\' AND tags LIKE \'" + tag + "\'")',
]

SAFE_SQL_SAMPLES = [
    # Parameterized queries
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    'db.execute("SELECT * FROM users WHERE name = %s AND email = %s", (name, email))',
    'query = "SELECT * FROM orders WHERE user_id = ?"',
    'cursor.execute(query, [user_id])',
    'db.execute("INSERT INTO logs (message, level) VALUES (%s, %s)", (msg, level))',
    'stmt = "UPDATE users SET name = %s WHERE id = %s"',
    'cursor.execute(stmt, (new_name, uid))',
    'db.execute("DELETE FROM sessions WHERE token = %s", (token,))',
    'cursor.execute("SELECT * FROM products WHERE category = %s ORDER BY name", (category,))',
    'q = "SELECT * FROM payments WHERE amount > %s AND status = %s"',
    'cursor.execute(q, (min_amount, "completed"))',
    # Java parameterized
    'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, userId);',
    'String q = "SELECT * FROM orders WHERE name = ?"; ps.setString(1, name);',
    'stmt.executeQuery("SELECT * FROM t WHERE c = ? AND d = ?", val, val2);',
    'PreparedStatement del = conn.prepareStatement("DELETE FROM logs WHERE id = ?"); del.setInt(1, id);',
    'String upd = "UPDATE users SET role = ? WHERE id = ?"; ps.setString(1, role); ps.setInt(2, uid);',
    # PHP PDO
    '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id"); $stmt->execute([":id" => $id]);',
    '$q = $pdo->prepare("SELECT * FROM products WHERE name = :name"); $q->execute(["name" => $_POST["name"]]);',
    '$stmt = $pdo->prepare("DELETE FROM cart WHERE session = :sid"); $stmt->execute(["sid" => $sid]);',
    # JS parameterized
    'db.query("SELECT * FROM users WHERE id = $1", [userId])',
    'pool.query("SELECT * FROM orders WHERE name = $1", [name])',
    'connection.query("DELETE FROM sessions WHERE token = ?", [token])',
    # Ruby AR
    'User.where(id: user_id).first',
    'Order.where("name = ?", params[:name]).first',
    # Go
    'db.Query("SELECT * FROM users WHERE id = $1", userId)',
    'db.Exec("DELETE FROM orders WHERE id = $1", orderId)',
    # Multi-line safe
    '''
username = request.form['username']
password = request.form['password']
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
    ''',
    '''
search = request.args.get('q')
query = "SELECT * FROM products WHERE name LIKE %s"
results = db.execute(query, ('%' + search + '%',))
    ''',
    # SQLAlchemy ORM
    'session.query(User).filter(User.id == user_id).first()',
    'db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})',
    'User.query.filter_by(username=username).first()',
    'Product.query.filter(Product.category == category).order_by(Product.name).all()',
]

XSS_SAMPLES = [
    'res.send(`<h1>Hello ${username}</h1>`)',
    'res.send("<div>" + userInput + "</div>")',
    'res.write("<p>" + comment + "</p>")',
    'document.getElementById("output").innerHTML = "Hello " + name;',
    'document.writeln("<img src=" + url + ">")',
    '$("div").html("<span>" + data + "</span>");',
    'el.innerHTML = "<a href=\'" + link + "\'>Click</a>";',
    'res.send("<script>var x = \'" + val + "\';</script>")',
    'element.innerHTML = "<div>" + response.body + "</div>";',
    'document.body.innerHTML += "<iframe src=\'" + iframeSrc + "\'></iframe>";',
    '$("#result").html("<pre>" + code + "</pre>");',
    'res.write("<td>" + cellData + "</td>");',
    'el.innerHTML = template + userInput;',
    'res.send("<h2>Results: " + count + "</h2>");',
    'document.getElementById("name").innerHTML = "Welcome, " + username + "!";',
    'output.innerHTML = "<img src=\\"" + userUrl + "\\">";',
    'res.write("<li>" + item.title + "</li>");',
    'element.outerHTML = "<div class=\'alert\'>" + message + "</div>";',
    'res.send(`The value is: ${param}`);',
    'document.write("<option value=\'" + val + "\'>" + label + "</option>");',
]

SAFE_XSS_SAMPLES = [
    'res.send("<h1>Hello World</h1>");',
    'element.textContent = "Hello " + name;',
    'element.innerText = "Hello " + name;',
    'res.send(DOMPurify.sanitize("<div>" + userInput + "</div>"));',
    'res.send(htmlEscape("<div>" + name + "</div>"));',
    'element.textContent = userInput;',
    'res.send(encodeURI(url));',
    'res.send(sanitize("<span>" + data + "</span>"));',
    'element.textContent = "Results: " + count;',
    'res.send("<p>Static content</p>");',
    'res.send(escape(userInput));',
    'el.innerText = "Hello";',
    'document.getElementById("out").textContent = value;',
    'res.send(htmlEscape.encode("<div>" + msg + "</div>"));',
    'res.send(mustache.render(template, {name: escape(name)}));',
    'el.textContent = DOMPurify.sanitize(rawHtml);',
    'res.send("<pre>" + escape(code) + "</pre>");',
    'res.send(encodeHTML("<span>" + input + "</span>"));',
    'element.innerText = "No XSS here";',
    'res.send(sanitizeHTML("<div>" + content + "</div>"));',
]

CMD_INJECTION_SAMPLES = [
    'os.system("ping " + host)',
    'os.system(f"ping {host}")',
    'os.system("echo " + msg)',
    'os.popen("ls " + directory)',
    'os.popen(f"cat {filename}")',
    'os.system("grep " + pattern + " " + filename)',
    'os.popen("wget " + url)',
    'os.system("curl " + api_url + " -o " + output)',
    'os.system("python " + script_path + " --arg " + arg)',
    'os.popen("tar -xzf " + archive + " -C " + dest)',
    'subprocess.call("rm -rf " + path)',
    'subprocess.Popen("cat " + filename)',
    'os.system("chmod " + permissions + " " + file)',
    'os.system("mkdir " + dirname)',
    'os.popen("find " + search_path + " -name " + pattern)',
    'os.system("kill " + str(pid))',
    'os.system("mv " + src + " " + dst)',
    'os.popen("convert " + input_file + " " + output_file)',
    'os.system("ffmpeg -i " + video_path + " " + out_path)',
    'os.system("docker run " + image_name + " " + cmd)',
]

SAFE_CMD_SAMPLES = [
    'subprocess.run(["ping", host])',
    'subprocess.run(["ls", directory], capture_output=True)',
    'subprocess.call(["cat", filename])',
    'os.system("ls -la")',
    'subprocess.Popen(["grep", pattern, filename])',
    'os.system("ls")',
    'subprocess.run(["wget", url], check=True)',
    'subprocess.run(["python", script_path, "--arg", arg])',
    'subprocess.Popen(["tar", "-xzf", archive, "-C", dest])',
    'os.system("echo hello")',
    'subprocess.call(["chmod", permissions, file])',
    'subprocess.run(["mkdir", dirname])',
    'subprocess.run(["find", search_path, "-name", pattern])',
    'subprocess.run(["kill", str(pid)])',
    'subprocess.call(["mv", src, dst])',
    'subprocess.run(["convert", input_file, output_file])',
    'os.system("ffmpeg -i input.mp4 output.mp3")',
    'subprocess.Popen(["docker", "run", image_name])',
    'subprocess.run(["cp", src, dst], check=True)',
    'os.system("pwd")',
]

PATH_TRAVERSAL_SAMPLES = [
    'open(request.args["file"])',
    'readFile(req.query.path)',
    'fs.readFileSync(req.params.filename)',
    'path.join(base_dir, req.query.file)',
    'sendFile(req.query.path)',
    'open(upload_dir + "/" + filename)',
    'path.join("/uploads", request.form["file"])',
    'fs.readFile(req.body.path, callback)',
    'path.join(static_dir, req.params.file)',
    'open(req.query["filename"])',
    'fs.readFileSync("data/" + req.params.id)',
    'path.join(uploadDir, request.params.name)',
    'sendFile(req.body.filePath)',
    'path.join(baseDir, fileName)',
    'open(os.path.join(upload_dir, request.args.get("file")))',
    'fs.readFileSync(req.query["file_path"])',
    'path.join(dataDir, request.params["filename"])',
    'sendFile(path.join(publicDir, req.query.path))',
    'open(req.params["filename"], "r")',
    'fs.readFileSync(req.body["file"])',
]

SAFE_PATH_SAMPLES = [
    'open("data/safe.txt")',
    'fs.readFileSync("data/default.txt")',
    'path.join(base_dir, "static", "index.html")',
    'sendFile("uploads/" + "photo.jpg")',
    'readFile("/absolute/safe/path")',
    'open(os.path.join(base_dir, "config.ini"))',
    'fs.readFileSync(path.join(__dirname, "config.json"))',
    'path.join("public", "images", "logo.png")',
    'sendFile("default.html")',
    'open(req.query.file.normalize())',
    'path.join(uploadDir, filename).realpath()',
    'fs.readFileSync(path.join(base, "templates", name))',
    'open(os.path.realpath(os.path.join(upload_dir, filename)))',
    'sendFile(path.normalize(req.query.file))',
    'path.join(base_dir, "data", file).normalize()',
    'readFile("templates/" + "index.html")',
    'fs.readFileSync(path.resolve("data", "config.json"))',
    'open(os.path.abspath(os.path.join(basedir, "data", fname)))',
    'path.join("/var", "log", "app.log")',
    'fs.readFileSync("public/index.html")',
]

HARDCODED_CRED_SAMPLES = [
    'password = "supersecretpassword123"',
    'DB_PASSWORD = "admin123"',
    'api_key = "sk-1234567890abcdef"',
    'secret = "my_secret_key_12345678"',
    'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    'GITHUB_TOKEN = "ghp_placeholder_token_xxxxx"',
    'SLACK_TOKEN = "SLACK-BOT-TOKEN-PLACEHOLDER"',
    'private_key = "-----BEGIN EXAMPLE PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA..."',
    'auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"',
    'access_key = "AKIA0000000000000000"',
    'STRIPE_SECRET_KEY = "stripe-test-key-xxxxxxxxxxxx"',
    'password = "root"',
    'passwd = "toor123"',
    'pwd = "admin12345"',
    'secret_key = "0123456789abcdef0123456789abcdef"',
    'database_password = "mypassword123!"',
    'MYSQL_ROOT_PASSWORD = "password123"',
    'REDIS_PASSWORD = "redis_secret_pass"',
    'LDAP_BIND_PASSWORD = "ldap_admin_pass"',
    'SMTP_PASSWORD = "email_password123"',
    'COOKIE_SECRET = "super_secret_cookie_key"',
    'JWT_SECRET = "my_jwt_secret_key_123"',
    'ENCRYPTION_KEY = "a]b3c4d5e6f7g8h9i0j!k@l#m$n"',
    'master_key = "MASTERKEY12345678901234567890"',
    'signing_key = "SHA256_HMAC_SIGNING_KEY_ABCDEF"',
]

SAFE_CRED_SAMPLES = [
    'password = os.environ["DB_PASSWORD"]',
    'api_key = os.getenv("API_KEY")',
    'secret = config["secret_key"]',
    'DB_PASSWORD = process.env.DB_PASSWORD',
    'password = vault.secret("db/password")',
    'token = os.environ.get("GITHUB_TOKEN", "")',
    'secret = config.get("SECRET_KEY")',
    'api_key = os.getenv("API_KEY", "default")',
    'password = os.environ["MYSQL_PASSWORD"]',
    'secret = process.env.STRIPE_SECRET',
    'db_pass = vault.get("database/password")',
    'key = os.environ.get("ENCRYPTION_KEY")',
    'pwd = config["auth"]["password"]',
    'token = os.getenv("SLACK_TOKEN")',
    'secret = os.environ.get("JWT_SECRET")',
    'api_secret = config.get("api_secret")',
    'password = os.environ["LDAP_PASSWORD"]',
    'key = process.env.REDIS_PASSWORD',
    'passwd = os.getenv("SMTP_PASSWORD")',
    'secret = vault.read("secret/data/app")',
]

INSECURE_DESERIALIZATION_SAMPLES = [
    'data = pickle.loads(raw_bytes)',
    'obj = pickle.load(f)',
    'data = yaml.load(config_string)',
    'obj = marshal.loads(byte_data)',
    'db = shelve.open("database")',
    'obj = dill.loads(pickled_data)',
    'data = pickle.loads(compressed_data)',
    'obj = pickle.Unpickler(f).load()',
    'config = yaml.load(user_input)',
    'data = marshal.loads(request.data)',
    'obj = dill.loads(session_data)',
    'raw = pickle.loads(base64_decode(encoded))',
    'config = yaml.load(open("config.yml").read())',
    'data = pickle.loads(zlib.decompress(compressed))',
    'obj = pickle.loads(requests.get(url).content)',
    'template = yaml.load(template_str)',
    'state = pickle.loads(cache_value)',
    'data = marshal.loads(blob)',
    'obj = pickle.loads(encrypted_data)',
    'settings = yaml.load(user_settings)',
]

SAFE_DESERIALIZATION_SAMPLES = [
    'data = pickle.loads(raw_bytes)  # noqa: trusted source',
    'config = yaml.safe_load(config_string)',
    'obj = json.loads(data)',
    'data = json.load(f)',
    'config = yaml.safe_load(open("config.yml").read())',
    'obj = yaml.safe_load(request.data)',
    'data = json.loads(request.body.decode())',
    'settings = yaml.safe_load(template_str)',
    'config = yaml.safe_load(open(f).read())',
    'data = json.loads(response.content)',
    'obj = yaml.safe_load(base64_decode(encoded))',
    'raw = json.loads(zlib.decompress(compressed))',
    'state = yaml.safe_load(cache_value)',
    'data = json.loads(requests.get(url).text)',
    'config = json.loads(open("config.json").read())',
    'obj = yaml.safe_load(encrypted_data)',
    'template = json.loads(template_json)',
    'params = yaml.safe_load(request.form["yaml"])',
    'data = json.loads(blob.decode("utf-8"))',
    'settings = json.load(open("settings.json"))',
]

GENERIC_SAFE_SAMPLES = [
    'def add(a, b): return a + b',
    'import os; os.chdir("/tmp")',
    'x = [i**2 for i in range(10)]',
    'with open("config.json") as f: data = json.load(f)',
    'return render_template("index.html", title="Home")',
    'response = requests.get("https://api.example.com/data")',
    'app = Flask(__name__)',
    '@app.route("/health")\ndef health(): return "ok"',
    'logger.info("Request received")',
    'user = User.query.filter_by(id=user_id).first()',
    'result = sum(numbers) / len(numbers)',
    'socket.emit("message", {"text": "hello"})',
    'cache.set("key", value, timeout=300)',
    'timestamp = datetime.now().isoformat()',
    'hash_val = hashlib.sha256(data.encode()).hexdigest()',
    'sorted_items = sorted(items, key=lambda x: x["name"])',
    'thread = threading.Thread(target=worker, args=(queue,))',
    'model = Sequential([Dense(64, activation="relu")])',
    'pipeline = Pipeline([("scaler", StandardScaler()), ("clf", LogisticRegression())])',
    'return jsonify({"status": "ok", "count": len(results)})',
]


def build_test_suite():
    """Build the full test suite with labels."""
    suite = []
    for code in SQL_INJECTION_SAMPLES:
        suite.append({"code": code, "expected": "sql_injection"})
    for code in SAFE_SQL_SAMPLES:
        suite.append({"code": code, "expected": "not_vulnerable"})
    for code in XSS_SAMPLES:
        suite.append({"code": code, "expected": "xss"})
    for code in SAFE_XSS_SAMPLES:
        suite.append({"code": code, "expected": "not_vulnerable"})
    for code in CMD_INJECTION_SAMPLES:
        suite.append({"code": code, "expected": "command_injection"})
    for code in SAFE_CMD_SAMPLES:
        suite.append({"code": code, "expected": "not_vulnerable"})
    for code in PATH_TRAVERSAL_SAMPLES:
        suite.append({"code": code, "expected": "path_traversal"})
    for code in SAFE_PATH_SAMPLES:
        suite.append({"code": code, "expected": "not_vulnerable"})
    for code in HARDCODED_CRED_SAMPLES:
        suite.append({"code": code, "expected": "hardcoded_credentials"})
    for code in SAFE_CRED_SAMPLES:
        suite.append({"code": code, "expected": "not_vulnerable"})
    for code in INSECURE_DESERIALIZATION_SAMPLES:
        suite.append({"code": code, "expected": "insecure_deserialization"})
    for code in SAFE_DESERIALIZATION_SAMPLES:
        suite.append({"code": code, "expected": "not_vulnerable"})
    for code in GENERIC_SAFE_SAMPLES:
        suite.append({"code": code, "expected": "not_vulnerable"})
    return suite


def compute_metrics(y_true: List[str], y_pred: List[str], classes: List[str]):
    """Compute per-class precision, recall, F1, and confusion matrix."""
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)
    tn = defaultdict(int)
    conf_matrix = defaultdict(lambda: defaultdict(int))

    for true, pred in zip(y_true, y_pred):
        conf_matrix[true][pred] += 1
        if true == pred:
            tp[true] += 1
        else:
            fn[true] += 1
            fp[pred] += 1

    for cls in classes:
        for other in classes:
            if cls not in conf_matrix or other not in conf_matrix[cls]:
                conf_matrix[cls][other] = 0

    metrics = {}
    for cls in classes:
        p = tp[cls] / (tp[cls] + fp[cls]) if (tp[cls] + fp[cls]) > 0 else 0.0
        r = tp[cls] / (tp[cls] + fn[cls]) if (tp[cls] + fn[cls]) > 0 else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
        metrics[cls] = {"precision": p, "recall": r, "f1": f1,
                        "support": tp[cls] + fn[cls]}

    total_true_neg = defaultdict(int)
    for cls in classes:
        for other in classes:
            if other != cls:
                total_true_neg[cls] += tp[other]
        total_true_neg[cls] -= tp.get(cls, 0)
        for other in classes:
            if other != cls and other != true:
                pass

    return metrics, conf_matrix, dict(fp), dict(fn), dict(tp)


def print_confusion_matrix(conf_matrix, classes):
    """Print a formatted confusion matrix."""
    class_abbrevs = {
        "not_vulnerable": "SAFE",
        "sql_injection": "SQLi",
        "xss": "XSS",
        "hardcoded_credentials": "CRDS",
        "command_injection": "CMDi",
        "path_traversal": "PTRV",
        "insecure_deserialization": "DESER",
    }
    abbrs = [class_abbrevs.get(c, c[:5]) for c in classes]
    max_label = max(len(a) for a in abbrs)

    header = " " * (max_label + 2) + "  ".join(f"{a:>{max_label}}" for a in abbrs)
    print(header)
    print("-" * len(header))
    for true_cls in classes:
        row = f"{class_abbrevs.get(true_cls, true_cls[:5]):<{max_label}}  "
        vals = []
        for pred_cls in classes:
            count = conf_matrix[true_cls][pred_cls]
            vals.append(f"{count:>{max_label}}")
        row += "  ".join(vals)
        print(row)


def run_context_aware_tests(classifier):
    """Test the context-aware SQL injection claims."""
    print("\n" + "=" * 70)
    print("CONTEXT-AWARE SQL INJECTION TEST")
    print("=" * 70)

    param_queries = [
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        'db.execute("SELECT * FROM users WHERE name = %s", (name,))',
        'db.execute("INSERT INTO logs (msg) VALUES (%s)", (message,))',
        'cursor.execute("UPDATE users SET email = %s WHERE id = %s", (email, uid))',
        'db.execute("DELETE FROM sessions WHERE token = %s", (token,))',
        'cursor.execute("SELECT * FROM products WHERE category = %s", (cat,))',
        'db.execute("INSERT INTO audit (action, uid) VALUES (%s, %s)", (action, uid))',
        'cursor.execute("UPDATE orders SET status = %s WHERE id = %s", (status, oid))',
        'db.execute("SELECT * FROM payments WHERE amount > %s", (min_amt,))',
        'cursor.execute("DELETE FROM cache WHERE key = %s", (key,))',
        'ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, id);',
        'stmt = conn.prepareStatement("SELECT * FROM t WHERE c = ?");',
        'String q = "SELECT * FROM orders WHERE name = ?"; ps.setString(1, name);',
        '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");',
        'db.query("SELECT * FROM users WHERE id = $1", [userId])',
        'pool.query("SELECT * FROM orders WHERE name = $1", [name])',
        'User.where(id: user_id).first',
        'db.Query("SELECT * FROM users WHERE id = $1", userId)',
        'session.query(User).filter(User.id == user_id).first()',
        'User.query.filter_by(username=username).first()',
    ]

    concat_queries = [
        'query = "SELECT * FROM users WHERE id = " + user_id',
        'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
        'db.execute(f"DELETE FROM orders WHERE order_id = {order_id}")',
        'query = "INSERT INTO logs (msg) VALUES (\'%s\')" % message',
        'cursor.execute("SELECT * FROM products WHERE search = \'" + term + "\'")',
        'sql = "UPDATE accounts SET balance = " + str(amt) + " WHERE id = " + str(uid)',
        'db.query("DELETE FROM sessions WHERE token = \'" + token + "\'")',
        'q = "SELECT * FROM orders WHERE user_id = " + str(user["id"])',
        'cursor.execute("INSERT INTO audit (action) VALUES (\'%s\')" % action)',
        'query = "SELECT * FROM admins WHERE username = \'" + username + "\'"',
        'db.execute("UPDATE users SET email = \'" + email + "\' WHERE id = " + str(uid))',
        'sql = "SELECT * FROM comments WHERE post_id = " + request.args["pid"]',
        'cursor.execute("DELETE FROM temp WHERE session = \'" + sid + "\'")',
        'q = "SELECT * FROM items WHERE category = \'" + cat + "\'"',
        'db.execute("INSERT INTO feedback (text) VALUES (\'%s\')" % feedback)',
        'query = "SELECT * FROM messages WHERE sender = \'" + user + "\'"',
        'cursor.execute("UPDATE inventory SET qty = qty - " + str(count) + " WHERE id = " + str(item_id))',
        'sql = "SELECT * FROM payments WHERE amount > " + str(min_amount)',
        'db.query("DELETE FROM notifications WHERE user_id = " + str(user_id))',
        'cursor.execute("SELECT * FROM tickets WHERE status = \'" + status + "\'")',
    ]

    param_correct = 0
    concat_correct = 0

    print(f"\n--- Parameterized Queries (should be 'not_vulnerable') ---")
    for i, code in enumerate(param_queries):
        result = classifier.classify(code)
        pred = result["prediction"]
        correct = pred == "not_vulnerable"
        param_correct += int(correct)
        status = "PASS" if correct else "FAIL"
        print(f"  [{status}] Sample {i+1:2d}: predicted={pred:25s} conf={result['confidence']:.3f}")

    print(f"\n--- String-Concatenated Queries (should be 'sql_injection') ---")
    for i, code in enumerate(concat_queries):
        result = classifier.classify(code)
        pred = result["prediction"]
        correct = pred == "sql_injection"
        concat_correct += int(correct)
        status = "PASS" if correct else "FAIL"
        print(f"  [{status}] Sample {i+1:2d}: predicted={pred:25s} conf={result['confidence']:.3f}")

    param_acc = param_correct / len(param_queries) * 100
    concat_acc = concat_correct / len(concat_queries) * 100

    print(f"\n--- Context-Aware Summary ---")
    print(f"  Parameterized queries accuracy:  {param_correct}/{len(param_queries)} = {param_acc:.1f}%")
    print(f"  Concatenated queries accuracy:   {concat_correct}/{len(concat_queries)} = {concat_acc:.1f}%")
    print(f"  Overall context-aware accuracy:  {(param_correct + concat_correct)}/{len(param_queries) + len(concat_queries)} = {(param_correct + concat_correct) / (len(param_queries) + len(concat_queries)) * 100:.1f}%")

    return param_correct, concat_correct, len(param_queries), len(concat_queries)


def main():
    print("=" * 70)
    print("  Specula Code Vulnerability Classifier — Evaluation Report")
    print("=" * 70)

    classifier = RuleBasedClassifier()

    # Build test suite
    suite = build_test_suite()
    print(f"\nTotal test samples: {len(suite)}")

    # Run classification
    y_true = []
    y_pred = []
    details = []
    for sample in suite:
        result = classifier.classify(sample["code"])
        true_label = sample["expected"]
        pred_label = result["prediction"]
        y_true.append(true_label)
        y_pred.append(pred_label)
        details.append({
            "code_snippet": sample["code"][:80],
            "expected": true_label,
            "predicted": pred_label,
            "confidence": result["confidence"],
            "correct": true_label == pred_label,
        })

    # Count distribution
    true_dist = Counter(y_true)
    pred_dist = Counter(y_pred)
    print(f"\nGround truth distribution:")
    for cls in sorted(true_dist.keys()):
        print(f"  {cls:30s}: {true_dist[cls]:3d}")
    print(f"\nPredicted distribution:")
    for cls in sorted(pred_dist.keys()):
        print(f"  {cls:30s}: {pred_dist[cls]:3d}")

    # Overall accuracy
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    print(f"\nOverall accuracy: {correct}/{len(y_true)} = {correct / len(y_true) * 100:.1f}%")

    # Compute metrics
    active_classes = sorted(set(y_true) | set(y_pred))
    metrics, conf_matrix, fp_counts, fn_counts, tp_counts = compute_metrics(y_true, y_pred, active_classes)

    # Per-class report
    print(f"\n{'=' * 70}")
    print("PER-CLASS METRICS")
    print(f"{'=' * 70}")
    print(f"{'Class':30s} {'Precision':>10s} {'Recall':>10s} {'F1':>10s} {'Support':>10s}")
    print("-" * 72)
    macro_p, macro_r, macro_f1 = 0.0, 0.0, 0.0
    count = 0
    for cls in active_classes:
        m = metrics[cls]
        print(f"{cls:30s} {m['precision']:10.3f} {m['recall']:10.3f} {m['f1']:10.3f} {m['support']:10d}")
        if m['support'] > 0:
            macro_p += m['precision']
            macro_r += m['recall']
            macro_f1 += m['f1']
            count += 1
    if count > 0:
        print("-" * 72)
        print(f"{'Macro avg':30s} {macro_p/count:10.3f} {macro_r/count:10.3f} {macro_f1/count:10.3f} {len(y_true):10d}")

    # Confusion matrix
    print(f"\n{'=' * 70}")
    print("CONFUSION MATRIX")
    print(f"{'=' * 70}")
    print_confusion_matrix(conf_matrix, active_classes)

    # False positive / false negative rates
    print(f"\n{'=' * 70}")
    print("FALSE POSITIVE & FALSE NEGATIVE ANALYSIS")
    print(f"{'=' * 70}")

    total_safe = sum(1 for t in y_true if t == "not_vulnerable")
    fp_safe = sum(1 for t, p in zip(y_true, y_pred) if t == "not_vulnerable" and p != "not_vulnerable")
    fn_safe = sum(1 for t, p in zip(y_true, y_pred) if t != "not_vulnerable" and p == "not_vulnerable")

    if total_safe > 0:
        print(f"\nFalse positive rate on safe code: {fp_safe}/{total_safe} = {fp_safe / total_safe * 100:.1f}%")
    else:
        print("\nNo safe code samples.")

    vuln_classes = [c for c in active_classes if c != "not_vulnerable"]
    total_vuln = sum(1 for t in y_true if t != "not_vulnerable")
    if total_vuln > 0:
        print(f"Overall false negative rate: {fn_safe}/{total_vuln} = {fn_safe / total_vuln * 100:.1f}%")

    print(f"\nFalse negative rate per vulnerability class:")
    for cls in vuln_classes:
        total = sum(1 for t in y_true if t == cls)
        fn = fn_counts.get(cls, 0)
        if total > 0:
            print(f"  {cls:30s}: FN={fn:3d}/{total:3d} = {fn / total * 100:.1f}%")
        else:
            print(f"  {cls:30s}: N/A (no samples)")

    print(f"\nFalse positive sources (safe code misclassified):")
    for t, p, conf, code in zip(y_true, y_pred, [d["confidence"] for d in details],
                                 [d["code_snippet"] for d in details]):
        if t == "not_vulnerable" and p != "not_vulnerable":
            print(f"  → predicted {p} (conf={conf:.3f}): {code[:70]}")

    # Context-aware tests
    param_correct, concat_correct, param_total, concat_total = run_context_aware_tests(classifier)

    # Misclassified samples
    print(f"\n{'=' * 70}")
    print("MISCLASSIFIED SAMPLES")
    print(f"{'=' * 70}")
    misclassified = [d for d in details if not d["correct"]]
    print(f"Total misclassified: {len(misclassified)}/{len(details)}")
    for d in misclassified:
        print(f"\n  Expected: {d['expected']}")
        print(f"  Predicted: {d['predicted']} (conf={d['confidence']:.3f})")
        print(f"  Code: {d['code_snippet']}")

    # Summary
    context_total = param_total + concat_total
    context_correct = param_correct + concat_correct
    print(f"\n{'=' * 70}")
    print("FINAL SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Test samples:                    {len(y_true)}")
    print(f"  Overall accuracy:                {correct}/{len(y_true)} = {correct / len(y_true) * 100:.1f}%")
    print(f"  False positive rate (safe code): {fp_safe}/{total_safe} = {fp_safe / total_safe * 100:.1f}%" if total_safe > 0 else "  FP rate: N/A")
    print(f"  False negative rate (all vuln):  {fn_safe}/{total_vuln} = {fn_safe / total_vuln * 100:.1f}%" if total_vuln > 0 else "  FN rate: N/A")
    print(f"  Context-aware accuracy:          {context_correct}/{context_total} = {context_correct / context_total * 100:.1f}%")
    print(f"  Macro F1:                        {macro_f1 / count:.3f}" if count > 0 else "  Macro F1: N/A")
    print()


if __name__ == "__main__":
    main()
