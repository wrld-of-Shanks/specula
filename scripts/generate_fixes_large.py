import csv
import random

from _paths import data_path

def generate_fix_samples():
    samples = []
    
    sql_fixes = [
        ('const query = "SELECT * FROM users WHERE id = " + userId;',
         'const query = "SELECT * FROM users WHERE id = ?";'),
        ('db.execute("SELECT * FROM products WHERE name = \'" + search + "\'");',
         'db.execute("SELECT * FROM products WHERE name = ?", [search]);'),
        ('const sql = `SELECT * FROM orders WHERE user_id = ${req.body.user_id}`;',
         'const sql = "SELECT * FROM orders WHERE user_id = $1";'),
        ('string q = "DELETE FROM accounts WHERE id=" + accountId;',
         'string q = "DELETE FROM accounts WHERE id=@id";'),
        ('query = "INSERT INTO logs (msg) VALUES (\'" + message + "\')";',
         'query = "INSERT INTO logs (msg) VALUES (?)";'),
        ('const update = "UPDATE users SET name=\'" + newName + "\' WHERE id=" + id;',
         'const update = "UPDATE users SET name=? WHERE id=?";'),
        ('sql = "SELECT * FROM users WHERE username=\'" + username + "\' AND password=\'" + pass + "\'";',
         'sql = "SELECT * FROM users WHERE username=? AND password=?";'),
        ('db.query("SELECT * FROM products WHERE category=" + category);',
         'db.query("SELECT * FROM products WHERE category=?", [category]);'),
        ('const deleteQuery = "DELETE FROM cart WHERE user_id=" + userId;',
         'const deleteQuery = "DELETE FROM cart WHERE user_id=?";'),
        ('execute("UPDATE accounts SET balance=balance-" + amount + " WHERE id=" + id);',
         'execute("UPDATE accounts SET balance=balance-? WHERE id=?", [amount, id]);'),
        ('const findUser = "SELECT * FROM users WHERE email=\'" + email + "\'";',
         'const findUser = "SELECT * FROM users WHERE email=?";'),
        ('db.raw("SELECT * FROM orders WHERE status=" + status);',
         'db.raw("SELECT * FROM orders WHERE status=?", [status]);'),
        ('const search = "SELECT * FROM items WHERE title LIKE \'%" + term + "%\'";',
         'const search = "SELECT * FROM items WHERE title LIKE ?");'),
        ('query("INSERT INTO comments (post_id, body) VALUES (" + postId + ", \'" + body + "\')");',
         'query("INSERT INTO comments (post_id, body) VALUES (?, ?)", [postId, body]);'),
        ('const login = "SELECT * FROM admins WHERE user=\'" + user + "\' AND pass=\'" + pwd + "\'";',
         'const login = "SELECT * FROM admins WHERE user=? AND pass=?";'),
        ('db.exec("UPDATE settings SET val=\'" + value + "\' WHERE key=\'" + key + "\'");',
         'db.exec("UPDATE settings SET val=? WHERE key=?", [value, key]);'),
        ('const getCount = "SELECT COUNT(*) FROM logs WHERE level=\'" + level + "\'";',
         'const getCount = "SELECT COUNT(*) FROM logs WHERE level=?");'),
        ('sql = "DELETE FROM sessions WHERE expired < \'" + date + "\'";',
         'sql = "DELETE FROM sessions WHERE expired < ?");'),
        ('const getData = "SELECT col1, col2 FROM t WHERE id IN (" + ids + ")";',
         'const getData = "SELECT col1, col2 FROM t WHERE id IN (?)");'),
    ]
    
    xss_fixes = [
        ('element.innerHTML = userInput;',
         'element.textContent = userInput;'),
        ('document.write("<div>" + data + "</div>");',
         'const div = document.createElement("div"); div.textContent = data; document.body.appendChild(div);'),
        ('div.outerHTML = req.body.content;',
         'div.textContent = DOMPurify.sanitize(req.body.content);'),
        ('element.insertAdjacentHTML("beforeend", userContent);',
         'const textNode = document.createTextNode(userContent); element.appendChild(textNode);'),
        ('response.send(`<p>${comment}</p>`);',
         'response.send(`<p>${escapeHtml(comment)}</p>`);'),
        ('el.innerHTML = "<img src=\'" + url + "\'>";',
         'el.textContent = url;'),
        ('document.body.innerHTML += userData;',
         'document.body.textContent = userData;'),
        ('output.innerHTML = "<a href=\'" + link + "\'>" + text + "</a>";',
         'output.textContent = text;'),
        ('element.innerHTML = "<script>" + script + "</script>";',
         'element.textContent = script;'),
        ('container.insertAdjacentHTML("afterend", req.query.html);',
         'container.textContent = req.query.html;'),
        ('document.getElementById("output").innerHTML = name;',
         'document.getElementById("output").textContent = name;'),
        ('div.textContent = "<b>" + userinput + "</b>";',
         'div.textContent = userinput;'),
        ('el.innerHTML = decodeURIComponent(hash);',
         'el.textContent = decodeURIComponent(hash);'),
        ('response.html("<div>" + req.body.data + "</div>");',
         'response.text(req.body.data);'),
        ('template.innerHTML = "<span>" + val + "</span>";',
         'template.textContent = val;'),
        ('document.body.insertAdjacentHTML("beforeend", req.query.content);',
         'const text = document.createTextNode(req.query.content); document.body.appendChild(text);'),
        ('node.innerHTML = "<p>" + unsafe + "</p>";',
         'node.textContent = unsafe;'),
        ('output.insertAdjacentHTML("afterbegin", userInput);',
         'output.textContent = userInput;'),
        ('element.innerHTML = atob(encoded);',
         'element.textContent = atob(encoded);'),
        ('container.innerHTML = JSON.parse(userString).html;',
         'container.textContent = JSON.parse(userString).html;'),
        ('div.innerHTML = `<h1>${title}</h1><p>${body}</p>`;',
         'div.textContent = title + " " + body;'),
        ('document.write(userContent);',
         'document.body.textContent = userContent;'),
        ('el.outerHTML = "<div>" + data + "</div>";',
         'el.textContent = data;'),
        ('wrapper.innerHTML = `<img src="${imgUrl}">`;',
         'wrapper.textContent = imgUrl;'),
        ('container.insertAdjacentHTML("beforeend", `<p>${text}</p>`);',
         'container.textContent = text;'),
        ('document.querySelector("#app").innerHTML = html;',
         'document.querySelector("#app").textContent = html;'),
        ('output.innerHTML = marked.parse(userMarkdown);',
         'output.textContent = userMarkdown;'),
        ('div.innerHTML = `<a href="${url}">Click</a>`;',
         'div.textContent = url;'),
        ('element.innerHTML = template(content);',
         'element.textContent = content;'),
        ('node.outerHTML = `<div class="card">${cardContent}</div>`;',
         'node.textContent = cardContent;'),
    ]
    
    credential_fixes = [
        ('const password = "admin123";',
         'const password = process.env.PASSWORD;'),
        ('const API_KEY = "sk-1234567890abcdef";',
         'const API_KEY = process.env.API_KEY;'),
        ('DB_PASSWORD = "secret_pass_123";',
         'DB_PASSWORD = process.env.DB_PASSWORD;'),
        ('const SECRET = "mysecretkey";',
         'const SECRET = process.env.SECRET_KEY;'),
        (         'api_token = "ghp_placeholder_token";',
         'api_token = process.env.GITHUB_TOKEN;'),
        (         'const AWS_KEY = "AKIA0000000000000000";',
         'const AWS_KEY = process.env.AWS_ACCESS_KEY_ID;'),
        ('password: "root",',
         'password: process.env.DB_PASSWORD,'),
        ('const dbPass = "mysql_password";',
         'const dbPass = process.env.MYSQL_PASSWORD;'),
        ('TOKEN = "eyJhbGciOiJIUzI1NiJ9";',
         'TOKEN = process.env.JWT_TOKEN;'),
        ('const secret_key = "supersecret";',
         'const secret_key = process.env.SECRET_KEY;'),
        (         'const PRIVATE_KEY = "-----BEGIN EXAMPLE PRIVATE KEY-----";',
         'const PRIVATE_KEY = fs.readFileSync(process.env.PRIVATE_KEY_PATH);'),
        ('db_password: "postgres",',
         'db_password: process.env.POSTGRES_PASSWORD,'),
        ('const encryption_key = "0123456789abcdef";',
         'const encryption_key = process.env.ENCRYPTION_KEY;'),
        ('REDIS_PASSWORD = "redis_pass";',
         'REDIS_PASSWORD = process.env.REDIS_PASSWORD;'),
        ('const smtp_pass = "email_password";',
         'const smtp_pass = process.env.SMTP_PASSWORD;'),
        ('mongodb_uri: "mongodb://admin:pass@localhost",',
         'mongodb_uri: process.env.MONGODB_URI,'),
        ('const stripe_key = "stripe-test-abc123";',
         'const stripe_key = process.env.STRIPE_SECRET_KEY;'),
        ('SENDGRID_API_KEY = "SG.abc123.def456";',
         'SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;'),
        ('const firebase_key = "AIzaSyA1234567890";',
         'const firebase_key = process.env.FIREBASE_API_KEY;'),
        ('jwt_secret: "my_jwt_secret_key",',
         'jwt_secret: process.env.JWT_SECRET,'),
        ('const slack_token = "SLACK-BOT-TOKEN-PLACEHOLDER";',
         'const slack_token = process.env.SLACK_BOT_TOKEN;'),
        (         'const github_token = "ghp_placeholder_token";',
         'const github_token = process.env.GITHUB_TOKEN;'),
        ('DB_USER: "root",',
         'DB_USER: process.env.DB_USER,'),
        ('const paypal_client_id = "AXq1234567890";',
         'const paypal_client_id = process.env.PAYPAL_CLIENT_ID;'),
        (         'const openai_key = "sk-placeholder-key";',
         'const openai_key = process.env.OPENAI_API_KEY;'),
    ]
    
    command_fixes = [
        ('exec("cat " + filename);',
         'const { execFile } = require("child_process"); execFile("cat", [filename]);'),
        ('system("ping " + host);',
         'subprocess.run(["ping", host], capture_output=True)'),
        ('child_process.exec(`ls ${dir}`);',
         'const { execFile } = require("child_process"); execFile("ls", [dir]);'),
        ('os.system("curl " + url);',
         'requests.get(url)'),
        ('exec("rm -rf " + path);',
         'shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)'),
        ('popen("grep " + pattern + " " + file);',
         'subprocess.Popen(["grep", pattern, file])'),
        ('subprocess.call("python " + script);',
         'subprocess.call(["python", script])'),
        ('child_process.execSync("npm install " + pkg);',
         'child_process.execFileSync("npm", ["install", pkg])'),
        ('exec("tar -xvf " + archive);',
         'subprocess.run(["tar", "-xvf", archive])'),
        ('system("nslookup " + userInput);',
         'subprocess.run(["nslookup", userInput])'),
        ('child_process.exec(`wget ${url}`);',
         'child_process.execFileSync("wget", [url])'),
        ('os.popen("cat " + filePath);',
         'open(filePath).read()'),
        ('exec("chmod 777 " + dir);',
         'os.chmod(dir, 0o777)'),
        ('subprocess.run("python3 " + script, shell=True);',
         'subprocess.run(["python3", script])'),
        ('system("convert " + inputFile + " " + outputFile);',
         'subprocess.run(["convert", inputFile, outputFile])'),
        ('child_process.spawn("ffmpeg", [input]);',
         'child_process.spawn("ffmpeg", ["-i", input])'),
        ('exec("mv " + source + " " + dest);',
         'shutil.move(source, dest)'),
        ('os.system("python " + userInput + ".py");',
         'subprocess.run(["python", userInput + ".py"])'),
        ('popen("find " + dir + " -name *.txt");',
         'subprocess.Popen(["find", dir, "-name", "*.txt"])'),
        ('subprocess.Popen("node " + script);',
         'subprocess.Popen(["node", script])'),
        ('exec("cp " + src + " " + dst);',
         'shutil.copy(src, dst)'),
        ('system("unzip " + zipfile + " -d " + targetDir);',
         'subprocess.run(["unzip", zipfile, "-d", targetDir])'),
        ('child_process.exec(`docker run ${image}`);',
         'child_process.execFileSync("docker", ["run", image])'),
        ('os.system("ffmpeg -i " + input + " " + output);',
         'subprocess.run(["ffmpeg", "-i", input, output])'),
        ('exec("python -m " + module);',
         'subprocess.run(["python", "-m", module])'),
    ]
    
    path_fixes = [
        ('readFile("/data/" + userPath);',
         'const resolved = path.resolve("/data", userPath); if (!resolved.startsWith("/data")) throw new Error("Invalid path"); readFile(resolved);'),
        ('fs.readFileSync(baseDir + "/" + filename);',
         'const resolved = path.resolve(baseDir, filename); if (!resolved.startsWith(baseDir)) throw new Error("Invalid path"); fs.readFileSync(resolved);'),
        ('open("/uploads/" + req.params.file);',
         'const safePath = path.join("/uploads", path.basename(req.params.file)); open(safePath);'),
        ('const content = fs.readFile(path.join(dir, userInput));',
         'const resolved = path.resolve(dir, userInput); if (!resolved.startsWith(dir)) throw new Error("Invalid path"); fs.readFile(resolved);'),
        ('readfile("/etc/" + configFile);',
         'const resolved = path.resolve("/etc", configFile); if (!resolved.startsWith("/etc")) throw new Error("Invalid path"); readfile(resolved);'),
        ('fs.readFile("/var/www/" + userFile, callback);',
         'const resolved = path.resolve("/var/www", userFile); if (!resolved.startsWith("/var/www")) throw new Error("Invalid path"); fs.readFile(resolved, callback);'),
        ('const data = readFileSync("/opt/" + fileName);',
         'const resolved = path.resolve("/opt", fileName); if (!resolved.startsWith("/opt")) throw new Error("Invalid path"); readFileSync(resolved);'),
        ('open("/backup/" + req.body.filename);',
         'const safePath = path.join("/backup", path.basename(req.body.filename)); open(safePath);'),
        ('fs.readFileSync("/logs/" + logFile);',
         'const resolved = path.resolve("/logs", logFile); if (!resolved.startsWith("/logs")) throw new Error("Invalid path"); fs.readFileSync(resolved);'),
        ('readFile(config.basePath + "/" + req.query.path);',
         'const resolved = path.resolve(config.basePath, req.query.path); if (!resolved.startsWith(config.basePath)) throw new Error("Invalid path"); readFile(resolved);'),
        ('fs.readFile("/storage/" + req.params.id + ".json");',
         'const safePath = path.join("/storage", path.basename(req.params.id) + ".json"); fs.readFile(safePath);'),
        ('const file = open("/documents/" + docName);',
         'const safePath = path.join("/documents", path.basename(docName)); const file = open(safePath);'),
        ('readFileSync("/static/" + assetPath);',
         'const resolved = path.resolve("/static", assetPath); if (!resolved.startsWith("/static")) throw new Error("Invalid path"); readFileSync(resolved);'),
        ('fs.readFile(path + "/" + userInput);',
         'const resolved = path.resolve(path, userInput); if (!resolved.startsWith(path)) throw new Error("Invalid path"); fs.readFile(resolved);'),
        ('open("/tmp/" + sessionFile);',
         'const safePath = path.join("/tmp", path.basename(sessionFile)); open(safePath);'),
        ('readFile("/images/" + imageName);',
         'const safePath = path.join("/images", path.basename(imageName)); readFile(safePath);'),
        ('const content = readFileSync("/exports/" + exportFile);',
         'const resolved = path.resolve("/exports", exportFile); if (!resolved.startsWith("/exports")) throw new Error("Invalid path"); readFileSync(resolved);'),
        ('fs.readFile("/templates/" + templateName);',
         'const safePath = path.join("/templates", path.basename(templateName)); fs.readFile(safePath);'),
        ('open("/data/uploads/" + req.file.originalname);',
         'const safePath = path.join("/data/uploads", path.basename(req.file.originalname)); open(safePath);'),
        ('readFileSync("/cache/" + cacheKey + ".json");',
         'const safePath = path.join("/cache", path.basename(cacheKey) + ".json"); readFileSync(safePath);'),
    ]
    
    for vulnerable, fixed in sql_fixes:
        samples.append((vulnerable, fixed))
    for vulnerable, fixed in xss_fixes:
        samples.append((vulnerable, fixed))
    for vulnerable, fixed in credential_fixes:
        samples.append((vulnerable, fixed))
    for vulnerable, fixed in command_fixes:
        samples.append((vulnerable, fixed))
    for vulnerable, fixed in path_fixes:
        samples.append((vulnerable, fixed))
    
    augmented_samples = []
    for vulnerable, fixed in samples:
        augmented_samples.append((vulnerable, fixed))
        
        if "SELECT" in vulnerable:
            augmented_samples.append((
                vulnerable.replace("SELECT *", "SELECT id, name, email"),
                fixed.replace("SELECT *", "SELECT id, name, email")
            ))
        if "FROM users" in vulnerable:
            augmented_samples.append((
                vulnerable.replace("users", "accounts"),
                fixed.replace("users", "accounts")
            ))
        if "FROM products" in vulnerable:
            augmented_samples.append((
                vulnerable.replace("products", "items"),
                fixed.replace("products", "items")
            ))
    
    random.shuffle(augmented_samples)
    return augmented_samples

def main():
    samples = generate_fix_samples()
    
    output_path = data_path('code', 'fixes_dataset.csv')
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['vulnerable', 'fixed'])
        writer.writerows(samples)
    
    print(f"Generated {len(samples)} fix pairs")
    print(f"Saved to {output_path}")

if __name__ == '__main__':
    main()
