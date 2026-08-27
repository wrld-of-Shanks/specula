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
                vulnerable.replace("SELECT *", "SELECT name, email"),
                fixed.replace("SELECT *", "SELECT name, email")
            ))
        if "FROM users" in vulnerable:
            augmented_samples.append((
                vulnerable.replace("users", "accounts"),
                fixed.replace("users", "accounts")
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
