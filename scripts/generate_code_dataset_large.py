import csv
import random

from _paths import data_path

def generate_sql_injection_samples(n=800):
    samples = []
    templates = [
        'const query = "SELECT * FROM users WHERE id = " + userId;',
        'db.execute("SELECT * FROM products WHERE name = \'" + search + "\'");',
        'const sql = `SELECT * FROM orders WHERE user_id = ${req.body.user_id}`;',
        'string q = "DELETE FROM accounts WHERE id=" + accountId;',
        'query = "INSERT INTO logs (msg) VALUES (\'" + message + "\')";',
        'const update = "UPDATE users SET name=\'" + newName + "\' WHERE id=" + id;',
        'sql = "SELECT * FROM users WHERE username=\'" + username + "\' AND password=\'" + pass + "\'";',
        'db.query("SELECT * FROM products WHERE category=" + category);',
        'const deleteQuery = "DELETE FROM cart WHERE user_id=" + userId;',
        'execute("UPDATE accounts SET balance=balance-" + amount + " WHERE id=" + id);',
        'const findUser = "SELECT * FROM users WHERE email=\'" + email + "\'";',
        'db.raw("SELECT * FROM orders WHERE status=" + status);',
        'const search = "SELECT * FROM items WHERE title LIKE \'%" + term + "%\'";',
        'query("INSERT INTO comments (post_id, body) VALUES (" + postId + ", \'" + body + "\')");',
        'const login = "SELECT * FROM admins WHERE user=\'" + user + "\' AND pass=\'" + pwd + "\'";',
        'db.exec("UPDATE settings SET val=\'" + value + "\' WHERE key=\'" + key + "\'");',
        'const getCount = "SELECT COUNT(*) FROM logs WHERE level=\'" + level + "\'";',
        'sql = "DELETE FROM sessions WHERE expired < \'" + date + "\'";',
        'const getData = "SELECT col1, col2 FROM t WHERE id IN (" + ids + ")";',
        'query("UPDATE users SET role=\'" + role + "\' WHERE id=" + uid);',
        'const exists = "SELECT 1 FROM users WHERE token=\'" + token + "\'";',
        'db.query("INSERT INTO audit (action, user) VALUES (\'" + action + "\', " + uid + ")");',
        'const result = "SELECT * FROM products WHERE price < " + maxPrice + " AND category=\'" + cat + "\'";',
        'execute("DROP TABLE IF EXISTS " + tableName);',
        'const update = "UPDATE products SET stock=stock-" + qty + " WHERE id=" + pid;',
        'sql = "SELECT * FROM payments WHERE amount > " + minAmount;',
        'const del = "DELETE FROM temp WHERE created_at < \'" + cutoff + "\'";',
        'query("INSERT INTO notifications (user_id, msg) VALUES (" + uid + ", \'" + msg + "\')");',
        'db.raw("SELECT u.*, o.* FROM users u JOIN orders o ON u.id=o.user_id WHERE u.id=" + uid);',
        'const check = "SELECT id FROM users WHERE email=\'" + email + "\' LIMIT 1";',
    ]
    
    variations = [
        '{}', '${}', '{} || ""', 'String({})', 'parseInt({})',
        'parseInt(req.query.{})', 'req.params.{}', 'req.body.{}',
        'req.query.{}', 'data.{}', 'params.{}', 'input.{}'
    ]
    
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'sql_injection'))
    
    return samples

def generate_xss_samples(n=800):
    samples = []
    templates = [
        'element.innerHTML = userInput;',
        'document.write("<div>" + data + "</div>");',
        'div.outerHTML = req.body.content;',
        'element.insertAdjacentHTML("beforeend", userContent);',
        'response.send(`<p>${comment}</p>`);',
        'el.innerHTML = "<img src=\'" + url + "\'>";',
        'document.body.innerHTML += userData;',
        'output.innerHTML = "<a href=\'" + link + "\'>" + text + "</a>";',
        'element.innerHTML = "<script>" + script + "</script>";',
        'container.insertAdjacentHTML("afterend", req.query.html);',
        'document.getElementById("output").innerHTML = name;',
        'div.textContent = "<b>" + userinput + "</b>";',
        'el.innerHTML = decodeURIComponent(hash);',
        'response.html("<div>" + req.body.data + "</div>");',
        'template.innerHTML = "<span>" + val + "</span>";',
        'document.body.insertAdjacentHTML("beforeend", req.query.content);',
        'node.innerHTML = "<p>" + unsafe + "</p>";',
        'output.insertAdjacentHTML("afterbegin", userInput);',
        'element.innerHTML = atob(encoded);',
        'container.innerHTML = JSON.parse(userString).html;',
        'div.innerHTML = `<h1>${title}</h1><p>${body}</p>`;',
        'document.write(userContent);',
        'el.outerHTML = "<div>" + data + "</div>";',
        'wrapper.innerHTML = `<img src="${imgUrl}">`;',
        'container.insertAdjacentHTML("beforeend", `<p>${text}</p>`);',
        'document.querySelector("#app").innerHTML = html;',
        'output.innerHTML = marked.parse(userMarkdown);',
        'div.innerHTML = `<a href="${url}">Click</a>`;',
        'element.innerHTML = template(content);',
        'node.outerHTML = `<div class="card">${cardContent}</div>`;',
    ]
    
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'xss'))
    
    return samples

def generate_hardcoded_credentials_samples(n=800):
    samples = []
    templates = [
        'const password = "admin123";',
        'const API_KEY = "sk-1234567890abcdef";',
        'DB_PASSWORD = "secret_pass_123";',
        'const SECRET = "mysecretkey";',
        'api_token = "ghp_placeholder_token";',
        'const AWS_KEY = "AKIA0000000000000000";',
        'password: "root",',
        'const dbPass = "mysql_password";',
        'TOKEN = "eyJhbGciOiJIUzI1NiJ9";',
        'const secret_key = "supersecret";',
        'const PRIVATE_KEY = "-----BEGIN EXAMPLE PRIVATE KEY-----";',
        'db_password: "postgres",',
        'const encryption_key = "0123456789abcdef";',
        'REDIS_PASSWORD = "redis_pass";',
        'const smtp_pass = "email_password";',
        'mongodb_uri: "mongodb://admin:pass@localhost",',
        'const stripe_key = "stripe-test-abc123";',
        'SENDGRID_API_KEY = "SG.abc123.def456";',
        'const firebase_key = "AIzaSyA1234567890";',
        'jwt_secret: "my_jwt_secret_key",',
        'const slack_token = "SLACK-BOT-TOKEN-PLACEHOLDER";',
        'const github_token = "ghp_placeholder_token";',
        'DB_USER: "root",',
        'const paypal_client_id = "AXq1234567890";',
        'const openai_key = "sk-placeholder-key";',
        'consul_token = "consul_secret_token";',
        'const vault_token = "s.abc123def456";',
        'etcd_password = "etcd_secret";',
        'const datadog_key = "abc123def456";',
        'const pagerduty_key = "abc123def456";',
    ]
    
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'hardcoded_credentials'))
    
    return samples

def generate_command_injection_samples(n=800):
    samples = []
    templates = [
        'exec("cat " + filename);',
        'system("ping " + host);',
        'child_process.exec(`ls ${dir}`);',
        'os.system("curl " + url);',
        'exec("rm -rf " + path);',
        'popen("grep " + pattern + " " + file);',
        'subprocess.call("python " + script);',
        'child_process.execSync("npm install " + pkg);',
        'exec("tar -xvf " + archive);',
        'system("nslookup " + userInput);',
        'child_process.exec(`wget ${url}`);',
        'os.popen("cat " + filePath);',
        'exec("chmod 777 " + dir);',
        'subprocess.run("python3 " + script, shell=True);',
        'system("convert " + inputFile + " " + outputFile);',
        'child_process.spawn("ffmpeg", [input]);',
        'exec("mv " + source + " " + dest);',
        'os.system("python " + userInput + ".py");',
        'popen("find " + dir + " -name *.txt");',
        'subprocess.Popen("node " + script);',
        'exec("cp " + src + " " + dst);',
        'system("unzip " + zipfile + " -d " + targetDir);',
        'child_process.exec(`docker run ${image}`);',
        'os.system("ffmpeg -i " + input + " " + output);',
        'exec("python -m " + module);',
        'subprocess.call(["sh", "-c", cmd]);',
        'child_process.exec(`git clone ${repoUrl}`);',
        'system("npm run " + scriptName);',
        'popen("curl -X POST " + endpoint);',
        'exec("mysql -u " + user + " -p" + pass + " < " + sqlFile);',
    ]
    
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'command_injection'))
    
    return samples

def generate_path_traversal_samples(n=800):
    samples = []
    templates = [
        'readFile("/data/" + userPath);',
        'fs.readFileSync(baseDir + "/" + filename);',
        'open("/uploads/" + req.params.file);',
        'const content = fs.readFile(path.join(dir, userInput));',
        'readfile("/etc/" + configFile);',
        'fs.readFile("/var/www/" + userFile, callback);',
        'const data = readFileSync("/opt/" + fileName);',
        'open("/backup/" + req.body.filename);',
        'fs.readFileSync("/logs/" + logFile);',
        'readFile(config.basePath + "/" + req.query.path);',
        'fs.readFile("/storage/" + req.params.id + ".json");',
        'const file = open("/documents/" + docName);',
        'readFileSync("/static/" + assetPath);',
        'fs.readFile(path + "/" + userInput);',
        'open("/tmp/" + sessionFile);',
        'readFile("/images/" + imageName);',
        'const content = readFileSync("/exports/" + exportFile);',
        'fs.readFile("/templates/" + templateName);',
        'open("/data/uploads/" + req.file.originalname);',
        'readFileSync("/cache/" + cacheKey + ".json");',
        'fs.readFile("/reports/" + reportId + ".pdf");',
        'const pdf = open("/invoices/" + invoiceNum + ".pdf");',
        'readFileSync("/attachments/" + fileName);',
        'fs.readFile("/media/" + mediaPath);',
        'open("/user_uploads/" + userId + "/" + filename);',
        'readFile("/downloads/" + req.query.file);',
        'const xml = readFileSync("/xml/" + xmlFile);',
        'fs.readFile("/imports/" + importFile);',
        'open("/temp/" + process.pid + ".tmp");',
        'readFileSync("/backups/" + backupDate + ".tar.gz");',
    ]
    
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'path_traversal'))
    
    return samples

def generate_not_vulnerable_samples(n=1000):
    samples = []
    templates = [
        'const x = 5;',
        'function add(a, b) { return a + b; }',
        'const arr = [1, 2, 3, 4, 5];',
        'if (x > 0) { console.log("positive"); }',
        'for (let i = 0; i < 10; i++) { sum += i; }',
        'const result = arr.map(x => x * 2);',
        'export default function myFunc() {}',
        'class MyClass { constructor() { this.x = 0; } }',
        'try { doSomething(); } catch (e) { log(e); }',
        'const data = await fetch(url);',
        'module.exports = { helper: () => {} };',
        'import React from "react";',
        'const [state, setState] = useState(0);',
        'app.get("/api", (req, res) => { res.json({}); });',
        'const config = require("./config");',
        'setTimeout(() => {}, 1000);',
        'Promise.all([p1, p2]).then(r => {});',
        'Object.assign(target, source);',
        'const merged = {...obj1, ...obj2};',
        'console.log("debug");',
        'const arr = Array.from({length: 10}, (_, i) => i);',
        'export const multiply = (a, b) => a * b;',
        'const isValid = value !== null && value !== undefined;',
        'for (const item of items) { process(item); }',
        'const filtered = arr.filter(x => x > 0);',
        'async function fetchData() { return await api.get("/data"); }',
        'const map = new Map();',
        'const set = new Set([1, 2, 3]);',
        'class Animal { speak() { return "Noise"; } }',
        'const delay = (ms) => new Promise(r => setTimeout(r, ms));',
        'function* generator() { yield 1; yield 2; }',
        'const [first, ...rest] = array;',
        'const obj = { key: "value", nested: { a: 1 } };',
        'if (arr.includes(value)) { /* do something */ }',
        'const sum = arr.reduce((acc, val) => acc + val, 0);',
        'Math.max(...numbers);',
        'JSON.parse(jsonString);',
        'JSON.stringify(object);',
        'Date.now();',
        'Math.random();',
        'const type = typeof variable;',
        'Array.isArray(value);',
        'Object.keys(obj).length;',
        'Object.values(obj);',
        'Object.entries(obj);',
        'str.includes("substring");',
        'str.replace("old", "new");',
        'str.split(",");',
        'num.toFixed(2);',
        'parseInt("123", 10);',
        'parseFloat("3.14");',
        'Boolean(value);',
        'Number("123");',
        'String(123);',
        'encodeURIComponent(str);',
        'decodeURIComponent(str);',
        'btoa("hello");',
        'atob("aGVsbG8=");',
        'const { a, b } = object;',
        'const [[x, y]] = coordinates;',
        'const fn = () => ({ key: "value" });',
        'const asyncFn = async () => { await promise; };',
        'class Stack { push(item) { this.items.push(item); } }',
        'const debounce = (fn, delay) => { let timer; return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); }; };',
        'const throttle = (fn, limit) => { let inThrottle; return (...args) => { if (!inThrottle) { fn(...args); inThrottle = true; setTimeout(() => inThrottle = false, limit); } }; };',
        'const memoize = (fn) => { const cache = {}; return (...args) => cache[args] || (cache[args] = fn(...args)); };',
        'const pipe = (...fns) => (x) => fns.reduce((v, f) => f(v), x);',
        'const compose = (...fns) => (x) => fns.reduceRight((v, f) => f(v), x);',
        'const curry = (fn) => (...args) => args.length >= fn.length ? fn(...args) : curry(fn.bind(null, ...args));',
        'const partial = (fn, ...args) => (...moreArgs) => fn(...args, ...moreArgs);',
        'const once = (fn) => { let called = false, result; return (...args) => { if (!called) { called = true; result = fn(...args); } return result; }; };',
        'const clamp = (num, min, max) => Math.min(Math.max(num, min), max);',
        'const lerp = (start, end, t) => start + (end - start) * t;',
        'const randomInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;',
        'const shuffle = (arr) => [...arr].sort(() => Math.random() - 0.5);',
        'const unique = (arr) => [...new Set(arr)];',
        'const flatten = (arr) => arr.reduce((acc, val) => acc.concat(Array.isArray(val) ? flatten(val) : val), []);',
        'const chunk = (arr, size) => Array.from({ length: Math.ceil(arr.length / size) }, (_, i) => arr.slice(i * size, i * size + size));',
        'const compact = (arr) => arr.filter(Boolean);',
        'const difference = (a, b) => a.filter(x => !b.includes(x));',
        'const intersection = (a, b) => a.filter(x => b.includes(x));',
        'const union = (a, b) => [...new Set([...a, ...b])];',
        'const without = (arr, ...args) => arr.filter(x => !args.includes(x));',
        'const groupBy = (arr, key) => arr.reduce((acc, item) => { (acc[item[key]] = acc[item[key]] || []).push(item); return acc; }, {});',
        'const sortBy = (arr, key) => [...arr].sort((a, b) => a[key] > b[key] ? 1 : -1);',
        'const deepClone = (obj) => JSON.parse(JSON.stringify(obj));',
        'const isEmpty = (obj) => Object.keys(obj).length === 0;',
        'const has = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);',
        'const get = (obj, path, defaultVal) => path.split(".").reduce((acc, val) => acc && acc[val], obj) || defaultVal;',
        'const set = (obj, path, value) => { const keys = path.split("."); let current = obj; for (let i = 0; i < keys.length - 1; i++) { current = current[keys[i]] = current[keys[i]] || {}; } current[keys[keys.length - 1]] = value; return obj; };',
        'const pick = (obj, keys) => keys.reduce((acc, key) => { if (key in obj) acc[key] = obj[key]; return acc; }, {});',
        'const omit = (obj, keys) => Object.keys(obj).reduce((acc, key) => { if (!keys.includes(key)) acc[key] = obj[key]; return acc; }, {});',
        'const mapKeys = (obj, fn) => Object.keys(obj).reduce((acc, key) => { acc[fn(key, obj[key])] = obj[key]; return acc; }, {});',
        'const mapValues = (obj, fn) => Object.keys(obj).reduce((acc, key) => { acc[key] = fn(obj[key], key); return acc; }, {});',
        'const invert = (obj) => Object.keys(obj).reduce((acc, key) => { acc[obj[key]] = key; return acc; }, {});',
        'const defaults = (obj, ...sources) => Object.assign({}, obj, ...sources.map(s => Object.keys(s).reduce((acc, key) => { if (!(key in obj)) acc[key] = s[key]; return acc; }, {})));',
        'const tap = (value, fn) => { fn(value); return value; };',
        'const thunkify = (fn) => (...args) => () => fn(...args);',
        'const asyncify = (fn) => (...args) => Promise.resolve().then(() => fn(...args));',
        'const retry = (fn, times) => (...args) => fn(...args).catch(err => times > 1 ? retry(fn, times - 1)(...args) : Promise.reject(err));',
        'const timeout = (fn, ms) => (...args) => Promise.race([fn(...args), new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), ms))]);',
        'const until = (fn, predicate) => (...args) => { let result = fn(...args); while (!predicate(result)) result = fn(result); return result; };',
        'const when = (predicate, fn) => (...args) => predicate(...args) ? fn(...args) : args[0];',
        'const unless = (predicate, fn) => (...args) => !predicate(...args) ? fn(...args) : args[0];',
        'const ifElse = (predicate, onTrue, onFalse) => (...args) => predicate(...args) ? onTrue(...args) : onFalse(...args);',
        'const not = (fn) => (...args) => !fn(...args);',
        'const and = (...fns) => (...args) => fns.every(fn => fn(...args));',
        'const or = (...fns) => (...args) => fns.some(fn => fn(...args));',
        'const allPass = (predicates) => (...args) => predicates.every(p => p(...args));',
        'const anyPass = (predicates) => (...args) => predicates.some(p => p(...args));',
        'const converge = (fn, fns) => (...args) => fn(...fns.map(f => f(...args)));',
        'const juxt = (...fns) => (...args) => fns.map(f => f(...args));',
        'const useWith = (fn, transformers) => (...args) => fn(...transformers.map((t, i) => t(args[i])));',
        'const memoizeWith = (keyFn, fn) => { const cache = {}; return (...args) => { const key = keyFn(...args); return key in cache ? cache[key] : (cache[key] = fn(...args)); }; };',
        'const nAry = (n, fn) => (...args) => fn(...args.slice(0, n));',
        'const unary = (fn) => nAry(1, fn);',
        'const binary = (fn) => nAry(2, fn);',
        'const ternary = (fn) => nAry(3, fn);',
        'const identity = (x) => x;',
        'const always = (x) => () => x;',
        'const T = always(true);',
        'const F = always(false);',
        'const nil = always(null);',
        'const nothing = always(undefined);',
        'const noop = () => {};',
        'const constant = (x) => () => x;',
        'const complement = (fn) => (...args) => !fn(...args);',
        'const flip = (fn) => (...args) => fn(...args.reverse());',
        'const flip2 = (fn) => (a, b) => fn(b, a);',
        'const flip3 = (fn) => (a, b, c) => fn(c, b, a);',
        'const on = (fn, g, a, b) => fn(g(a), g(b));',
        'const applyTo = (x, fn) => fn(x);',
        'const applyTo = (fn) => (x) => fn(x);',
        'const thrush = (x, fn) => fn(x);',
        'const thrush = (x) => (fn) => fn(x);',
        'const tap = (fn, x) => { fn(x); return x; };',
        'const tap = (fn) => (x) => { fn(x); return x; };',
        'const curryN = (n, fn) => (...args) => args.length >= n ? fn(...args) : curryN(n, fn).bind(null, ...args);',
        'const partialRight = (fn, ...args) => (...moreArgs) => fn(...moreArgs, ...args);',
        'const Curry = (fn) => (...args) => args.length >= fn.length ? fn(...args) : Curry(fn.bind(null, ...args));',
        'const compose2 = (f, g) => (...args) => f(g(...args));',
        'const pipe2 = (f, g) => (...args) => g(f(...args));',
        'const composeN = (...fns) => fns.reduce((f, g) => (...args) => f(g(...args)));',
        'const pipeN = (...fns) => fns.reduce((f, g) => (...args) => g(f(...args)));',
    ]
    
    for _ in range(n):
        template = random.choice(templates)
        samples.append((template, 'not_vulnerable'))
    
    return samples

def main():
    all_samples = []
    all_samples.extend(generate_sql_injection_samples(800))
    all_samples.extend(generate_xss_samples(800))
    all_samples.extend(generate_hardcoded_credentials_samples(800))
    all_samples.extend(generate_command_injection_samples(800))
    all_samples.extend(generate_path_traversal_samples(800))
    all_samples.extend(generate_not_vulnerable_samples(1000))
    
    random.shuffle(all_samples)
    
    output_path = data_path('code', 'cve_dataset.csv')
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['code', 'label'])
        writer.writerows(all_samples)
    
    print(f"Generated {len(all_samples)} samples")
    print(f"Saved to {output_path}")
    
    from collections import Counter
    labels = [s[1] for s in all_samples]
    print("\nClass distribution:")
    for label, count in Counter(labels).items():
        print(f"  {label}: {count}")

if __name__ == '__main__':
    main()
