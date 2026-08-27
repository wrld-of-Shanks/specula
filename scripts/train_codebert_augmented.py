"""
Augmented CodeBERT training — optimized for speed.
Adds parameterized queries (not_vulnerable) and insecure_deserialization,
then fine-tunes CodeBERT on the combined dataset.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'code'))

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from transformers import RobertaTokenizer, RobertaForSequenceClassification
from torch.utils.data import TensorDataset, DataLoader
from sklearn.metrics import classification_report

VULNERABILITY_CLASSES = [
    'not_vulnerable', 'sql_injection', 'xss', 'hardcoded_credentials',
    'command_injection', 'path_traversal', 'insecure_deserialization'
]

NEW_SAMPLES = {
    'not_vulnerable': [
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        'cursor.execute("SELECT * FROM orders WHERE user_id = %s AND status = %s", (uid, status))',
        'cursor.execute("INSERT INTO logs (action, user_id) VALUES (%s, %s)", (action, uid))',
        'cursor.execute("UPDATE users SET name = %s WHERE id = %s", (name, user_id))',
        'cursor.execute("DELETE FROM sessions WHERE expires < %s", (now,))',
        'cursor.execute("SELECT * FROM products WHERE category = ? AND price < ?", (cat, max_price))',
        'session.query(User).filter(User.id == user_id).first()',
        'session.query(Order).filter(Order.user_id == uid).all()',
        'db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})',
        'cursor.executemany("INSERT INTO records (a, b) VALUES (%s, %s)", data)',
        'cursor.execute("SELECT * FROM accounts WHERE account_id = %s FOR UPDATE", (account_id,))',
        'await pool.execute("SELECT * FROM users WHERE id = $1", [user_id])',
        'cursor.execute("SELECT * FROM users WHERE name LIKE %s", (f"%{search}%",))',
        'cursor.execute("SELECT * FROM products WHERE id = ANY(%s)", (product_ids,))',
        'cur.execute("SELECT * FROM events WHERE created_at > %s", (since,))',
        'cursor.execute("SELECT u.* FROM users u JOIN profiles p ON u.id = p.user_id WHERE u.id = %s", (uid,))',
        'session.query(User).filter(User.email == email).one()',
        'cursor.execute("SELECT count(*) FROM orders WHERE user_id = %s", (uid,))',
        'db.execute(text("UPDATE accounts SET balance = balance - :amount WHERE id = :id"), {"amount": amt, "id": acc_id})',
        'cursor.execute("SELECT * FROM logs WHERE level = %s AND timestamp > %s", (level, since))',
        'val = os.environ.get("API_KEY")',
        'config = json.load(open("config.json"))',
        'result = requests.get(url, timeout=10)',
        'data = response.json()',
        'with open("output.txt", "w") as f: f.write(content)',
        'import hashlib; h = hashlib.sha256(data.encode()).hexdigest()',
        'timestamp = datetime.now().isoformat()',
        'output = subprocess.run(["ls", "-la"], capture_output=True, text=True)',
        'items = [x for x in range(10) if x % 2 == 0]',
        'result = sum(numbers) / len(numbers)',
    ],
    'insecure_deserialization': [
        'pickle.loads(user_data)',
        'pickle.load(f)',
        'data = pickle.loads(request.cookies.get("session_data"))',
        'obj = pickle.loads(base64.b64decode(token))',
        'payload = pickle.loads(encrypted_payload)',
        'cache = pickle.load(open("cache.pkl", "rb"))',
        'model = pickle.load(request.files["model"])',
        'state = pickle.loads(os.environ["SESSION_STATE"])',
        'yaml.load(raw_config)',
        'yaml.load(open("config.yaml"))',
        'config = yaml.load(request.data)',
        'settings = yaml.load(user_input)',
        'data = yaml.load(form_data.decode())',
        'marshal.loads(bytecode)',
        'code = marshal.loads(serialized_code)',
        'shelve.open("database")',
        'obj = pickle.loads(bytes.fromhex(hex_data))',
        'session_data = pickle.loads(redis.get("session"))',
        'params = pickle.loads(base64.b64decode(request.args["data"]))',
        'import dill; func = dill.loads(pickled_func)',
    ],
}


def main():
    print("=" * 60)
    print("TRAINING CODEBERT CLASSIFIER (AUGMENTED)")
    print("=" * 60)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Device: {device}")

    csv_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'code', 'cve_dataset.csv')
    df = pd.read_csv(csv_path)

    # Augment
    for label, samples in NEW_SAMPLES.items():
        for code in samples:
            df = pd.concat([df, pd.DataFrame({'code': [code], 'label': [label]})], ignore_index=True)

    print(f"Dataset: {len(df)} samples")
    print(df['label'].value_counts().to_string())

    label_map = {cls: idx for idx, cls in enumerate(VULNERABILITY_CLASSES)}
    codes = df['code'].tolist()
    labels = np.array([label_map[l] for l in df['label']])

    print("Loading CodeBERT...")
    tokenizer = RobertaTokenizer.from_pretrained('microsoft/codebert-base')
    model = RobertaForSequenceClassification.from_pretrained(
        'microsoft/codebert-base', num_labels=len(VULNERABILITY_CLASSES)
    ).to(device)

    print("Tokenizing...")
    encodings = tokenizer(codes, add_special_tokens=True, max_length=64,
                          padding='max_length', truncation=True,
                          return_attention_mask=True)

    input_ids = torch.tensor(encodings['input_ids'])
    attention_mask = torch.tensor(encodings['attention_mask'])
    label_tensor = torch.tensor(labels, dtype=torch.long)

    dataset = TensorDataset(input_ids, attention_mask, label_tensor)
    dataloader = DataLoader(dataset, batch_size=32, shuffle=True)

    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5)
    class_counts = np.bincount(labels, minlength=len(VULNERABILITY_CLASSES))
    weights = torch.FloatTensor(len(labels) / (len(VULNERABILITY_CLASSES) * class_counts)).to(device)
    criterion = nn.CrossEntropyLoss(weight=weights)

    epochs = 6
    print(f"\nTraining {epochs} epochs, {len(dataloader)} batches/epoch...")

    model.train()
    for epoch in range(epochs):
        total_loss = 0
        correct = 0
        total = 0
        for i, batch in enumerate(dataloader):
            ids, mask, lbl = [b.to(device) for b in batch]
            outputs = model(input_ids=ids, attention_mask=mask)
            loss = criterion(outputs.logits, lbl)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            preds = torch.argmax(outputs.logits, dim=1)
            correct += (preds == lbl).sum().item()
            total += lbl.size(0)

        acc = correct / total * 100
        print(f"  Epoch {epoch+1}/{epochs} — loss: {total_loss/len(dataloader):.4f}, acc: {acc:.1f}%")

    # Save
    weights_dir = os.path.join(os.path.dirname(__file__), '..', 'services', 'code', 'models', 'weights', 'codebert_classifier')
    os.makedirs(weights_dir, exist_ok=True)
    model.save_pretrained(weights_dir)
    tokenizer.save_pretrained(weights_dir)
    print(f"\nSaved to {weights_dir}")

    # Sanity checks
    print("\n" + "=" * 60)
    print("SANITY CHECKS")
    print("=" * 60)
    model.eval()
    tests = [
        ('sql_injection', 'query = "SELECT * FROM users WHERE id=" + user_input'),
        ('sql_injection', 'const q = "UPDATE users SET name=\'" + name + "\' WHERE id=" + id'),
        ('not_vulnerable', 'cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))'),
        ('not_vulnerable', 'session.query(User).filter(User.id == user_id).first()'),
        ('not_vulnerable', 'db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": uid})'),
        ('xss', 'document.innerHTML = userInput'),
        ('xss', 'element.insertAdjacentHTML("beforeend", userContent)'),
        ('hardcoded_credentials', 'password = "supersecret123"'),
        ('hardcoded_credentials', 'api_key = "sk-1234567890abcdef"'),
        ('command_injection', 'os.system("cat " + filename)'),
        ('command_injection', 'subprocess.call("ping " + host, shell=True)'),
        ('path_traversal', 'open("/etc/passwd" + user_input)'),
        ('path_traversal', 'readFile(req.query.path)'),
        ('insecure_deserialization', 'pickle.loads(user_data)'),
        ('insecure_deserialization', 'yaml.load(raw_config)'),
        ('not_vulnerable', 'result = requests.get(url, timeout=10)'),
        ('not_vulnerable', 'data = json.loads(response.text)'),
    ]
    for expected, code in tests:
        enc = tokenizer(code, add_special_tokens=True, max_length=64,
                       padding='max_length', truncation=True,
                       return_attention_mask=True, return_tensors='pt')
        with torch.no_grad():
            out = model(input_ids=enc['input_ids'].to(device),
                       attention_mask=enc['attention_mask'].to(device))
        probs = torch.softmax(out.logits, dim=1)[0]
        pred_idx = torch.argmax(probs).item()
        pred_class = VULNERABILITY_CLASSES[pred_idx]
        conf = probs[pred_idx].item()
        status = "OK" if pred_class == expected else "FAIL"
        print(f"  [{status}] {expected:30s} -> {pred_class:30s} {conf:.0%}  | {code[:45]}")


if __name__ == '__main__':
    main()
