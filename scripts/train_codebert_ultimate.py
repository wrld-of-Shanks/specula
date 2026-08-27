import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'code'))

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from transformers import RobertaTokenizer, RobertaForSequenceClassification
from torch.utils.data import Dataset, DataLoader, Subset
from sklearn.metrics import classification_report

from _paths import data_path, model_path

# Must match the 7 classes expected by backend/services/code/models/codebert_classifier.py
VULNERABILITY_CLASSES = [
    'not_vulnerable',
    'sql_injection',
    'xss',
    'hardcoded_credentials',
    'command_injection',
    'path_traversal',
    'insecure_deserialization'
]

class CodeDataset(Dataset):
    def __init__(self, codes, labels, tokenizer, max_length=64):
        self.codes = codes
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length
    
    def __len__(self):
        return len(self.codes)
    
    def __getitem__(self, idx):
        code = str(self.codes[idx])
        label = self.labels[idx]
        
        encoding = self.tokenizer(
            code,
            add_special_tokens=True,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt'
        )
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }

def train_codebert_ultimate():
    print("=" * 60)
    print("TRAINING CODEBERT CLASSIFIER (ULTIMATE FAST MODE)")
    print("=" * 60)
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    csv_path = data_path('code', 'cve_dataset.csv')
    df = pd.read_csv(csv_path)
    
    print(f"Full dataset size: {len(df)}")
    
    label_map = {cls: idx for idx, cls in enumerate(VULNERABILITY_CLASSES)}
    
    sampled_df = df.groupby('label').apply(lambda x: x.sample(min(500, len(x)), random_state=42)).reset_index(drop=True)
    
    print(f"Sampled dataset size: {len(sampled_df)}")
    
    codes = sampled_df['code'].tolist()
    labels = [label_map[label] for label in sampled_df['label'].tolist()]
    
    indices = np.random.permutation(len(codes))
    codes = [codes[i] for i in indices]
    labels = [labels[i] for i in indices]
    
    split_idx = int(len(codes) * 0.8)
    train_codes, val_codes = codes[:split_idx], codes[split_idx:]
    train_labels, val_labels = labels[:split_idx], labels[split_idx:]
    
    print(f"Train size: {len(train_codes)}")
    print(f"Val size: {len(val_codes)}")
    
    print("Loading CodeBERT...")
    tokenizer = RobertaTokenizer.from_pretrained('microsoft/codebert-base')
    model = RobertaForSequenceClassification.from_pretrained(
        'microsoft/codebert-base',
        num_labels=len(VULNERABILITY_CLASSES)
    ).to(device)
    
    for param in model.roberta.parameters():
        param.requires_grad = False
    
    for param in model.roberta.encoder.layer[-2:].parameters():
        param.requires_grad = True
    
    train_dataset = CodeDataset(train_codes, train_labels, tokenizer)
    val_dataset = CodeDataset(val_codes, val_labels, tokenizer)
    
    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=64, shuffle=False)
    
    optimizer = torch.optim.AdamW(filter(lambda p: p.requires_grad, model.parameters()), lr=5e-5)
    
    class_counts = np.bincount(train_labels)
    class_weights = torch.FloatTensor(
        len(train_labels) / (len(VULNERABILITY_CLASSES) * class_counts)
    ).to(device)
    criterion = nn.CrossEntropyLoss(weight=class_weights)
    
    epochs = 2
    print(f"\nTraining for {epochs} epochs...")
    
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        correct = 0
        total = 0
        
        for batch_idx, batch in enumerate(train_loader):
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)
            
            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask
            )
            
            loss = criterion(outputs.logits, labels)
            total_loss += loss.item()
            
            _, predicted = torch.max(outputs.logits, 1)
            correct += (predicted == labels).sum().item()
            total += labels.size(0)
            
            loss.backward()
            optimizer.step()
            optimizer.zero_grad()
            
            if (batch_idx + 1) % 3 == 0:
                print(f"  Epoch {epoch+1}, Batch {batch_idx+1}/{len(train_loader)}, Loss: {loss.item():.4f}")
        
        avg_loss = total_loss / len(train_loader)
        accuracy = correct / total * 100
        print(f"\nEpoch {epoch+1}/{epochs} - Avg Loss: {avg_loss:.4f}, Train Accuracy: {accuracy:.1f}%")
        
        model.eval()
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                labels = batch['labels'].to(device)
                
                outputs = model(
                    input_ids=input_ids,
                    attention_mask=attention_mask
                )
                
                _, predicted = torch.max(outputs.logits, 1)
                all_preds.extend(predicted.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
        
        val_accuracy = sum(p == l for p, l in zip(all_preds, all_labels)) / len(all_labels) * 100
        print(f"Val Accuracy: {val_accuracy:.1f}%")
    
    print(f"\n{'='*60}")
    print("CODEBERT EVALUATION RESULTS")
    print(f"{'='*60}")
    print("\nClassification Report:")
    print(classification_report(
        all_labels, all_preds,
        target_names=VULNERABILITY_CLASSES,
        zero_division=0
    ))
    
    save_path = model_path('codebert_classifier')
    os.makedirs(save_path, exist_ok=True)
    model.save_pretrained(save_path)
    tokenizer.save_pretrained(save_path)
    print(f"\nModel saved to: {save_path}")
    
    return model, tokenizer

if __name__ == '__main__':
    model, tokenizer = train_codebert_ultimate()
