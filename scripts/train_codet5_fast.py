import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'code'))

import pandas as pd
import numpy as np
import torch
from transformers import RobertaTokenizer, T5ForConditionalGeneration
from torch.utils.data import Dataset, DataLoader
from nltk.translate.bleu_score import sentence_bleu

from _paths import data_path, model_path

class FixDataset(Dataset):
    def __init__(self, vulnerable_codes, fixed_codes, tokenizer, max_length=64):
        self.vulnerable_codes = vulnerable_codes
        self.fixed_codes = fixed_codes
        self.tokenizer = tokenizer
        self.max_length = max_length
    
    def __len__(self):
        return len(self.vulnerable_codes)
    
    def __getitem__(self, idx):
        vulnerable = str(self.vulnerable_codes[idx])
        fixed = str(self.fixed_codes[idx])
        
        input_encoding = self.tokenizer(
            f"fix: {vulnerable}",
            add_special_tokens=True,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt'
        )
        
        target_encoding = self.tokenizer(
            fixed,
            add_special_tokens=True,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )
        
        labels = target_encoding['input_ids'].flatten()
        labels[labels == self.tokenizer.pad_token_id] = -100
        
        return {
            'input_ids': input_encoding['input_ids'].flatten(),
            'attention_mask': input_encoding['attention_mask'].flatten(),
            'labels': labels
        }

def train_codet5_fast():
    print("=" * 60)
    print("TRAINING CODET5 FIX GENERATOR (FAST MODE)")
    print("=" * 60)
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    csv_path = data_path('code', 'fixes_dataset.csv')
    df = pd.read_csv(csv_path)
    
    print(f"Dataset size: {len(df)} fix pairs")
    
    vulnerable_codes = df['vulnerable'].tolist()
    fixed_codes = df['fixed'].tolist()
    
    split_idx = int(len(vulnerable_codes) * 0.8)
    train_vuln, val_vuln = vulnerable_codes[:split_idx], vulnerable_codes[split_idx:]
    train_fix, val_fix = fixed_codes[:split_idx], fixed_codes[split_idx:]
    
    print(f"Train size: {len(train_vuln)}")
    print(f"Val size: {len(val_vuln)}")
    
    print("Loading CodeT5...")
    tokenizer = RobertaTokenizer.from_pretrained('Salesforce/codet5-base')
    model = T5ForConditionalGeneration.from_pretrained(
        'Salesforce/codet5-base'
    ).to(device)
    
    for param in model.encoder.parameters():
        param.requires_grad = False
    
    for param in model.encoder.block[-2:].parameters():
        param.requires_grad = True
    
    train_dataset = FixDataset(train_vuln, train_fix, tokenizer)
    val_dataset = FixDataset(val_vuln, val_fix, tokenizer)
    
    train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=16, shuffle=False)
    
    optimizer = torch.optim.AdamW(filter(lambda p: p.requires_grad, model.parameters()), lr=5e-5)
    
    epochs = 2
    print(f"\nTraining for {epochs} epochs...")
    
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        
        for batch_idx, batch in enumerate(train_loader):
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['labels'].to(device)
            
            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                labels=labels
            )
            
            loss = outputs.loss
            total_loss += loss.item()
            
            loss.backward()
            optimizer.step()
            optimizer.zero_grad()
            
            if (batch_idx + 1) % 5 == 0:
                print(f"  Epoch {epoch+1}, Batch {batch_idx+1}/{len(train_loader)}, Loss: {loss.item():.4f}")
        
        avg_loss = total_loss / len(train_loader)
        print(f"\nEpoch {epoch+1}/{epochs} - Avg Loss: {avg_loss:.4f}")
        
        model.eval()
        bleu_scores = []
        exact_matches = 0
        
        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                
                outputs = model.generate(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    max_length=64,
                    num_beams=3,
                    early_stopping=True
                )
                
                for i, output in enumerate(outputs):
                    generated = tokenizer.decode(output, skip_special_tokens=True)
                    reference = val_fix[min(batch_idx * 16 + i, len(val_fix) - 1)]
                    
                    ref_tokens = reference.split()
                    gen_tokens = generated.split()
                    
                    if gen_tokens:
                        try:
                            bleu = sentence_bleu([ref_tokens], gen_tokens)
                            bleu_scores.append(bleu)
                        except:
                            bleu_scores.append(0)
                    
                    if generated.strip() == reference.strip():
                        exact_matches += 1
        
        avg_bleu = np.mean(bleu_scores) if bleu_scores else 0
        exact_match_rate = exact_matches / len(val_vuln) * 100
        
        print(f"Val BLEU: {avg_bleu:.4f}")
        print(f"Val Exact Match: {exact_match_rate:.1f}%")
    
    print(f"\n{'='*60}")
    print("CODET5 EVALUATION RESULTS")
    print(f"{'='*60}")
    print(f"\nFinal BLEU Score: {avg_bleu:.4f}")
    print(f"Final Exact Match Rate: {exact_match_rate:.1f}%")
    
    save_path = model_path('codet5_fixer')
    os.makedirs(save_path, exist_ok=True)
    model.save_pretrained(save_path)
    tokenizer.save_pretrained(save_path)
    print(f"\nModel saved to: {save_path}")
    
    return model, tokenizer

if __name__ == '__main__':
    model, tokenizer = train_codet5_fast()
