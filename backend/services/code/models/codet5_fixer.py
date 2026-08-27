import os
import torch
from transformers import T5Tokenizer, T5ForConditionalGeneration
from torch.utils.data import Dataset, DataLoader
import pandas as pd

class FixDataset(Dataset):
    def __init__(self, vulnerable_codes, fixed_codes, tokenizer, max_length=512):
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

class CodeT5Fixer:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.is_trained = False
        self.load_model()
        
    def is_loaded(self):
        return self.is_trained
    
    def load_pretrained(self):
        self.tokenizer = T5Tokenizer.from_pretrained('Salesforce/codet5-base')
        self.model = T5ForConditionalGeneration.from_pretrained(
            'Salesforce/codet5-base'
        ).to(self.device)
    
    def train(self, data_path, epochs=3, batch_size=8, learning_rate=3e-5):
        df = pd.read_csv(data_path)
        
        self.load_pretrained()
        
        vulnerable_codes = df['vulnerable'].tolist()
        fixed_codes = df['fixed'].tolist()
        
        dataset = FixDataset(vulnerable_codes, fixed_codes, self.tokenizer)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=learning_rate)
        
        self.model.train()
        
        for epoch in range(epochs):
            total_loss = 0
            for batch in dataloader:
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels = batch['labels'].to(self.device)
                
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=labels
                )
                
                loss = outputs.loss
                total_loss += loss.item()
                
                loss.backward()
                optimizer.step()
                optimizer.zero_grad()
            
            print(f"Epoch {epoch + 1}/{epochs}, Loss: {total_loss / len(dataloader):.4f}")
        
        self.is_trained = True
        self.save_model()
        
        return {'epochs': epochs, 'final_loss': total_loss / len(dataloader)}
    
    def generate_fix(self, vulnerable_code, vulnerability_type=None):
        if not self.is_trained:
            return {
                'fix': None,
                'confidence': 0.0,
                'original': vulnerable_code,
                'message': 'Fix model not trained yet. Train with /train endpoint first.'
            }
        
        prompt = f"fix: {vulnerable_code}"
        
        encoding = self.tokenizer(
            prompt,
            add_special_tokens=True,
            max_length=512,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt'
        )
        
        input_ids = encoding['input_ids'].to(self.device)
        attention_mask = encoding['attention_mask'].to(self.device)
        
        with torch.no_grad():
            outputs = self.model.generate(
                input_ids=input_ids,
                attention_mask=attention_mask,
                max_length=512,
                num_beams=5,
                early_stopping=True,
                no_repeat_ngram_size=3
            )
        
        fixed_code = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        bleu_score = self._calculate_bleu(vulnerable_code, fixed_code)
        
        return {
            'fix': fixed_code,
            'confidence': bleu_score,
            'original': vulnerable_code
        }
    
    def _calculate_bleu(self, reference, hypothesis):
        from nltk.translate.bleu_score import sentence_bleu
        
        reference_tokens = reference.split()
        hypothesis_tokens = hypothesis.split()
        
        if not hypothesis_tokens:
            return 0.0
        
        try:
            score = sentence_bleu([reference_tokens], hypothesis_tokens)
            return score
        except:
            return 0.0
    
    def save_model(self, path=None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'weights', 'codet5_fixer')
        os.makedirs(path, exist_ok=True)
        self.model.save_pretrained(path)
        self.tokenizer.save_pretrained(path)
    
    def load_model(self, path=None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'weights', 'codet5_fixer')
        if os.path.exists(path):
            try:
                self.model = T5ForConditionalGeneration.from_pretrained(path).to(self.device)
                self.tokenizer = T5Tokenizer.from_pretrained(path)
                self.is_trained = True
                return True
            except Exception:
                return False
        return False
