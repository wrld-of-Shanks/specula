import os
import torch
import torch.nn as nn
from transformers import RobertaTokenizer, RobertaForSequenceClassification
from torch.utils.data import Dataset, DataLoader
import pandas as pd
import numpy as np
from models.rule_classifier import RuleBasedClassifier, VULNERABILITY_CLASSES as RULE_CLASSES, CWE_MAPPING as RULE_CWE

VULNERABILITY_CLASSES = [
    'not_vulnerable',
    'sql_injection',
    'xss',
    'hardcoded_credentials',
    'command_injection',
    'path_traversal',
    'insecure_deserialization'
]

CWE_MAPPING = {
    'not_vulnerable': 'N/A',
    'sql_injection': 'CWE-89',
    'xss': 'CWE-79',
    'hardcoded_credentials': 'CWE-798',
    'command_injection': 'CWE-78',
    'path_traversal': 'CWE-22',
    'insecure_deserialization': 'CWE-502'
}

class CodeDataset(Dataset):
    def __init__(self, codes, labels, tokenizer, max_length=512):
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

class CodeBERTClassifier:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.is_trained = False
        self.load_model()
        
    def is_loaded(self):
        return self.is_trained
    
    def load_pretrained(self):
        self.tokenizer = RobertaTokenizer.from_pretrained('microsoft/codebert-base')
        self.model = RobertaForSequenceClassification.from_pretrained(
            'microsoft/codebert-base',
            num_labels=len(VULNERABILITY_CLASSES)
        ).to(self.device)
    
    def train(self, data_path, epochs=5, batch_size=16, learning_rate=2e-5):
        df = pd.read_csv(data_path)
        
        self.load_pretrained()
        
        label_map = {cls: idx for idx, cls in enumerate(VULNERABILITY_CLASSES)}
        codes = df['code'].tolist()
        labels = [label_map.get(label, 0) for label in df['label'].tolist()]
        
        dataset = CodeDataset(codes, labels, self.tokenizer)
        dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        optimizer = torch.optim.AdamW(self.model.parameters(), lr=learning_rate)
        
        class_counts = np.bincount(labels)
        class_weights = torch.FloatTensor(
            len(labels) / (len(VULNERABILITY_CLASSES) * class_counts)
        ).to(self.device)
        criterion = nn.CrossEntropyLoss(weight=class_weights)
        
        self.model.train()
        
        for epoch in range(epochs):
            total_loss = 0
            for batch in dataloader:
                input_ids = batch['input_ids'].to(self.device)
                attention_mask = batch['attention_mask'].to(self.device)
                labels = batch['labels'].to(self.device)
                
                outputs = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask
                )
                
                loss = criterion(outputs.logits, labels)
                total_loss += loss.item()
                
                loss.backward()
                optimizer.step()
                optimizer.zero_grad()
            
            print(f"Epoch {epoch + 1}/{epochs}, Loss: {total_loss / len(dataloader):.4f}")
        
        self.is_trained = True
        self.save_model()
        
        return {'epochs': epochs, 'final_loss': total_loss / len(dataloader)}
    
    def classify(self, code):
        if not self.is_trained:
            fallback = RuleBasedClassifier()
            return fallback.classify(code)
        
        encoding = self.tokenizer(
            code,
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
            outputs = self.model(
                input_ids=input_ids,
                attention_mask=attention_mask
            )
        
        probabilities = torch.softmax(outputs.logits, dim=1)[0]
        predicted_class = torch.argmax(probabilities).item()
        confidence = probabilities[predicted_class].item()
        
        top_predictions = []
        sorted_probs = torch.argsort(probabilities, descending=True)
        for idx in sorted_probs[:3]:
            top_predictions.append({
                'class': VULNERABILITY_CLASSES[idx.item()],
                'cwe': CWE_MAPPING[VULNERABILITY_CLASSES[idx.item()]],
                'confidence': probabilities[idx].item()
            })
        
        return {
            'prediction': VULNERABILITY_CLASSES[predicted_class],
            'cwe': CWE_MAPPING[VULNERABILITY_CLASSES[predicted_class]],
            'confidence': confidence,
            'top_predictions': top_predictions
        }
    
    def save_model(self, path=None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'weights', 'codebert_classifier')
        os.makedirs(path, exist_ok=True)
        self.model.save_pretrained(path)
        self.tokenizer.save_pretrained(path)
    
    def load_model(self, path=None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'weights', 'codebert_classifier')
        if os.path.exists(path):
            self.model = RobertaForSequenceClassification.from_pretrained(path).to(self.device)
            self.tokenizer = RobertaTokenizer.from_pretrained(path)
            self.is_trained = True
            return True
        return False
