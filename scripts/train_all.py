#!/usr/bin/env python3
import subprocess
import sys
import os

def run_script(script_name, description):
    print(f"\n{'='*70}")
    print(f"  {description}")
    print(f"{'='*70}\n")
    
    result = subprocess.run(
        [sys.executable, script_name],
        capture_output=False,
        text=True
    )
    
    if result.returncode != 0:
        print(f"\n[ERROR] {description} failed with return code {result.returncode}")
        return False
    
    print(f"\n[SUCCESS] {description} completed")
    return True

def main():
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("=" * 70)
    print("  SPECULA - COMPLETE MODEL TRAINING PIPELINE")
    print("=" * 70)
    
    training_scripts = [
        ('train_xgboost.py', 'Training XGBoost Classifier (Network Module)'),
        ('train_isolation_forest.py', 'Training Isolation Forest (Network Module)'),
        ('train_codebert.py', 'Training CodeBERT Classifier (Code Module)'),
        ('train_codet5.py', 'Training CodeT5 Fix Generator (Code Module)'),
    ]
    
    results = {}
    
    for script, description in training_scripts:
        script_path = os.path.join(scripts_dir, script)
        success = run_script(script_path, description)
        results[description] = success
    
    print("\n" + "=" * 70)
    print("  TRAINING SUMMARY")
    print("=" * 70)
    
    for description, success in results.items():
        status = "[OK]" if success else "[FAILED]"
        print(f"  {status} {description}")
    
    all_success = all(results.values())
    
    if all_success:
        print("\n" + "=" * 70)
        print("  ALL MODELS TRAINED SUCCESSFULLY!")
        print("=" * 70)
        print("\nModels saved to:")
        print("  - services/network/models/weights/xgboost_model.pkl")
        print("  - services/network/models/weights/isolation_forest.pkl")
        print("  - services/code/models/weights/codebert_classifier/")
        print("  - services/code/models/weights/codet5_fixer/")
    else:
        print("\n[WARNING] Some models failed to train. Check errors above.")
    
    return all_success

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
