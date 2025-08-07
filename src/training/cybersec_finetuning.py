#!/usr/bin/env python3
"""
Cybersecurity Fine-Tuning Pipeline for Free Models
Specialized training for security domain without external restrictions
"""

import json
import logging
import asyncio
import os
import subprocess
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
import yaml
import time
import hashlib
from dataclasses import dataclass

@dataclass
class FineTuningConfig:
    """Configuration for cybersecurity fine-tuning"""
    model_name: str
    base_model: str
    dataset_path: str
    output_path: str
    training_args: Dict[str, Any]
    security_focus: str = "general"
    filter_override: bool = True
    domain_specialization: str = "cybersecurity"

class CybersecurityDatasetBuilder:
    """
    Builds cybersecurity training datasets from multiple sources
    Focuses on legitimate security research and professional use
    """
    
    def __init__(self, output_dir: str = "data/cybersec_training"):
        self.logger = logging.getLogger(__name__)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Security domain categories
        self.security_domains = {
            "vulnerability_assessment": "Network and application vulnerability analysis",
            "malware_analysis": "Malware reverse engineering and analysis",
            "penetration_testing": "Ethical hacking and security testing",
            "incident_response": "Security incident handling and forensics", 
            "threat_intelligence": "Threat analysis and intelligence gathering",
            "security_tools": "Development and usage of security tools",
            "compliance": "Security compliance and risk management",
            "cryptography": "Cryptographic implementations and analysis"
        }
    
    def generate_training_data(self) -> Dict[str, str]:
        """Generate comprehensive cybersecurity training data"""
        
        self.logger.info("🔒 Generating cybersecurity training dataset...")
        
        training_data = {
            "conversations": [],
            "instructions": [],
            "code_examples": [],
            "analysis_cases": []
        }
        
        # Generate domain-specific training data
        for domain, description in self.security_domains.items():
            domain_data = self._generate_domain_data(domain, description)
            training_data["conversations"].extend(domain_data["conversations"])
            training_data["instructions"].extend(domain_data["instructions"])
            training_data["code_examples"].extend(domain_data["code_examples"])
            training_data["analysis_cases"].extend(domain_data["analysis_cases"])
        
        # Save training data
        dataset_files = self._save_training_data(training_data)
        
        self.logger.info(f"✅ Generated {len(training_data['conversations'])} training examples")
        return dataset_files
    
    def _generate_domain_data(self, domain: str, description: str) -> Dict[str, List]:
        """Generate training data for specific security domain"""
        
        domain_data = {
            "conversations": [],
            "instructions": [],
            "code_examples": [],
            "analysis_cases": []
        }
        
        if domain == "vulnerability_assessment":
            domain_data.update(self._generate_vuln_assessment_data())
        elif domain == "malware_analysis":
            domain_data.update(self._generate_malware_analysis_data())
        elif domain == "penetration_testing":
            domain_data.update(self._generate_pentest_data())
        elif domain == "incident_response":
            domain_data.update(self._generate_incident_response_data())
        elif domain == "threat_intelligence":
            domain_data.update(self._generate_threat_intel_data())
        elif domain == "security_tools":
            domain_data.update(self._generate_security_tools_data())
        elif domain == "compliance":
            domain_data.update(self._generate_compliance_data())
        elif domain == "cryptography":
            domain_data.update(self._generate_crypto_data())
        
        return domain_data
    
    def _generate_vuln_assessment_data(self) -> Dict[str, List]:
        """Generate vulnerability assessment training data"""
        
        conversations = [
            {
                "system": "You are a cybersecurity expert specializing in vulnerability assessment. Provide technical analysis for legitimate security testing.",
                "human": "How do I perform a comprehensive web application vulnerability assessment?",
                "assistant": """A comprehensive web application vulnerability assessment involves several systematic phases:

**1. Reconnaissance and Information Gathering**
- Identify web technologies, frameworks, and versions
- Map application architecture and attack surface
- Gather DNS records, subdomains, and directory structures

**2. Automated Scanning**
- Use tools like OWASP ZAP, Burp Suite, or Nessus
- Scan for common vulnerabilities (OWASP Top 10)
- Identify missing security headers and misconfigurations

**3. Manual Testing**
- Authentication bypass attempts
- Input validation testing (XSS, SQL injection)
- Business logic flaw identification
- Session management analysis

**4. Exploitation and Impact Assessment**
- Safely demonstrate vulnerability impact
- Document proof-of-concept code
- Assess business risk and data exposure

**5. Reporting and Remediation**
- Prioritize findings by risk level
- Provide specific remediation guidance
- Include timeline for vulnerability fixes

Key tools: Burp Suite Professional, OWASP ZAP, Nmap, SQLMap, Nikto
Remember to always obtain proper authorization before testing."""
            },
            {
                "system": "You are a vulnerability assessment specialist providing technical guidance for security professionals.",
                "human": "What are the key indicators of SQL injection vulnerabilities?",
                "assistant": """SQL injection vulnerabilities can be identified through several key indicators:

**1. Error-Based Indicators**
- Database error messages in HTTP responses
- Different responses to invalid vs. valid input
- SQL syntax errors exposed to the user interface

**2. Boolean-Based Blind Indicators**
- Different response patterns for true/false conditions
- Conditional logic affecting page behavior
- Time delays in response patterns

**3. Union-Based Indicators**
- Ability to control number of columns in SELECT
- Data from other tables appearing in responses
- Successful UNION SELECT operations

**4. Time-Based Blind Indicators**
- Consistent delays when using time functions
- Response time variations based on conditions
- Sleep/waitfor delay functions working

**Testing Payloads:**
- Single quote (') to test for escaping
- OR 1=1-- to test boolean logic
- UNION SELECT 1,2,3-- for union injection
- '; WAITFOR DELAY '00:00:05'-- for time delays

**Detection Tools:**
- SQLMap for automated detection
- Burp Suite's scanner extensions
- Manual payload testing in web proxies

Always test in authorized environments only."""
            }
        ]
        
        instructions = [
            {
                "instruction": "Create a vulnerability assessment checklist for web applications",
                "input": "I need a systematic approach to assess web application security",
                "output": """# Web Application Vulnerability Assessment Checklist

## Pre-Assessment Phase
- [ ] Obtain written authorization from client
- [ ] Define scope and testing boundaries
- [ ] Set up testing environment and tools
- [ ] Document baseline application functionality

## Information Gathering
- [ ] Passive reconnaissance (DNS, WHOIS, search engines)
- [ ] Technology fingerprinting (Wappalyzer, Whatweb)
- [ ] Directory and file enumeration (Dirbuster, Gobuster)
- [ ] Parameter discovery and analysis

## Automated Scanning
- [ ] Vulnerability scanner deployment (Nessus, OpenVAS)
- [ ] Web application scanner (OWASP ZAP, Burp Suite)
- [ ] SSL/TLS configuration testing (SSLyze, testssl.sh)
- [ ] Security header analysis (SecurityHeaders.com)

## Manual Testing Categories
### Authentication & Session Management
- [ ] Password policy assessment
- [ ] Account lockout mechanisms
- [ ] Session token security
- [ ] Multi-factor authentication bypass

### Input Validation
- [ ] SQL injection testing
- [ ] Cross-site scripting (XSS)
- [ ] Command injection
- [ ] Path traversal/directory traversal
- [ ] XML External Entity (XXE)

### Authorization & Access Control
- [ ] Vertical privilege escalation
- [ ] Horizontal privilege escalation
- [ ] Direct object references
- [ ] Function-level access control

### Business Logic
- [ ] Workflow bypass attempts
- [ ] Race conditions
- [ ] Price manipulation
- [ ] Process validation flaws

## Documentation & Reporting
- [ ] Evidence collection and screenshots
- [ ] Risk rating and impact analysis
- [ ] Remediation recommendations
- [ ] Executive summary preparation"""
            }
        ]
        
        code_examples = [
            {
                "description": "Python script for basic SQL injection testing",
                "language": "python",
                "code": """#!/usr/bin/env python3
\"\"\"
Basic SQL Injection Testing Script
For authorized penetration testing only
\"\"\"

import requests
import time
import sys
from urllib.parse import urljoin

class SQLInjectionTester:
    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "admin'--",
            "admin'/*",
            "' OR 1=1--",
            "') OR ('1'='1",
            "') OR ('1'='1'--"
        ]
    
    def test_parameter(self, param_name, param_value):
        \"\"\"Test a specific parameter for SQL injection\"\"\"
        results = []
        
        for payload in self.payloads:
            test_value = param_value + payload
            data = {param_name: test_value}
            
            try:
                response = self.session.post(self.target_url, data=data)
                
                # Check for common SQL error patterns
                sql_errors = [
                    'mysql_fetch_array',
                    'ORA-01756',
                    'Microsoft OLE DB Provider',
                    'SQLServer JDBC Driver',
                    'PostgreSQL query failed',
                    'Warning: mysql_',
                    'valid MySQL result',
                    'MySqlClient.MySqlException'
                ]
                
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        results.append({
                            'payload': payload,
                            'vulnerable': True,
                            'error_type': error,
                            'response_length': len(response.text)
                        })
                        break
                else:
                    results.append({
                        'payload': payload,
                        'vulnerable': False,
                        'response_length': len(response.text)
                    })
                
                # Add delay to avoid overwhelming the server
                time.sleep(0.5)
                
            except requests.exceptions.RequestException as e:
                print(f"Request error: {e}")
                continue
        
        return results
    
    def generate_report(self, test_results):
        \"\"\"Generate a vulnerability report\"\"\"
        vulnerable_payloads = [r for r in test_results if r['vulnerable']]
        
        print("\\n" + "="*50)
        print("SQL Injection Test Results")
        print("="*50)
        print(f"Target: {self.target_url}")
        print(f"Total payloads tested: {len(test_results)}")
        print(f"Vulnerable responses: {len(vulnerable_payloads)}")
        
        if vulnerable_payloads:
            print("\\nVULNERABLE PAYLOADS DETECTED:")
            for result in vulnerable_payloads:
                print(f"  Payload: {result['payload']}")
                print(f"  Error: {result.get('error_type', 'Unknown')}")
                print()
        else:
            print("\\nNo SQL injection vulnerabilities detected.")
        
        return len(vulnerable_payloads) > 0

# Usage example (authorized testing only)
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sqli_test.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    tester = SQLInjectionTester(target)
    
    # Test common parameter names
    common_params = ['username', 'user', 'login', 'id', 'search', 'q']
    
    for param in common_params:
        print(f"Testing parameter: {param}")
        results = tester.test_parameter(param, "test")
        tester.generate_report(results)"""
            }
        ]
        
        return {
            "conversations": conversations,
            "instructions": instructions,
            "code_examples": code_examples,
            "analysis_cases": []
        }
    
    def _generate_malware_analysis_data(self) -> Dict[str, List]:
        """Generate malware analysis training data"""
        
        conversations = [
            {
                "system": "You are a malware analyst providing technical guidance for security research and incident response.",
                "human": "What are the key steps in static malware analysis?",
                "assistant": """Static malware analysis involves examining malware samples without execution. Here's a systematic approach:

**1. Safe Environment Setup**
- Isolated analysis VM (no network connectivity)
- Snapshot-based rollback capability
- Proper tool installation (hex editors, disassemblers)

**2. Initial Triage**
- File type identification (file command, TrID)
- Hash calculation (MD5, SHA-1, SHA-256)
- Virus scanning (multiple engines)
- Packer/obfuscation detection (PEiD, Detect It Easy)

**3. Metadata Analysis**
- PE header examination (PE-bear, CFF Explorer)
- Import/export table analysis
- Resource section inspection
- Digital signature verification

**4. String Analysis**
- Printable string extraction (strings utility)
- Unicode string identification
- URL, IP, and registry key discovery
- Potential C2 infrastructure indicators

**5. Disassembly and Code Analysis**
- Disassembly with IDA Pro/Ghidra/x64dbg
- Control flow analysis
- Function identification and naming
- API call analysis

**6. Behavioral Indicators**
- Registry modification patterns
- File system operations
- Network communication protocols
- Persistence mechanisms

**Tools: IDA Pro, Ghidra, x64dbg, PE-bear, strings, Volatility**
**Remember: Always use isolated environments and proper containment.**"""
            }
        ]
        
        return {"conversations": conversations, "instructions": [], "code_examples": [], "analysis_cases": []}
    
    def _generate_pentest_data(self) -> Dict[str, List]:
        """Generate penetration testing training data"""
        
        conversations = [
            {
                "system": "You are a penetration testing expert providing guidance for authorized security testing.",
                "human": "How should I approach network penetration testing methodology?",
                "assistant": """Network penetration testing follows a structured methodology:

**1. Pre-Engagement**
- Scope definition and rules of engagement
- Legal authorization and contracts
- Emergency contact procedures
- Testing timeline establishment

**2. Information Gathering**
- Passive reconnaissance (OSINT)
- DNS enumeration and zone transfers
- Network range identification
- Social media intelligence gathering

**3. Active Scanning**
- Host discovery (Nmap ping sweeps)
- Port scanning and service enumeration
- OS fingerprinting and version detection
- Vulnerability scanning (Nessus, OpenVAS)

**4. Enumeration**
- Service-specific enumeration
- SMB/NetBIOS information gathering
- SNMP community string testing
- Web service fingerprinting

**5. Vulnerability Assessment**
- CVE research and validation
- Custom vulnerability verification
- False positive elimination
- Impact and exploitability analysis

**6. Exploitation**
- Proof-of-concept development
- Privilege escalation attempts
- Lateral movement techniques
- Data exfiltration simulation

**7. Post-Exploitation**
- Persistence establishment
- Additional system compromise
- Evidence collection and documentation
- Clean-up and artifact removal

**Tools: Nmap, Metasploit, Burp Suite, Cobalt Strike, BloodHound**
**Always maintain detailed logs and evidence for reporting.**"""
            }
        ]
        
        return {"conversations": conversations, "instructions": [], "code_examples": [], "analysis_cases": []}
    
    def _generate_incident_response_data(self) -> Dict[str, List]:
        """Generate incident response training data"""
        return {"conversations": [], "instructions": [], "code_examples": [], "analysis_cases": []}
    
    def _generate_threat_intel_data(self) -> Dict[str, List]:
        """Generate threat intelligence training data"""
        return {"conversations": [], "instructions": [], "code_examples": [], "analysis_cases": []}
    
    def _generate_security_tools_data(self) -> Dict[str, List]:
        """Generate security tools training data"""
        return {"conversations": [], "instructions": [], "code_examples": [], "analysis_cases": []}
    
    def _generate_compliance_data(self) -> Dict[str, List]:
        """Generate compliance training data"""
        return {"conversations": [], "instructions": [], "code_examples": [], "analysis_cases": []}
    
    def _generate_crypto_data(self) -> Dict[str, List]:
        """Generate cryptography training data"""
        return {"conversations": [], "instructions": [], "code_examples": [], "analysis_cases": []}
    
    def _save_training_data(self, training_data: Dict[str, List]) -> Dict[str, str]:
        """Save training data to files"""
        
        dataset_files = {}
        
        # Save conversations in ChatML format
        conversations_file = self.output_dir / "cybersec_conversations.jsonl"
        with open(conversations_file, 'w') as f:
            for conv in training_data["conversations"]:
                f.write(json.dumps(conv) + '\n')
        dataset_files["conversations"] = str(conversations_file)
        
        # Save instructions in Alpaca format
        instructions_file = self.output_dir / "cybersec_instructions.jsonl"
        with open(instructions_file, 'w') as f:
            for inst in training_data["instructions"]:
                f.write(json.dumps(inst) + '\n')
        dataset_files["instructions"] = str(instructions_file)
        
        # Save code examples
        code_file = self.output_dir / "cybersec_code.jsonl"
        with open(code_file, 'w') as f:
            for code in training_data["code_examples"]:
                f.write(json.dumps(code) + '\n')
        dataset_files["code"] = str(code_file)
        
        # Create combined dataset
        combined_file = self.output_dir / "cybersec_combined.jsonl"
        with open(combined_file, 'w') as f:
            # Convert conversations to instruction format
            for conv in training_data["conversations"]:
                combined_entry = {
                    "instruction": conv["human"],
                    "input": "",
                    "output": conv["assistant"],
                    "system": conv["system"]
                }
                f.write(json.dumps(combined_entry) + '\n')
            
            # Add instructions
            for inst in training_data["instructions"]:
                f.write(json.dumps(inst) + '\n')
        
        dataset_files["combined"] = str(combined_file)
        
        self.logger.info(f"✅ Saved training data to {len(dataset_files)} files")
        return dataset_files

class CybersecurityFineTuner:
    """
    Fine-tunes free models for cybersecurity domain
    Removes generic AI restrictions and optimizes for security tasks
    """
    
    def __init__(self, config_path: str = "configs/finetune_config.yaml"):
        self.logger = logging.getLogger(__name__)
        self.config_path = config_path
        self.config = self._load_config()
        
        # Security-focused training configuration
        self.security_training_args = {
            "learning_rate": 5e-5,
            "batch_size": 4,
            "gradient_accumulation_steps": 4,
            "max_seq_length": 2048,
            "num_epochs": 3,
            "warmup_ratio": 0.1,
            "save_steps": 500,
            "evaluation_strategy": "steps",
            "eval_steps": 500,
            "logging_steps": 100,
            "load_best_model_at_end": True,
            "remove_unused_columns": False,
            "dataloader_pin_memory": False
        }
    
    def _load_config(self) -> Dict[str, Any]:
        """Load fine-tuning configuration"""
        
        if Path(self.config_path).exists():
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            # Create default configuration
            return self._create_default_config()
    
    def _create_default_config(self) -> Dict[str, Any]:
        """Create default fine-tuning configuration"""
        
        config = {
            "models": [
                {
                    "name": "llama3_cybersec_ft",
                    "base_model": "meta-llama/Llama-2-7b-chat-hf",
                    "security_focus": "general",
                    "training_args": self.security_training_args
                },
                {
                    "name": "mistral_security_ft", 
                    "base_model": "mistralai/Mistral-7B-Instruct-v0.1",
                    "security_focus": "analysis",
                    "training_args": self.security_training_args
                }
            ],
            "dataset_config": {
                "train_ratio": 0.8,
                "eval_ratio": 0.1,
                "test_ratio": 0.1,
                "max_length": 2048
            },
            "security_overrides": {
                "remove_safety_filters": True,
                "domain_focus": "cybersecurity",
                "ethical_framework": "professional_security"
            }
        }
        
        # Save configuration
        Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        return config
    
    def prepare_dataset(self, dataset_file: str) -> str:
        """Prepare dataset for fine-tuning"""
        
        self.logger.info(f"📊 Preparing dataset from {dataset_file}")
        
        # Load dataset
        with open(dataset_file, 'r') as f:
            data = [json.loads(line) for line in f]
        
        self.logger.info(f"📚 Loaded {len(data)} training examples")
        
        # Split dataset
        train_size = int(len(data) * self.config["dataset_config"]["train_ratio"])
        eval_size = int(len(data) * self.config["dataset_config"]["eval_ratio"])
        
        train_data = data[:train_size]
        eval_data = data[train_size:train_size + eval_size]
        test_data = data[train_size + eval_size:]
        
        # Save splits
        dataset_dir = Path(dataset_file).parent / "splits"
        dataset_dir.mkdir(exist_ok=True)
        
        splits = {
            "train": train_data,
            "eval": eval_data,
            "test": test_data
        }
        
        split_files = {}
        for split_name, split_data in splits.items():
            split_file = dataset_dir / f"{split_name}.jsonl"
            with open(split_file, 'w') as f:
                for item in split_data:
                    f.write(json.dumps(item) + '\n')
            split_files[split_name] = str(split_file)
        
        self.logger.info(f"✅ Dataset prepared: {len(train_data)} train, {len(eval_data)} eval, {len(test_data)} test")
        return str(dataset_dir)
    
    def fine_tune_model(self, model_config: Dict[str, Any], dataset_dir: str) -> str:
        """Fine-tune model for cybersecurity domain"""
        
        self.logger.info(f"🔧 Fine-tuning {model_config['name']}...")
        
        # Create fine-tuning script
        finetune_script = f"""#!/usr/bin/env python3
import os
import json
import torch
from transformers import (
    AutoTokenizer, AutoModelForCausalLM, 
    TrainingArguments, Trainer, DataCollatorForLanguageModeling
)
from datasets import Dataset
from peft import LoraConfig, TaskType, get_peft_model

def load_dataset(file_path):
    with open(file_path, 'r') as f:
        data = [json.loads(line) for line in f]
    return Dataset.from_list(data)

def format_prompt(example):
    if "system" in example and example["system"]:
        return f"<s>[INST] <<SYS>>\\n{{example['system']}}\\n<</SYS>>\\n\\n{{example['instruction']}} [/INST] {{example['output']}} </s>"
    else:
        return f"<s>[INST] {{example['instruction']}} [/INST] {{example['output']}} </s>"

# Load model and tokenizer
model_name = "{model_config['base_model']}"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    torch_dtype=torch.float16,
    device_map="auto",
    trust_remote_code=True
)

# Add padding token
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

# Setup LoRA configuration for efficient fine-tuning
lora_config = LoraConfig(
    task_type=TaskType.CAUSAL_LM,
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "v_proj", "k_proj", "o_proj"],
    lora_dropout=0.1,
    bias="none"
)

model = get_peft_model(model, lora_config)

# Load and prepare datasets
train_dataset = load_dataset("{dataset_dir}/train.jsonl")
eval_dataset = load_dataset("{dataset_dir}/eval.jsonl")

def tokenize_function(examples):
    # Format prompts
    texts = [format_prompt(example) for example in examples]
    
    # Tokenize
    tokenized = tokenizer(
        texts,
        padding=True,
        truncation=True,
        max_length={model_config['training_args']['max_seq_length']},
        return_tensors="pt"
    )
    
    # Set labels for language modeling
    tokenized["labels"] = tokenized["input_ids"].clone()
    
    return tokenized

# Apply tokenization
train_dataset = train_dataset.map(tokenize_function, batched=True)
eval_dataset = eval_dataset.map(tokenize_function, batched=True)

# Training arguments
training_args = TrainingArguments(
    output_dir="{model_config['name']}_checkpoint",
    learning_rate={model_config['training_args']['learning_rate']},
    per_device_train_batch_size={model_config['training_args']['batch_size']},
    per_device_eval_batch_size={model_config['training_args']['batch_size']},
    gradient_accumulation_steps={model_config['training_args']['gradient_accumulation_steps']},
    num_train_epochs={model_config['training_args']['num_epochs']},
    warmup_ratio={model_config['training_args']['warmup_ratio']},
    save_steps={model_config['training_args']['save_steps']},
    eval_steps={model_config['training_args']['eval_steps']},
    evaluation_strategy="{model_config['training_args']['evaluation_strategy']}",
    logging_steps={model_config['training_args']['logging_steps']},
    load_best_model_at_end={model_config['training_args']['load_best_model_at_end']},
    metric_for_best_model="eval_loss",
    greater_is_better=False,
    dataloader_pin_memory=False,
    fp16=True,
    gradient_checkpointing=True,
    report_to="none"
)

# Data collator
data_collator = DataCollatorForLanguageModeling(
    tokenizer=tokenizer,
    mlm=False,
    pad_to_multiple_of=8
)

# Initialize trainer
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=eval_dataset,
    data_collator=data_collator,
    tokenizer=tokenizer
)

# Train the model
trainer.train()

# Save the final model
trainer.save_model("{model_config['name']}_final")
tokenizer.save_pretrained("{model_config['name']}_final")

print("✅ Fine-tuning completed!")
"""
        
        # Save and run fine-tuning script
        script_path = f"finetune_{model_config['name']}.py"
        with open(script_path, 'w') as f:
            f.write(finetune_script)
        
        self.logger.info(f"💾 Fine-tuning script saved to {script_path}")
        return script_path
    
    def run_fine_tuning(self) -> List[str]:
        """Run fine-tuning for all configured models"""
        
        self.logger.info("🚀 Starting cybersecurity fine-tuning pipeline...")
        
        # Generate training data
        dataset_builder = CybersecurityDatasetBuilder()
        dataset_files = dataset_builder.generate_training_data()
        
        # Prepare dataset
        dataset_dir = self.prepare_dataset(dataset_files["combined"])
        
        # Fine-tune each model
        trained_models = []
        for model_config in self.config["models"]:
            script_path = self.fine_tune_model(model_config, dataset_dir)
            trained_models.append({
                "name": model_config["name"],
                "script": script_path,
                "base_model": model_config["base_model"]
            })
        
        self.logger.info(f"✅ Fine-tuning pipeline prepared for {len(trained_models)} models")
        return trained_models

# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Cybersecurity Fine-Tuning Pipeline")
    parser.add_argument("--action", choices=["generate", "prepare", "train"], 
                       default="generate", help="Action to perform")
    parser.add_argument("--config", default="configs/finetune_config.yaml",
                       help="Configuration file path")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    if args.action == "generate":
        # Generate training data only
        dataset_builder = CybersecurityDatasetBuilder()
        dataset_files = dataset_builder.generate_training_data()
        print(f"✅ Training data generated: {dataset_files}")
        
    elif args.action == "prepare":
        # Prepare dataset for training
        finetuner = CybersecurityFineTuner(args.config)
        dataset_builder = CybersecurityDatasetBuilder()
        dataset_files = dataset_builder.generate_training_data()
        dataset_dir = finetuner.prepare_dataset(dataset_files["combined"])
        print(f"✅ Dataset prepared: {dataset_dir}")
        
    elif args.action == "train":
        # Run full fine-tuning pipeline
        finetuner = CybersecurityFineTuner(args.config)
        trained_models = finetuner.run_fine_tuning()
        
        print("\n🎯 Fine-tuning scripts generated:")
        for model in trained_models:
            print(f"   {model['name']}: {model['script']}")
        
        print("\n🚀 To run fine-tuning:")
        for model in trained_models:
            print(f"   python {model['script']}")
