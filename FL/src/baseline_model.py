import os
import sys
import time
import json
import logging
import re
import subprocess
import tempfile
import shutil
from functools import wraps
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd 
from tqdm import tqdm
from ollama import chat, ChatResponse 

req = 10
TOTAL_POLICIES = 282
MAX_ITERATIONS = 5
MAX_ATTEMPT = 1
DELAY = 1
TARGET_ACCURACY = 100.0

POLICY_DIR = "/home/your_username/your_project/FL/Experiment-2/original_policy"
REQUIREMENTS_DIR = f"/home/your_username/your_project/FL/Experiment-2/requests/request-{req}"
OUTPUT_DIR = f"/home/your_username/your_project/FL/Experiment-2/results/result-{req}-baseline-gpt"
LOG_DIR = f"/home/your_username/your_project/FL/Experiment-2/logs/log-{req}-requirements-baseline-gpt"
TEMP_DIR = f"/home/your_username/your_project/FL/Experiment-2/temp_validation/val-{req}-baseline-gpt"
QUACKY_SRC_DIR = "/home/your_username/your_project/quacky/src"
SMT_VALIDATOR_SCRIPT = "/home/your_username/your_project/quacky/src/validate_requests.py"




def setup_logging(log_dir: str = LOG_DIR):  
    """Configure logging"""
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f'requirements_only_repair_{OLLAMA_MODEL}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler() 
        ]
    )
    return log_file

# Retry decorator
def retry(max_attempts=MAX_ATTEMPT, delay=DELAY):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < max_attempts:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempts += 1
                    if attempts == max_attempts:
                        raise
                    logging.warning(f"Attempt {attempts} failed: {e}. Retrying in {delay} seconds...")
                    time.sleep(delay)
        return wrapper
    return decorator
from timeout_decorator import timeout
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from ollama import chat
import logging

logging.basicConfig(level=logging.INFO)


def setup_logging(log_dir: str = LOG_DIR):  
    """Configure logging"""
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f'requirements_only_repair_{OLLAMA_MODEL}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler() 
        ]
    )
    return log_file

# Retry decorator
def retry(max_attempts=MAX_ATTEMPT, delay=DELAY):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < max_attempts:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    attempts += 1
                    if attempts == max_attempts:
                        raise
                    logging.warning(f"Attempt {attempts} failed: {e}. Retrying in {delay} seconds...")
                    time.sleep(delay)
        return wrapper
    return decorator

import os
os.environ['PYTORCH_CUDA_ALLOC_CONF'] = 'expandable_segments:True'


def call_ollama(prompt, system_prompt=""):

        client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))        
        messages = []

        if system_prompt:
            messages.append({
                'role': 'system',
                'content': system_prompt
            })
        
        messages.append({
            'role': 'user',
            'content': prompt
        })
        
        response = client.chat.completions.create(
            model="gpt-4.1",
            messages=messages,
            top_p=0.3,
            stop=['\n```', '```\n'],
            frequency_penalty=0.1
        )
        
        return response.choices[0].message.content

def create_requirements_only_repair_prompt(current_policy, requirements, iteration):

    prompt = f"""You are an AWS IAM policy expert. You must use security best practices to repair the following policy so that the provided tests sets are allowed and denied.
    CRITICAL OUTPUT REQUIREMENTS:

        
CURRENT POLICY TO REVIEW:
{json.dumps(current_policy, indent=2)}

REQUIREMENTS:
{requirements}

OUTPUT INSTRUCTIONS:
Return ONLY the complete corrected policy as valid JSON. No explanations, no markdown formatting.
fix the policy.

CORRECTED POLICY:"""

    return prompt

def create_security_focused_system_prompt():
    """Security-focused system prompt for requirements-only repair"""
    return """Reapir the policy given the requirement. 


REMEMBER: Return ONLY the secure, compliant JSON policy, nothing else."""

def extract_and_validate_json(response_text: str) -> dict:
    """Extract and validate JSON from Ollama response with debugging"""
    text = response_text.strip()
    
    # Remove markdown formatting
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    
    if text.endswith("```"):
        text = text[:-3]
    
    text = text.strip()
    
    # Find JSON boundaries
    start_idx = text.find("{")
    end_idx = text.rfind("}")
    
    if start_idx == -1 or end_idx == -1:
        logging.error(f"No JSON object found in response. Full text: {text}")
        raise ValueError(f"No JSON object found in response. Text: {text[:200]}...")
    
    json_text = text[start_idx:end_idx+1]
    
    try:
        parsed_json = json.loads(json_text)
        
        # Validate essential fields only
        if not isinstance(parsed_json, dict):
            raise ValueError("Response is not a JSON object")
        
        if "Statement" not in parsed_json:
            raise ValueError("Missing 'Statement' field in policy")
        
        if not isinstance(parsed_json["Statement"], list):
            raise ValueError("'Statement' field must be an array")
        
        # Add default version if missing (AWS default)
        if "Version" not in parsed_json:
            parsed_json["Version"] = "2012-10-17"
        
        return parsed_json
        
    except json.JSONDecodeError as e:
        # Log what the LLM actually generated
        logging.error(f"LLM generated invalid JSON!")
        logging.error(f"JSON parsing failed at line {e.lineno}, column {e.colno}: {e.msg}")
        logging.error("=== FULL LLM RESPONSE ===")
        logging.error(response_text)
        logging.error("=== END LLM RESPONSE ===")
        
        logging.error("=== EXTRACTED JSON ===")
        logging.error(json_text)
        logging.error("=== END EXTRACTED JSON ===")
        
        # Show the problematic area with line numbers
        json_lines = json_text.split('\n')
        logging.error("JSON with line numbers (error location marked):")
        for i, line in enumerate(json_lines, 1):
            marker = " <-- Error Here" if i == e.lineno else ""
            logging.error(f"{i:2}: {line}{marker}")
        
        raise ValueError(f"LLM generated invalid JSON: {e}")

@retry()
def repair_policy_with_requirements_only(policy: dict, requirements: dict, iteration: int = 1, policy_idx: int = None) -> dict:
    """Repair policy using ONLY requirements and security best practices (no counter-examples or fault localization)"""
    
    # Use requirements-only prompt generation
    prompt = create_requirements_only_repair_prompt(policy, requirements, iteration)

    prompt += """
"""

    system_prompt = create_security_focused_system_prompt()

    logging.info(f"{'='*80}")
    logging.info(f"Baseline Repair - Iteration {iteration}")
    logging.info(f"{'='*80}")
    
    allow_count = 0
    deny_count = 0
    if "Requests" in requirements:
        for req in requirements["Requests"]:
            if req.get("Effect", "").lower() == "allow":
                allow_count += 1
            else:
                deny_count += 1
    
    logging.info(f"Request analysis:")
    logging.info(f"  - Allow requests: {allow_count}")
    logging.info(f"  - Deny requests: {deny_count}")
    logging.info(f"  - Total requests: {allow_count + deny_count}")

    logging.info(f"Prompt length: {len(prompt)} characters")
    logging.info(f"{'='*80}")
    
    response_text = call_ollama(prompt, system_prompt)
    # Save raw LLM output for every iteration
    raw_output_file = os.path.join(TEMP_DIR, f"raw_llm_output_policy_{policy_idx:03d}_iter_{iteration}.txt")
    os.makedirs(TEMP_DIR, exist_ok=True)
    with open(raw_output_file, 'w', encoding='utf-8') as f:
        f.write(response_text)
    
    # Enhanced response logging
    logging.info(f"{'='*80}")
    logging.info(f"LLM RESPONSE - ITERATION {iteration}")
    
    # Enhanced response logging
    logging.info(f"{'='*80}")
    logging.info(f"LLM RESPONSE - ITERATION {iteration}")
    logging.info(f"{'='*80}")
    logging.info(f"Response length: {len(response_text)} characters")
    logging.info(f"Response preview: {response_text[:200]}...")
    logging.info(f"{'='*80}")
    logging.info(f"Complete Response - Iteration {iteration}: ")
    logging.info(f"{'='*120}")
    logging.info(response_text)
    logging.info(f"{'='*120}")
    logging.info(f"End of Complete Response - Iteration {iteration}")

    if not response_text:
        raise ValueError("Empty response from LLM")
    
    # Parse and validate response
    repaired_policy = extract_and_validate_json(response_text)
    
    # Enhanced change analysis
    original_statements = policy.get('Statement', [])
    repaired_statements = repaired_policy.get('Statement', [])
    
    logging.info(f"POLICY CHANGES ANALYSIS:")
    logging.info(f"  Original statements: {len(original_statements)}")
    logging.info(f"  Repaired statements: {len(repaired_statements)}")
    logging.info(f"  Approach: Requirements-only with security best practices")
    logging.info(f"{'='*80}")
    
    return repaired_policy

def run_smt_validator(policy_file: str, requests_file: str, policy_idx: int = None) -> dict:
    """Run SMT validator - only get accuracy metrics (no failed examples or fault localization)"""
    try:
        original_dir = os.getcwd()
        os.chdir(QUACKY_SRC_DIR)
        
        # Create output directories
        if policy_idx is not None:
            policy_specific_dir = os.path.join(OUTPUT_DIR, "Quacky_output", f"policy_{policy_idx:03d}")
            os.makedirs(policy_specific_dir, exist_ok=True)
            
            # File paths for validation
            accuracy_output_path = os.path.join(policy_specific_dir, f"policy_{policy_idx:03d}_accuracy_validation.txt")
        else:
            # Fallback naming
            quacky_output_dir = os.path.join(OUTPUT_DIR, "Quacky_output")
            os.makedirs(quacky_output_dir, exist_ok=True)
            timestamp = int(time.time())
            pid = os.getpid()
            accuracy_output_path = os.path.join(quacky_output_dir, f"temp_accuracy_{pid}_{timestamp}.txt")
        
        # ===== VALIDATION: Complete Policy (for accuracy measurement only) =====
        cmd_accuracy = [
            'python', 'validate_requests.py',
            '-p1', policy_file,
            '--requests', requests_file,
            '-s'
        ]
        
        logging.debug(f"Running accuracy validation: {' '.join(cmd_accuracy)}")
        
        with open(accuracy_output_path, 'w') as output_file:
            result = subprocess.run(cmd_accuracy, stdout=output_file, stderr=subprocess.PIPE, text=True, timeout=300)
        
        if result.returncode != 0:
            logging.error(f"Accuracy validation failed: {result.stderr}")
            raise Exception(f"Accuracy validation failed: {result.stderr}")
        
        with open(accuracy_output_path, 'r') as f:
            accuracy_output_content = f.read()
        
        os.chdir(original_dir)
        
        # ===== PARSE ACCURACY RESULTS ONLY =====
        accuracy_lines = accuracy_output_content.split('\n')
        accuracy = 0.0
        total_requests = 0
        correct_count = 0
        incorrect_count = 0
        misclassified_allow_to_deny = 0
        misclassified_deny_to_allow = 0
        
        in_analysis_section = False
        for i, line in enumerate(accuracy_lines):
            line = line.strip()
            
            if "INDIVIDUAL REQUEST ANALYSIS" in line:
                in_analysis_section = True
                continue
            elif line.startswith("=") and in_analysis_section and len(line) > 10:
                if any(phrase in ''.join(accuracy_lines[i:i+5]) for phrase in ["Results saved", "saved to HOME"]):
                    break
            
            if in_analysis_section:
                if line.startswith("Total Individual Requests:"):
                    import re
                    total_match = re.search(r'(\d+)', line)
                    if total_match:
                        total_requests = int(total_match.group(1))
                elif line.startswith("Correct Classifications:"):
                    import re
                    correct_match = re.search(r'(\d+)', line)
                    if correct_match:
                        correct_count = int(correct_match.group(1))
                elif line.startswith("Incorrect Classifications:"):
                    import re
                    incorrect_match = re.search(r'(\d+)', line)
                    if incorrect_match:
                        incorrect_count = int(incorrect_match.group(1))
                elif line.startswith("Overall Accuracy:"):
                    import re
                    accuracy_match = re.search(r'(\d+\.?\d*)%', line)
                    if accuracy_match:
                        accuracy = float(accuracy_match.group(1))
                elif line.startswith("Expected Allow -> Got Deny:"):
                    import re
                    allow_deny_match = re.search(r'(\d+)', line)
                    if allow_deny_match:
                        misclassified_allow_to_deny = int(allow_deny_match.group(1))
                elif line.startswith("Expected Deny -> Got Allow:"):
                    import re
                    deny_allow_match = re.search(r'(\d+)', line)
                    if deny_allow_match:
                        misclassified_deny_to_allow = int(deny_allow_match.group(1))
                        
        # Parse SMT timing data
        smt_call_times = []
        import re
        timing_pattern = r"'solver_call_time':\s*([0-9.]+)"
        timing_matches = re.findall(timing_pattern, accuracy_output_content)

        for match in timing_matches:
            try:
                time_val = float(match)
                smt_call_times.append(time_val)
                logging.debug(f"Found timing: {time_val}s")
            except ValueError as e:
                logging.warning(f"Failed to parse timing value: {match} - Error: {e}")

        # Alternative: if the above doesn't work, try looking for the actual printed timing
        if not smt_call_times:
            lines = accuracy_output_content.split('\n')
            for line in lines:
                if "Solver time:" in line:
                    try:
                        time_part = line.split("Solver time:")[1].strip()
                        time_str = time_part.split()[0]
                        time_val = float(time_str)
                        smt_call_times.append(time_val)
                        logging.debug(f"Found timing from console output: {time_val}s")
                    except (IndexError, ValueError) as e:
                        logging.debug(f"Failed to parse timing from console: {line.strip()}")

        # Parse solver call count from individual validation results
        solver_calls = 0
        for line in lines:
            # Look for various possible patterns
            if re.search(r'solver.*call.*#?\s*(\d+)', line, re.IGNORECASE):
                numbers = re.findall(r'\d+', line)
                if numbers:
                    solver_calls = max(solver_calls, int(numbers[-1]))
            elif "total solver calls" in line.lower():
                numbers = re.findall(r'\d+', line)
                if numbers:
                    solver_calls = int(numbers[0])
        
        logging.info(f"Validation completed - Accuracy: {accuracy}%, Total: {total_requests}, Correct: {correct_count}, Incorrect: {incorrect_count}")
        
        if smt_call_times:
            total_smt_time = sum(smt_call_times)
            avg_smt_time = total_smt_time / len(smt_call_times)
            max_smt_time = max(smt_call_times)
            min_smt_time = min(smt_call_times)
            logging.info(f"SMT Solver calls: {solver_calls}, Total time {total_smt_time:.2f}s, Avg time {avg_smt_time:.2f}s, Max time {max_smt_time:.2f}s, Min time {min_smt_time:.2f}s")
        else:
            logging.info(f"SMT Solver calls: {solver_calls}, No timing data found in output")
    
        # Clean up temporary files
        if os.path.exists(accuracy_output_path):
            os.unlink(accuracy_output_path)
        
        return {
            'accuracy': accuracy, 
            'total_requests': total_requests,
            'correct': correct_count,
            'incorrect': incorrect_count,
            'misclassified_allow_to_deny': misclassified_allow_to_deny,
            'misclassified_deny_to_allow': misclassified_deny_to_allow,
            'raw_output': accuracy_output_content,
            'output_file': accuracy_output_path,
            'solver_calls': solver_calls,  # Added solver call count
            'smt_call_times': smt_call_times,
            'total_smt_time': sum(smt_call_times) if smt_call_times else 0,
            'avg_smt_time': sum(smt_call_times) / len(smt_call_times) if smt_call_times else 0
        }
        
    except subprocess.TimeoutExpired:
        try:
            os.chdir(original_dir)
        except:
            pass
        logging.error("SMT validator timed out")
        raise Exception("SMT validator timed out")
    except Exception as e:
        try:
            os.chdir(original_dir)
        except:
            pass
        logging.error(f"Error running SMT validator: {e}")
        raise


def load_json_file(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(data: dict, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def process_policy_with_requirements_only(idx: int, baseline_accuracy: float = 0.0) -> dict:
    """Process a single policy with requirements-only approach (no counter-examples or fault localization)"""
    
    # START TIME TRACKING
    cycle_start_time = time.time()
    
    policy_file = os.path.join(POLICY_DIR, f"{idx}.json")
    req_file = os.path.join(REQUIREMENTS_DIR, f"{idx}.json")
    
    if not os.path.exists(policy_file) or not os.path.exists(req_file):
        raise FileNotFoundError(f"Missing files for index {idx}")
    
    original_policy = load_json_file(policy_file)
    requirements = load_json_file(req_file)
    
    logging.info(f"Starting requirements-only repair for policy {idx} (baseline: {baseline_accuracy:.1f}%)...")
    
    # Count requirements for logging
    allow_count = deny_count = 0
    if "Requests" in requirements:
        for req in requirements["Requests"]:
            if req.get("Effect", "").lower() == "allow":
                allow_count += 1
            else:
                deny_count += 1
    
    logging.info(f"Requirements: {allow_count} Allow, {deny_count} Deny (Total: {allow_count + deny_count})")
    
    if baseline_accuracy >= TARGET_ACCURACY:
        cycle_end_time = time.time()
        cycle_duration = cycle_end_time - cycle_start_time
        
        logging.info(f"Policy {idx} already achieves target accuracy ({baseline_accuracy:.1f}%). Skipping repair.")
        final_output_file = os.path.join(OUTPUT_DIR, f"repaired_{idx}_already_perfect.json")
        save_json_file(original_policy, final_output_file)
        
        return {
            'index': idx,
            'status': 'already_perfect',
            'baseline_accuracy': baseline_accuracy,
            'final_accuracy': baseline_accuracy,
            'improvement_from_baseline': 0.0,
            'iterations_used': 0,
            'iteration_accuracies': [baseline_accuracy],
            'iteration_results': [],
            'final_policy_file': final_output_file,
            'cycle_duration_seconds': cycle_duration,
            'cycle_duration_formatted': str(timedelta(seconds=int(cycle_duration))),
            'average_accuracy': baseline_accuracy

            
        }
    
    iteration_results = []
    current_policy = original_policy.copy()
    final_accuracy = baseline_accuracy
    iteration_accuracies = [baseline_accuracy]
    
    for iteration in range(1, MAX_ITERATIONS + 1):
        iteration_start_time = time.time()
        
        logging.info(f"Policy {idx} - Iteration {iteration}/{MAX_ITERATIONS} (Previous: {final_accuracy:.1f}%)")
        
        iteration_success = False
        iteration_accuracy = 0.0
        iteration_policy_file = None
        
        try:
            logging.info(f"Repairing policy with requirements-only approach (iteration {iteration})...")
            logging.info(f"Using {allow_count + deny_count} requests")
            
            # Use ONLY requirements and security best practices for repair
            repaired_policy = repair_policy_with_requirements_only(current_policy, requirements, iteration, policy_idx=idx)
            
            temp_policy_file = os.path.join(TEMP_DIR, f"policy_{idx}_iter_{iteration}.json")
            os.makedirs(TEMP_DIR, exist_ok=True)
            save_json_file(repaired_policy, temp_policy_file)
            
            logging.info(f"Validating with SMT solver (iteration {iteration})...")
            smt_start_time = time.time()
            validation_results = run_smt_validator(temp_policy_file, req_file, policy_idx=idx)
            smt_end_time = time.time()
            
            smt_duration = smt_end_time - smt_start_time
            
            accuracy = validation_results['accuracy']
            iteration_accuracy = accuracy
            iteration_policy_file = temp_policy_file
            
            # ALWAYS append iteration accuracy before any potential exceptions
            iteration_accuracies.append(accuracy)
            improvement = accuracy - baseline_accuracy
            
            iteration_end_time = time.time()
            iteration_duration = iteration_end_time - iteration_start_time
            
            logging.info(f"Iteration {iteration} Results:")
            logging.info(f"  Accuracy: {accuracy:.1f}% (Baseline: {baseline_accuracy:.1f}%, Improvement: {improvement:+.1f}%)")
            logging.info(f"  Duration: {iteration_duration:.1f} seconds")
            logging.info(f"  Approach: Requirements-only with security best practices")
            
            # Create iteration record BEFORE success check
            iteration_record = {
                'policy_idx': idx,
                'iteration': iteration,
                'validation_type': 'requirements_only',
                'accuracy': accuracy,
                'baseline_accuracy': baseline_accuracy,
                'improvement_from_baseline': improvement,
                'total_requests': validation_results['total_requests'],
                'correct': validation_results['correct'],
                'incorrect': validation_results['incorrect'],
                'misclassified_allow_to_deny': validation_results['misclassified_allow_to_deny'],
                'misclassified_deny_to_allow': validation_results['misclassified_deny_to_allow'],
                'requirements_count': allow_count + deny_count,
                'allow_requirements': allow_count,
                'deny_requirements': deny_count,
                'policy_file': temp_policy_file,
                'iteration_duration_seconds': iteration_duration,
                'smt_validation_duration_seconds': smt_duration,  # Add this line,
                'smt_solver_calls': validation_results.get('solver_calls', 0),  # Add this line,

                # NEW: Add SMT timing data
                'smt_call_times': validation_results.get('smt_call_times', []),
                'total_smt_time': validation_results.get('total_smt_time', 0),
                'avg_smt_time': validation_results.get('avg_smt_time', 0),
                'smt_calls_count': len(validation_results.get('smt_call_times', []))
            }
            iteration_results.append(iteration_record)
            
            final_accuracy = accuracy
            
            # Check if we achieved target accuracy
            if accuracy >= TARGET_ACCURACY:
                cycle_end_time = time.time()
                cycle_duration = cycle_end_time - cycle_start_time
                repair_accuracies = iteration_accuracies[1:] if len(iteration_accuracies) > 1 else []
                average_accuracy = sum(repair_accuracies) / len(repair_accuracies) if repair_accuracies else accuracy

                logging.info(f"Target accuracy achieved for policy {idx} in {iteration} iterations!")
                logging.info(f"Final accuracy: {accuracy:.1f}% (Improvement from baseline: {improvement:+.1f}%)")
                logging.info(f"Total cycle time: {cycle_duration:.1f} seconds ({str(timedelta(seconds=int(cycle_duration)))})")
                logging.info(f"Average accuracy across all iterations: {average_accuracy:.1f}%")
                
                # Try to save final policy with error handling
                try:
                    final_output_file = os.path.join(OUTPUT_DIR, f"repaired_{idx}_final.json")
                    save_json_file(repaired_policy, final_output_file)
                    iteration_success = True
                    
                    return {
                        'index': idx,
                        'status': 'success',
                        'baseline_accuracy': baseline_accuracy,
                        'final_accuracy': accuracy,
                        'improvement_from_baseline': improvement,
                        'iterations_used': iteration,
                        'iteration_accuracies': iteration_accuracies,
                        'iteration_results': iteration_results,
                        'final_policy_file': final_output_file,
                        'cycle_duration_seconds': cycle_duration,
                        'cycle_duration_formatted': str(timedelta(seconds=int(cycle_duration))),
                        'average_accuracy': average_accuracy
                    }
                except Exception as save_error:
                    logging.error(f"Error saving final policy for {idx}: {save_error}")
                    # Continue to try saving as best policy below
                    iteration_success = True  # We still achieved target accuracy
            
            # Update for next iteration
            current_policy = repaired_policy.copy()
            
        except Exception as e:
            iteration_end_time = time.time()
            iteration_duration = iteration_end_time - iteration_start_time
            
            logging.error(f"Error in iteration {iteration} for policy {idx}: {e}")
            
            # If we haven't recorded the iteration yet, add an error record
            if not any(record.get('iteration') == iteration for record in iteration_results):
                iteration_record = {
                    'policy_idx': idx,
                    'iteration': iteration,
                    'validation_type': 'requirements_only',
                    'accuracy': iteration_accuracy,
                    'baseline_accuracy': baseline_accuracy,
                    'improvement_from_baseline': iteration_accuracy - baseline_accuracy,
                    'requirements_count': allow_count + deny_count,
                    'error': str(e),
                    'policy_file': iteration_policy_file,
                    'iteration_duration_seconds': iteration_duration,
                    
                }
                iteration_results.append(iteration_record)
                
                # Only append to iteration_accuracies if we got a real accuracy
                if iteration_accuracy > 0:
                    iteration_accuracies.append(iteration_accuracy)
            
            # If we achieved target accuracy but had a save error, try to save as best
            if iteration_success and iteration_accuracy >= TARGET_ACCURACY:
                try:
                    cycle_end_time = time.time()
                    cycle_duration = cycle_end_time - cycle_start_time
                    average_accuracy = sum(iteration_accuracies) / len(iteration_accuracies)
                    
                    final_output_file = os.path.join(OUTPUT_DIR, f"repaired_{idx}_final.json")
                    if iteration_policy_file and os.path.exists(iteration_policy_file):
                        shutil.copy2(iteration_policy_file, final_output_file)
                        
                        return {
                            'index': idx,
                            'status': 'success',
                            'baseline_accuracy': baseline_accuracy,
                            'final_accuracy': iteration_accuracy,
                            'improvement_from_baseline': iteration_accuracy - baseline_accuracy,
                            'iterations_used': iteration,
                            'iteration_accuracies': iteration_accuracies,
                            'iteration_results': iteration_results,
                            'final_policy_file': final_output_file,
                            'cycle_duration_seconds': cycle_duration,
                            'cycle_duration_formatted': str(timedelta(seconds=int(cycle_duration))),
                            'average_accuracy': average_accuracy
                        }
                except Exception as fallback_error:
                    logging.error(f"Error in fallback save for {idx}: {fallback_error}")

    # END TIME TRACKING FOR FAILED CASES
    cycle_end_time = time.time()
    cycle_duration = cycle_end_time - cycle_start_time
    average_accuracy = sum(iteration_accuracies) / len(iteration_accuracies) if iteration_accuracies else baseline_accuracy

    # If we reach here, we didn't achieve target accuracy
    # Find the best iteration result
    best_accuracy = baseline_accuracy
    best_iteration = None

    if iteration_results:
        logging.info(f"Policy {idx}: All iteration results:")
        for i, result in enumerate(iteration_results):
            duration = result.get('iteration_duration_seconds', 0)
            logging.info(f"  Iteration {result.get('iteration')}: {result.get('accuracy', 0):.1f}% ({duration:.1f}s) - File: {result.get('policy_file')}")
        
        best_iteration = max(iteration_results, key=lambda x: x.get('accuracy', 0))
        best_accuracy = best_iteration.get('accuracy', baseline_accuracy)
        best_file = best_iteration.get('policy_file')
        best_iter_num = best_iteration.get('iteration')
        
        logging.info(f"Policy {idx}: Selected best iteration {best_iter_num} with accuracy {best_accuracy:.1f}%")
        
        if ('policy_file' in best_iteration and best_iteration['policy_file'] is not None and os.path.exists(best_iteration['policy_file'])):
            final_output_file = os.path.join(OUTPUT_DIR, f"repaired_{idx}_best.json")
            shutil.copy2(best_iteration['policy_file'], final_output_file)
        else:
            final_output_file = os.path.join(OUTPUT_DIR, f"repaired_{idx}_original.json")
            save_json_file(original_policy, final_output_file)
            best_accuracy = baseline_accuracy
            logging.warning(f"Policy {idx}: No valid best iteration file found, saving original policy")
    else:
        final_output_file = os.path.join(OUTPUT_DIR, f"repaired_{idx}_original.json")
        save_json_file(original_policy, final_output_file)
        logging.warning(f"Policy {idx}: No iteration results found, saving original policy")

    improvement = best_accuracy - baseline_accuracy
    logging.warning(f"Failed to achieve target accuracy for policy {idx} after {MAX_ITERATIONS} iterations.")
    logging.warning(f"Best accuracy: {best_accuracy:.1f}% (Baseline: {baseline_accuracy:.1f}%, Improvement: {improvement:+.1f}%)")
    logging.warning(f"Total cycle time: {cycle_duration:.1f} seconds ({str(timedelta(seconds=int(cycle_duration)))})")
    logging.warning(f"Average accuracy across all iterations: {average_accuracy:.1f}%")

    return {
        'index': idx,
        'status': 'failed',
        'baseline_accuracy': baseline_accuracy,
        'final_accuracy': best_accuracy,
        'improvement_from_baseline': improvement,
        'iterations_used': MAX_ITERATIONS,
        'iteration_accuracies': iteration_accuracies,
        'iteration_results': iteration_results,
        'final_policy_file': final_output_file,
        'cycle_duration_seconds': cycle_duration,
        'cycle_duration_formatted': str(timedelta(seconds=int(cycle_duration))),
        'average_accuracy': average_accuracy
    }

class RequirementsOnlyProgressTracker:
    """Progress tracker for requirements-only policy repair"""
    def __init__(self, progress_file: str = os.path.join(OUTPUT_DIR, "requirements_only_progress.json")):
        self.progress_file = progress_file
        self.progress = self._load_progress()
    
    def _load_progress(self):
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            "last_processed": -1, 
            "completed": [], 
            "failed": [],
            "policy_iterations": {},
            "baseline_completed": [],
            "baseline_accuracies": {}
        }
    
    def save_progress(self):
        os.makedirs(os.path.dirname(self.progress_file), exist_ok=True)
        with open(self.progress_file, 'w') as f:
            json.dump(self.progress, f, indent=2)
    
    def mark_baseline_completed(self, idx, baseline_accuracy=None):
        if idx not in self.progress["baseline_completed"]:
            self.progress["baseline_completed"].append(idx)
        
        if baseline_accuracy is not None:
            self.progress["baseline_accuracies"][str(idx)] = baseline_accuracy
            
        self.save_progress()
    
    def get_baseline_accuracy(self, idx):
        return self.progress["baseline_accuracies"].get(str(idx), 0.0)
    
    def is_baseline_done(self, idx):
        return idx in self.progress.get("baseline_completed", [])
    
    def mark_completed(self, idx, baseline_accuracy, final_accuracy, iterations_used, iteration_accuracies, cycle_duration=0.0, smt_timing_data=None, total_smt_validation_duration=0.0):
        self.progress["last_processed"] = idx
        if idx not in self.progress["completed"]:
            self.progress["completed"].append(idx)
        if idx in self.progress["failed"]:
            self.progress["failed"].remove(idx)
        
        self.progress["baseline_accuracies"][str(idx)] = baseline_accuracy
        
        # Calculate average accuracy across repair iterations only (excluding baseline)
        repair_accuracies = iteration_accuracies[1:] if len(iteration_accuracies) > 1 else []
        average_accuracy = sum(repair_accuracies) / len(repair_accuracies) if repair_accuracies else final_accuracy
        
        self.progress["policy_iterations"][str(idx)] = {
        "status": "completed",
        "baseline_accuracy": baseline_accuracy,
        "final_accuracy": final_accuracy,
        "improvement": final_accuracy - baseline_accuracy,
        "iterations_used": iterations_used,
        "iteration_accuracies": iteration_accuracies,
        "average_accuracy": average_accuracy,
        "cycle_duration_seconds": cycle_duration,
        "cycle_duration_formatted": str(timedelta(seconds=int(cycle_duration))) if cycle_duration > 0 else "00:00:00",
        # NEW: Add SMT timing data
        "smt_timing": smt_timing_data if smt_timing_data else {
            "total_smt_time": 0,
            "total_smt_calls": 0,
            "avg_smt_call_time": 0,
            "max_smt_call_time": 0,
            "min_smt_call_time": 0
        },
        "total_smt_validation_duration_seconds": total_smt_validation_duration 

    }
        self.save_progress()
    
    def mark_failed(self, idx, baseline_accuracy, final_accuracy, iterations_used, iteration_accuracies, cycle_duration=0.0, smt_timing_data=None, total_smt_validation_duration=0.0):
        if idx not in self.progress["failed"]:
            self.progress["failed"].append(idx)
        
        self.progress["baseline_accuracies"][str(idx)] = baseline_accuracy
        
        # Calculate average accuracy across repair iterations only (excluding baseline)
        repair_accuracies = iteration_accuracies[1:] if len(iteration_accuracies) > 1 else []
        average_accuracy = sum(repair_accuracies) / len(repair_accuracies) if repair_accuracies else final_accuracy
        
        self.progress["policy_iterations"][str(idx)] = {
        "status": "failed",
        "baseline_accuracy": baseline_accuracy,
        "final_accuracy": final_accuracy,
        "improvement": final_accuracy - baseline_accuracy,
        "iterations_used": iterations_used,
        "iteration_accuracies": iteration_accuracies,
        "average_accuracy": average_accuracy,
        "cycle_duration_seconds": cycle_duration,
        "cycle_duration_formatted": str(timedelta(seconds=int(cycle_duration))) if cycle_duration > 0 else "00:00:00",
        # NEW: Add SMT timing data
        "smt_timing": smt_timing_data if smt_timing_data else {
            "total_smt_time": 0,
            "total_smt_calls": 0,
            "avg_smt_call_time": 0,
            "max_smt_call_time": 0,
            "min_smt_call_time": 0
        },
        "total_smt_validation_duration_seconds": total_smt_validation_duration  # Add this line,
    }
        self.save_progress()
    
    def get_next(self):
        return self.progress.get("last_processed", -1) + 1
    
    def is_done(self, idx):
        return idx in self.progress.get("completed", [])

def test_ollama_connection():
    """Test if Ollama is running and the model is available"""
    try:
        test_response = call_ollama("Test", "Respond with only 'OK'")
        if not test_response:
            return False, "Model test failed - empty response"
        
        return True, f"Ollama connection successful with model {OLLAMA_MODEL}"
        
    except Exception as e:
        return False, f"Ollama connection error: {e}. Make sure Ollama is running and model '{OLLAMA_MODEL}' is installed."

def run_baseline_validation(idx: int) -> dict:
    """Run baseline validation on the original policy"""
    policy_file = os.path.join(POLICY_DIR, f"{idx}.json")
    req_file = os.path.join(REQUIREMENTS_DIR, f"{idx}.json")
    
    if not os.path.exists(policy_file) or not os.path.exists(req_file):
        raise FileNotFoundError(f"Missing files for index {idx}")
    
    logging.info(f"Running baseline validation for policy {idx}...")
    
    try:
        validation_results = run_smt_validator(policy_file, req_file, policy_idx=idx)
        
        baseline_result = {
            'policy_idx': idx,
            'validation_type': 'baseline',
            'accuracy': validation_results['accuracy'],
            'total_requests': validation_results['total_requests'],
            'correct': validation_results['correct'],
            'incorrect': validation_results['incorrect'],
            'misclassified_allow_to_deny': validation_results['misclassified_allow_to_deny'],
            'misclassified_deny_to_allow': validation_results['misclassified_deny_to_allow'],
            'output_file': validation_results['output_file']
        }
        
        logging.info(f"Baseline validation for policy {idx}: {validation_results['accuracy']:.1f}% accuracy")
        
        return baseline_result
        
    except Exception as e:
        logging.error(f"Baseline validation failed for policy {idx}: {e}")
        return {
            'policy_idx': idx,
            'validation_type': 'baseline',
            'accuracy': 0.0,
            'error': str(e)
        }

def main():
    """Main function - Requirements-only guided repair"""
    log_file = setup_logging()
    logging.info("Starting requirements-only guided policy repair system")
    
    print("=" * 60)
    print("Requirements-Only Guided Policy Repair System")
    print("=" * 60)
    
    # # Test Ollama connection first
    # print("Testing Ollama connection...")
    # ollama_ok, ollama_msg = test_ollama_connection()
    # if not ollama_ok:
    #     logging.error(f"Ollama connection failed: {ollama_msg}")
    #     print(f"Ollama connection failed: {ollama_msg}")
    #     print("\nPlease ensure:")
    #     print("1. Ollama is running (ollama serve)")
    #     print(f"2. Model '{OLLAMA_MODEL}' is installed (ollama pull {OLLAMA_MODEL})")
    #     print("3. Ollama is accessible")
    #     sys.exit(1)

    
    # Ensure required directories exist
    for directory in [POLICY_DIR, REQUIREMENTS_DIR]:
        if not os.path.isdir(directory):
            logging.error(f"Directory '{directory}' not found.")
            print(f"Directory '{directory}' not found. Exiting.")
            sys.exit(1)
    
    # Check if SMT validator script exists
    if not os.path.exists(SMT_VALIDATOR_SCRIPT):
        logging.error(f"SMT validator script '{SMT_VALIDATOR_SCRIPT}' not found.")
        print(f"SMT validator script '{SMT_VALIDATOR_SCRIPT}' not found. Exiting.")
        sys.exit(1)
    
    # Create output directories
    for directory in [OUTPUT_DIR, TEMP_DIR, os.path.join(OUTPUT_DIR, "Quacky_output")]:
        os.makedirs(directory, exist_ok=True)
    
    # Initialize progress tracker
    tracker = RequirementsOnlyProgressTracker()
    total = TOTAL_POLICIES
    
    # Step 1: Run baseline validation for all policies
    print("\n" + "=" * 60)
    print("STEP 1: BASELINE VALIDATION")
    print("=" * 60)
    
    baseline_results = []
    baseline_to_process = [i for i in range(total) if not tracker.is_baseline_done(i)]
    
    if baseline_to_process:
        logging.info(f"Running baseline validation for policies: {baseline_to_process}")
        
        for idx in tqdm(baseline_to_process, desc="Baseline validation"):
            try:
                baseline_result = run_baseline_validation(idx)
                baseline_results.append(baseline_result)
                
                baseline_accuracy = baseline_result.get('accuracy', 0.0)
                tracker.mark_baseline_completed(idx, baseline_accuracy)
                
                if 'error' not in baseline_result:
                    logging.info(f"Policy {idx} baseline: {baseline_accuracy:.1f}% accuracy")
                else:
                    logging.error(f"Policy {idx} baseline failed: {baseline_result['error']}")
                    
            except Exception as e:
                logging.error(f"Baseline validation failed for policy {idx}: {e}")
                baseline_results.append({
                    'policy_idx': idx,
                    'validation_type': 'baseline',
                    'accuracy': 0.0,
                    'error': str(e)
                })
                tracker.mark_baseline_completed(idx, 0.0)
    else:
        logging.info("All baseline validations already completed. Loading existing results...")
        for i in range(total):
            baseline_accuracy = tracker.get_baseline_accuracy(i)
            baseline_results.append({
                'policy_idx': i,
                'validation_type': 'baseline',
                'accuracy': baseline_accuracy
            })
    
    # Save baseline results
    if baseline_results:
        baseline_csv = os.path.join(OUTPUT_DIR, "baseline_results_requirements_only.csv")
        baseline_df = pd.DataFrame(baseline_results)
        baseline_df.to_csv(baseline_csv, index=False)
        logging.info(f"Baseline results saved to {baseline_csv}")
    
    # Print baseline summary
    print(f"\n{'='*60}")
    print("BASELINE VALIDATION SUMMARY")
    print(f"{'='*60}")
    successful_baselines = [r for r in baseline_results if r.get('accuracy', 0) > 0 and 'error' not in r]
    failed_baselines = [r for r in baseline_results if 'error' in r]
    perfect_baselines = [r for r in baseline_results if r.get('accuracy', 0) >= TARGET_ACCURACY]
    
    if successful_baselines:
        avg_baseline_accuracy = sum(r['accuracy'] for r in successful_baselines) / len(successful_baselines)
        print(f"Successfully validated policies: {len(successful_baselines)}")
        print(f"Failed baseline validations: {len(failed_baselines)}")
        print(f"Average baseline accuracy: {avg_baseline_accuracy:.1f}%")
        print(f"Policies already at target accuracy: {len(perfect_baselines)}")
        
        if perfect_baselines:
            perfect_indices = [r['policy_idx'] for r in perfect_baselines]
            print(f"Perfect baseline policies: {perfect_indices}")
    
    print(f"{'='*60}")
    
    # Step 2: Requirements-only guided repair
    print("\nSTEP 2: REQUIREMENTS-ONLY GUIDED REPAIR")
    print("=" * 60)
    
    baseline_accuracy_map = {r['policy_idx']: r.get('accuracy', 0.0) for r in baseline_results}
    
    to_process = [i for i in range(total) if not tracker.is_done(i)]
    logging.info(f"Policies to process for requirements-only repair: {to_process}")
    
    all_results = []
    all_iteration_data = baseline_results.copy()
    
    # Process each policy - ONLY use requirements and security best practices
    for idx in tqdm(to_process, desc="Processing policies with requirements-only repair"):
        try:
            baseline_acc = baseline_accuracy_map.get(idx, 0.0)
            
            # Pass ONLY baseline accuracy - NO counter-examples or fault localization
            result = process_policy_with_requirements_only(idx, baseline_acc)
            # NEW: Calculate SMT timing data from iteration results
            all_smt_times = []
            total_smt_time = 0
            total_smt_calls = 0
            total_smt_validation_duration = 0

            for iter_result in result['iteration_results']:
                if 'smt_call_times' in iter_result and iter_result['smt_call_times']:
                    all_smt_times.extend(iter_result['smt_call_times'])
                if 'total_smt_time' in iter_result:
                    total_smt_time += iter_result.get('total_smt_time', 0)
                if 'smt_calls_count' in iter_result:
                    total_smt_calls += iter_result.get('smt_calls_count', 0)
                if 'smt_validation_duration_seconds' in iter_result:
                    # Calculate total SMT validation duration from iteration results
                    total_smt_validation_duration = sum(iter_result.get('smt_validation_duration_seconds', 0) for iter_result in result['iteration_results'])

            smt_timing_data = {
                "total_smt_time": total_smt_time,
                "total_smt_calls": total_smt_calls,
                "avg_smt_call_time": sum(all_smt_times) / len(all_smt_times) if all_smt_times else 0,
                "max_smt_call_time": max(all_smt_times) if all_smt_times else 0,
                "min_smt_call_time": min(all_smt_times) if all_smt_times else 0
            },
            
            # Track completion/failure
            if result['status'] in ['success', 'already_perfect']:
                tracker.mark_completed(
                    idx, 
                    result['baseline_accuracy'], 
                    result['final_accuracy'], 
                    result['iterations_used'], 
                    result['iteration_accuracies'],
                    result.get('cycle_duration_seconds', 0.0),
                    smt_timing_data,  # Now this is defined,
                    total_smt_validation_duration  # Pass total SMT validation duration
                )
            else:
                tracker.mark_failed(
                    idx, 
                    result['baseline_accuracy'], 
                    result['final_accuracy'], 
                    result['iterations_used'], 
                    result.get('iteration_accuracies', []),
                    result.get('cycle_duration_seconds', 0.0),
                    smt_timing_data, # Now this is defined,
                    total_smt_validation_duration  # Pass total SMT validation duration
                )
                
            all_results.append(result)
            
            # Collect iteration data
            for iter_data in result['iteration_results']:
                all_iteration_data.append(iter_data)
            
        except Exception as e:
            logging.error(f"Policy {idx} failed completely: {e}")
            baseline_acc = baseline_accuracy_map.get(idx, 0.0)
            tracker.mark_failed(idx, baseline_acc, 0.0, 0, [])
            all_results.append({
                'index': idx,
                'status': 'error',
                'baseline_accuracy': baseline_acc,
                'final_accuracy': 0.0,
                'improvement_from_baseline': 0.0,
                'iterations_used': 0,
                'iteration_accuracies': [],
                'error': str(e)
            })
    
    # Save comprehensive results
    
    # Summary results
    if all_results:
        df_summary = pd.DataFrame(all_results)
        summary_csv = os.path.join(OUTPUT_DIR, "requirements_only_repair_summary.csv")
        df_summary.to_csv(summary_csv, index=False)
        logging.info(f"Summary results saved to {summary_csv}")
    
    # Detailed iteration results
    if all_iteration_data:
        df_iterations = pd.DataFrame(all_iteration_data)
        iterations_csv = os.path.join(OUTPUT_DIR, "requirements_only_repair_details.csv")
        df_iterations.to_csv(iterations_csv, index=False)
        logging.info(f"Detailed iteration results saved to {iterations_csv}")
    
    # Final summary
    successful = len([r for r in all_results if r.get('status') in ['success', 'already_perfect']])
    already_perfect = len([r for r in all_results if r.get('status') == 'already_perfect'])
    improved = len([r for r in all_results if r.get('status') == 'success'])
    failed = len([r for r in all_results if r.get('status') in ['failed', 'error']])
    
    if all_results:
        avg_baseline = sum(r.get('baseline_accuracy', 0) for r in all_results) / len(all_results)
        avg_final = sum(r.get('final_accuracy', 0) for r in all_results) / len(all_results)
        avg_improvement = avg_final - avg_baseline
        total_iterations = sum(r.get('iterations_used', 0) for r in all_results)
        
        baseline_perfect = len([r for r in all_results if r.get('baseline_accuracy', 0) >= TARGET_ACCURACY])
        final_perfect = len([r for r in all_results if r.get('final_accuracy', 0) >= TARGET_ACCURACY])
        improvement_count = final_perfect - baseline_perfect
    else:
        avg_baseline = avg_final = avg_improvement = total_iterations = improvement_count = 0
        baseline_perfect = final_perfect = 0
    
    # Print final summary to console
    print(f"\n{'='*60}")
    print("REQUIREMENTS-ONLY GUIDED REPAIR - FINAL SUMMARY")
    print(f"{'='*60}")
    print(f"Total policies processed: {len(all_results)}")
    print(f"Model used: {OLLAMA_MODEL}")
    print(f"")
    print(f"BASELINE PERFORMANCE:")
    print(f"  Average baseline accuracy: {avg_baseline:.1f}%")
    print(f"  Policies at target (baseline): {baseline_perfect}")
    print(f"")
    print(f"FINAL PERFORMANCE:")
    print(f"  Successfully repaired to 100%: {improved}")
    print(f"  Already perfect (no repair needed): {already_perfect}")
    print(f"  Failed to reach 100%: {failed}")
    print(f"  Average final accuracy: {avg_final:.1f}%")
    print(f"  Policies at target (final): {final_perfect}")
    print(f"")
    print(f"IMPROVEMENT:")
    print(f"  Net improvement: +{improvement_count} policies reaching 100%")
    print(f"  Accuracy improvement: {avg_improvement:.1f} percentage points")
    print(f"  Total iterations used: {total_iterations}")
    print(f"  Average iterations per policy: {total_iterations/len(all_results):.1f}" if all_results else "0")
    
    #log final summary
    logging.info("FINAL SUMMARY:")
    logging.info(f"Total policies processed: {len(all_results)}")
    logging.info(f"Model used: {OLLAMA_MODEL}")
    logging.info(f"")
    logging.info(f"BASELINE PERFORMANCE:")
    logging.info(f"  Average baseline accuracy: {avg_baseline:.1f}%")
    logging.info(f"  Policies at target (baseline): {baseline_perfect}")
    logging.info(f"")
    logging.info(f"FINAL PERFORMANCE:")
    logging.info(f"  Successfully repaired to 100%: {improved}")
    logging.info(f"  Already perfect (no repair needed): {already_perfect}")
    logging.info(f"  Failed to reach 100%: {failed}")
    logging.info(f"  Average final accuracy: {avg_final:.1f}%")
    logging.info(f"  Policies at target (final): {final_perfect}")
    logging.info(f"")
    logging.info(f"IMPROVEMENT:")
    logging.info(f"  Net improvement: +{improvement_count} policies reaching 100%")
    logging.info(f"  Accuracy improvement: {avg_improvement:.1f} percentage points")
    logging.info(f"  Total iterations used: {total_iterations}")
    logging.info(f"  Average iterations per policy: {total_iterations/len(all_results):.1f}" if all_results else "0")
    
    # Show detailed results
    print(f"\nDETAILED RESULTS:")
    for result in all_results:
        idx = result['index']
        baseline = result.get('baseline_accuracy', 0)
        final = result.get('final_accuracy', 0)
        status = result.get('status', 'unknown')
        iterations = result.get('iterations_used', 0)
        improvement = result.get('improvement_from_baseline', 0)
        
        if status == 'already_perfect':
            print(f"  Policy {idx}: {baseline:.1f}% -> {final:.1f}% (already perfect)")
        elif status == 'success':
            print(f"  Policy {idx}: {baseline:.1f}% -> {final:.1f}% (SUCCESS in {iterations} iterations, +{improvement:.1f}%)")
        elif status == 'failed':
            print(f"  Policy {idx}: {baseline:.1f}% -> {final:.1f}% (failed after {iterations} iterations, +{improvement:.1f}%)")
        else:
            print(f"  Policy {idx}: {baseline:.1f}% -> {final:.1f}% (ERROR: {result.get('error', 'unknown')})")

    print(f"{'='*60}")
    print("Results files:")
    print(f"  - Baseline: baseline_results_requirements_only.csv")
    print(f"  - Summary: requirements_only_repair_summary.csv")
    print(f"  - Detailed iterations: requirements_only_repair_details.csv")
    print(f"  - Progress tracker: {tracker.progress_file}")
    print(f"{'='*60}")
    print("\nKEY APPROACH:")
    print("- Uses ONLY requirements and AWS IAM security best practices")
    print("- NO counter-examples or validation feedback")
    print("- NO fault localization or error analysis")
    print("- Pure requirements-driven repair methodology")
    print("- Focuses on principle of least privilege and secure policy design")
    print("- Emphasizes compliance with requirements using minimal necessary permissions")

    # Cleanup
    if os.path.exists(TEMP_DIR):
        logging.info(f"Temporary files kept for analysis in: {TEMP_DIR}")

def cleanup_previous_run():
    directories_to_clean = [
        OUTPUT_DIR,
        TEMP_DIR,
        os.path.join(OUTPUT_DIR, "Quacky_output")
    ]
    
    for directory in directories_to_clean:
        if os.path.exists(directory):
            shutil.rmtree(directory)
            logging.info(f"Cleaned previous run data from {directory}")
    
    # Recreate the directories
    for directory in directories_to_clean:
        os.makedirs(directory, exist_ok=True)
        
if __name__ == "__main__":
    main()
