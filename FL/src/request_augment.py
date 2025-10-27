import os
import sys
import json
import logging
import re
import subprocess
import time
from pathlib import Path


QUACKY_SRC_DIR = "/home/bhall2/Documents/fixmypolicy/quacky/src"
OUTPUT_DIR = "./output"
TEMP_DIR = "./temp"

POLICY_DIR = "/home/bhall2/Documents/fixmypolicy/FL/Experiment-2/original_policy"
REQUESTS_DIR = "/home/bhall2/Documents/fixmypolicy/FL/Experiment-2/requests"
OUTPUT_DIR = "/home/bhall2/Documents/fixmypolicy/FL/Experiment-2/extended_requests-v2"

os.makedirs(OUTPUT_DIR, exist_ok = True)

def setup_logging():
    """Configure logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

def run_smt_validator(policy_file: str, requests_file: str, policy_idx: int = None) -> dict:
    """Run SMT validator and extract misclassified requests"""
    try:
        original_dir = os.getcwd()
        os.chdir(QUACKY_SRC_DIR)
        
        if policy_idx is not None:
            policy_specific_dir = os.path.join(original_dir, OUTPUT_DIR, "Quacky_output", f"policy_{policy_idx:03d}")
            os.makedirs(policy_specific_dir, exist_ok=True)
            accuracy_output_path = os.path.join(policy_specific_dir, f"policy_{policy_idx:03d}_accuracy_validation.txt")
        else:
            quacky_output_dir = os.path.join(original_dir, OUTPUT_DIR, "Quacky_output")
            os.makedirs(quacky_output_dir, exist_ok=True)
            timestamp = int(time.time())
            pid = os.getpid()
            accuracy_output_path = os.path.join(quacky_output_dir, f"temp_accuracy_{pid}_{timestamp}.txt")
        
        cmd_accuracy = [
            sys.executable, 'validate_requests.py',
            '-p1', os.path.abspath(os.path.join(original_dir, policy_file)),
            '--requests', os.path.abspath(os.path.join(original_dir, requests_file)),
            '-s'
        ]
        
        logging.info(f"Running SMT validation: {' '.join(cmd_accuracy)}")
        logging.info(f"Output file: {accuracy_output_path}")
        
        with open(accuracy_output_path, 'w') as output_file:
            result = subprocess.run(cmd_accuracy, stdout=output_file, stderr=subprocess.PIPE, text=True, timeout=300)
        
        os.chdir(original_dir)
        
        if result.returncode != 0:
            logging.error(f"SMT validation failed: {result.stderr}")
            raise Exception(f"SMT validation failed: {result.stderr}")
        
        with open(accuracy_output_path, 'r') as f:
            output_content = f.read()
        
        accuracy, total_requests, correct_count, incorrect_count = parse_accuracy_results(output_content)
        misclassified_requests = extract_misclassified_requests(output_content)
        
        logging.info(f"SMT Validation Results - Accuracy: {accuracy}%, Total: {total_requests}, Misclassified: {len(misclassified_requests)}")
        
        # Clean up temporary files
        if os.path.exists(accuracy_output_path):
            os.unlink(accuracy_output_path)
        
        return {
            'accuracy': accuracy,
            'total_requests': total_requests,
            'correct': correct_count,
            'incorrect': incorrect_count,
            'misclassified_requests': misclassified_requests,
            'raw_output': output_content
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

def parse_accuracy_results(output_content: str) -> tuple:
    """Parse accuracy results from SMT validator output"""
    lines = output_content.split('\n')
    accuracy = 0.0
    total_requests = 0
    correct_count = 0
    incorrect_count = 0
    
    in_analysis_section = False
    for i, line in enumerate(lines):
        line = line.strip()
        
        if "INDIVIDUAL REQUEST ANALYSIS" in line:
            in_analysis_section = True
            continue
        elif line.startswith("=") and in_analysis_section and len(line) > 10:
            if any(phrase in ''.join(lines[i:i+5]) for phrase in ["Results saved", "saved to HOME"]):
                break
        
        if in_analysis_section:
            if line.startswith("Total Individual Requests:"):
                total_match = re.search(r'(\d+)', line)
                if total_match:
                    total_requests = int(total_match.group(1))
            elif line.startswith("Correct Classifications:"):
                correct_match = re.search(r'(\d+)', line)
                if correct_match:
                    correct_count = int(correct_match.group(1))
            elif line.startswith("Incorrect Classifications:"):
                incorrect_match = re.search(r'(\d+)', line)
                if incorrect_match:
                    incorrect_count = int(incorrect_match.group(1))
            elif line.startswith("Overall Accuracy:"):
                accuracy_match = re.search(r'(\d+\.?\d*)%', line)
                if accuracy_match:
                    accuracy = float(accuracy_match.group(1))
    
    return accuracy, total_requests, correct_count, incorrect_count

def extract_misclassified_requests(output_content: str) -> list:
    """Extract misclassified request IDs and details from SMT validator output"""
    misclassified_requests = []
    lines = output_content.split('\n')
    
    current_request = None
    
    for line in lines:
        line = line.strip()
        
        if "Validating individual request:" in line:
            match = re.search(r'Validating individual request: (\w+)_combo_\d+', line)
            if match:
                current_request = {"id": match.group(1)}
        
        elif line.startswith("Action:") and current_request:
            parts = line.split(", ")
            for part in parts:
                if part.startswith("Action:"):
                    current_request["action"] = part.split(": ", 1)[1].strip()
                elif part.startswith("Resource:"):
                    current_request["resource"] = part.split(": ", 1)[1].strip()
                elif part.startswith("Principal:"):
                    principal_val = part.split(": ", 1)[1].strip()
                    current_request["principal"] = principal_val if principal_val != "None" else None
                elif part.startswith("Condition:"):
                    condition_val = part.split(": ", 1)[1].strip()
                    current_request["condition"] = condition_val if condition_val != "None" else None
        
        elif "INCORRECT:" in line and current_request:
            match = re.search(r'Expected=(\w+), Got=(\w+)', line)
            if match:
                expected = match.group(1)
                actual = match.group(2)
                
                misclassified_request = {
                    "request_id": current_request.get("id", "unknown"),
                    "action": current_request.get("action", "unknown"),
                    "resource": current_request.get("resource", "unknown"),
                    "principal": current_request.get("principal"),
                    "condition": current_request.get("condition"),
                    "expected": expected,
                    "actual": actual
                }
                
                misclassified_requests.append(misclassified_request)
                logging.debug(f"Found misclassified request: {misclassified_request}")
        
        elif "CORRECT:" in line or "Processing request object:" in line:
            current_request = None
    
    logging.info(f"Extracted {len(misclassified_requests)} misclassified requests")
    return misclassified_requests
def generate_similar_resources(original_resource: str) -> list:
    """Generate additional similar resources based on resource type using real-world AWS patterns"""
    variations = [original_resource] 
    
    if 'iam::' in original_resource and 'role/' in original_resource:
        base_parts = original_resource.split('role/')
        base_arn = base_parts[0] + 'role/'
        role_name = base_parts[1]
        variations.extend([
            base_arn + role_name + '-dev' ,
            base_arn + role_name + '-staging',
            base_arn + role_name + '-prod'])
        
    elif 'iam::' in original_resource and 'user/' in original_resource:
        # For IAM users
        base_parts = original_resource.split('user/')
        base_arn = base_parts[0] + 'user/'
        user_name = base_parts[1]
        variations.extend([
            base_arn + user_name + '-service',
            base_arn + user_name + '-admin',
            base_arn + user_name + '-dev'
        ])
        
    elif 'kms:' in original_resource and 'key/' in original_resource:
        # For KMS keys - 
        base_parts = original_resource.split('key/')
        base_arn = base_parts[0] + 'key/'
        key_id = base_parts[1]
        key_variations = [
            'a' + key_id[1:],  # to change the first letter,
            'b' + key_id[1:],
            'c' + key_id[1:]
        ]
        for new_key_id in key_variations:
            variations.append(base_arn + new_key_id)
            
    elif 's3:::' in original_resource:
        # For S3 resources - 
        bucket_match = original_resource.split('s3:::')[1]
        if '/' in bucket_match:
            bucket_name, path = bucket_match.split('/', 1)
        else:
            bucket_name, path = bucket_match, ''
        
        bucket_variations = [
            bucket_name + '-dev',
            bucket_name + '-staging',
            bucket_name + '-prod',
            bucket_name + '-backup',
            bucket_name + '-archive'
        ]
        
        for new_bucket in bucket_variations:
            new_resource = f"arn:aws:s3:::{new_bucket}"
            if path:
                new_resource += f"/{path}"
            variations.append(new_resource)
            
    elif 'lambda:' in original_resource and 'function:' in original_resource:
        # For Lambda functions 
        base_parts = original_resource.split('function:')
        base_arn = base_parts[0] + 'function:'
        function_name = base_parts[1]
        # Remove version/alias if present
        if ':' in function_name:
            function_name = function_name.split(':')[0]
        
        variations.extend([
            base_arn + function_name + '-dev',
            base_arn + function_name + '-staging',
            base_arn + function_name + '-prod',
            base_arn + function_name + '-v2',
            base_arn + function_name + '-v3'
        ])
        
    elif 'ec2:' in original_resource and 'instance/' in original_resource:
        # For EC2 instances
        base_parts = original_resource.split('instance/')
        base_arn = base_parts[0] + 'instance/'
        instance_id = base_parts[1]
        # Generate realistic instance IDs
        for i in range(1, 5):
            new_instance_id = 'i-' + instance_id[2:8] + f'{i:06x}' + instance_id[14:]
            variations.append(base_arn + new_instance_id)
            
    elif 'rds:' in original_resource and 'db:' in original_resource:
        # For RDS databases
        base_parts = original_resource.split('db:')
        base_arn = base_parts[0] + 'db:'
        db_name = base_parts[1]
        variations.extend([
            base_arn + db_name + '-replica',
            base_arn + db_name + '-backup',
            base_arn + db_name + '-read-replica',
            base_arn + db_name + '-test'
        ])
            
    elif 'athena:' in original_resource and 'workgroup/' in original_resource:
        # For Athena workgroups - realistic naming
        base_parts = original_resource.split('workgroup/')
        base_arn = base_parts[0] + 'workgroup/'
        workgroup_name = base_parts[1]
        variations.extend([
            base_arn + workgroup_name + '-cost-control',
            base_arn + workgroup_name + '-analytics',
            base_arn + workgroup_name + '-dev'
        ])
        
    elif 'glue:' in original_resource and 'table/' in original_resource:
        # For Glue tables - realistic data lake patterns
        base_parts = original_resource.split('table/')
        base_arn = base_parts[0] + 'table/'
        table_parts = base_parts[1].split('/')
        database = table_parts[0]
        table = table_parts[1] if len(table_parts) > 1 else 'default_table'
        
        variations.extend([
            base_arn + database + '_dev/' + table,
            base_arn + database + '_staging/' + table,
            base_arn + database + '_prod/' + table,
        ])
        
    elif 'dynamodb:' in original_resource and 'table/' in original_resource:
        # For DynamoDB tables
        base_parts = original_resource.split('table/')
        base_arn = base_parts[0] + 'table/'
        table_name = base_parts[1]
        variations.extend([
            base_arn + table_name + '-dev',
            base_arn + table_name + '-staging',
            base_arn + table_name + '-prod'
        ])
        
    elif 'logs:' in original_resource and 'log-group:' in original_resource:
        # For CloudWatch Log Groups
        base_parts = original_resource.split('log-group:')
        base_arn = base_parts[0] + 'log-group:'
        log_group = base_parts[1]
        # Remove existing suffixes
        log_group = log_group.rstrip(':*')
        variations.extend([
            base_arn + log_group + '-dev',
            base_arn + log_group + '-staging',
            base_arn + log_group + '-prod'
        ])
    elif 'sqs:' in original_resource and 'queue/' in original_resource:
        # For SQS queues
        base_parts = original_resource.split('queue/')
        base_arn = base_parts[0] + 'queue/'
        queue_name = base_parts[1]
        variations.extend([
            base_arn + queue_name + '-dev',
            base_arn + queue_name + '-staging',
            base_arn + queue_name + '-prod',
            base_arn + queue_name + '-fifo'
        ])
    elif 'sns:' in original_resource and 'topic/' in original_resource:
        # For SNS topics
        base_parts = original_resource.split('topic/')
        base_arn = base_parts[0] + 'topic/'
        topic_name = base_parts[1]
        variations.extend([
            base_arn + topic_name + '-notifications',
            base_arn + topic_name + '-alerts',
            base_arn + topic_name + '-dev'
        ])
    elif 'apigateway:' in original_resource and 'restapi/' in original_resource:
        # For API Gateway REST APIs
        base_parts = original_resource.split('restapi/')
        base_arn = base_parts[0] + 'restapi/'
        api_id = base_parts[1]
        variations.extend([
            base_arn + api_id + '-prod',
            base_arn + api_id + '-staging',
            base_arn + api_id + '-dev'
        ])
    elif 'cloudfront:' in original_resource and 'distribution/' in original_resource:
        # For CloudFront distributions
        base_parts = original_resource.split('distribution/')
        base_arn = base_parts[0] + 'distribution/'
        distribution_id = base_parts[1]
        variations.extend([
            base_arn + distribution_id + '-test',
            base_arn + distribution_id + '-staging',
            base_arn + distribution_id + '-prod'
 
        ])
    elif 'KMS:' in original_resource or 'kms:' in original_resource and 'key/' in original_resource:
        # For KMS keys
        base_parts = original_resource.split('key/')
        base_arn = base_parts[0] + 'key/'
        key_id = base_parts[1]
        variations.extend([
            base_arn + key_id + '-staging',
            base_arn + key_id + '-prod',
            base_arn + key_id + '-test'
          
        ])
    elif 's3:::' in original_resource:
        # For S3 buckets
        bucket_match = original_resource.split('s3:::')[1]
        if '/' in bucket_match:
            bucket_name, path = bucket_match.split('/', 1)
        else:
            bucket_name, path = bucket_match, ''
        
        bucket_variations = [
            bucket_name + '-prod',
            bucket_name + '-dev',
            bucket_name + '-staging',
            bucket_name + '-backup'
    
        ]
        
        for new_bucket in bucket_variations:
            new_resource = f"arn:aws:s3:::{new_bucket}"
            if path:
                new_resource += f"/{path}"
            variations.append(new_resource)

    return variations

def identify_misclassified_and_augment(policy_file: str, requests_file: str, output_file: str):
    """Main function to run SMT validator, identify misclassified requests, and augment their resources"""
    
    with open(requests_file, 'r') as f:
        requests_data = json.load(f)
    
    requests = requests_data.get('Requests', [])
    
    print("=== RUNNING SMT VALIDATOR ===")
    
    validation_results = run_smt_validator(policy_file, requests_file)
    
    misclassified_requests = validation_results['misclassified_requests']
    misclassified_ids = [req['request_id'] for req in misclassified_requests]
    
    print(f"SMT Validation Results:")
    print(f"  Accuracy: {validation_results['accuracy']:.1f}%")
    print(f"  Total requests: {validation_results['total_requests']}")
    print(f"  Correct: {validation_results['correct']}")
    print(f"  Incorrect: {validation_results['incorrect']}")
    print(f"  Misclassified request IDs: {misclassified_ids}")
    
    if not misclassified_ids:
        print("No misclassified requests found. No augmentation needed.")
        with open(output_file, 'w') as f:
            json.dump(requests_data, f, indent=2)
        return {
            'total_requests': len(requests),
            'misclassified_count': 0,
            'misclassified_ids': [],
            'output_file': output_file
        }
    
    print(f"\n=== AUGMENTING {len(misclassified_ids)} MISCLASSIFIED REQUESTS ===")
    
    augmented_requests = []
    for request in requests:
        if request['id'] in misclassified_ids:
            print(f"\nAugmenting request: {request['id']}")
            print(f"Original resources: {request['Resource']}")
            
            augmented_resources = []
            for resource in request['Resource']:
                similar_resources = generate_similar_resources(resource)
                augmented_resources.extend(similar_resources)
            
            unique_resources = []
            seen = set()
            for resource in augmented_resources:
                if resource not in seen:
                    unique_resources.append(resource)
                    seen.add(resource)
            
            augmented_request = request.copy()
            augmented_request['Resource'] = unique_resources
            augmented_requests.append(augmented_request)
            
            print(f"Augmented resources: {unique_resources}")
            print(f"Added {len(unique_resources) - len(request['Resource'])} new resources")
        else:
            augmented_requests.append(request)
    
    output_data = {'Requests': augmented_requests}
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\nAugmented requests saved to: {output_file}")
    
    return {
        'total_requests': len(requests),
        'misclassified_count': len(misclassified_ids),
        'misclassified_ids': misclassified_ids,
        'augmented_requests': augmented_requests,
        'output_file': output_file
    }

def main():
    """Process all policies and requests in batch"""
    setup_logging()
    
    # Create output directories
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)
    
    # Verify required directories exist
    if not os.path.exists(POLICY_DIR):
        print(f"Error: Policy directory not found: {POLICY_DIR}")
        return
    
    if not os.path.exists(REQUESTS_DIR):
        print(f"Error: Requests directory not found: {REQUESTS_DIR}")
        return
    
    if not os.path.exists(QUACKY_SRC_DIR):
        print(f"Error: Quacky source directory not found: {QUACKY_SRC_DIR}")
        return

    specific_requests_dir = os.path.join(REQUESTS_DIR, "request-10")

    if not os.path.exists(specific_requests_dir):
        print(f"Error: Specific requests directory not found: {specific_requests_dir}")
        return
    
    # Find all policy files (0.json, 1.json, etc.)
    policy_files = []
    idx = 0
    while True:
        policy_file = os.path.join(POLICY_DIR, f"{idx}.json")
        if os.path.exists(policy_file):
            policy_files.append((idx, policy_file))
            idx += 1
        else:
            break
    
    print(f"Found {len(policy_files)} policy files")
    
    results_summary = []
    
    for idx, policy_file in policy_files:
        print(f"\n{'='*80}")
        print(f"PROCESSING POLICY {idx}")
        print(f"{'='*80}")
        
        # Corresponding request file
        requests_file = os.path.join(specific_requests_dir, f"{idx}.json")
        output_file = os.path.join(OUTPUT_DIR, f"{idx}.json")
        
        # Check if request file exists
        if not os.path.exists(requests_file):
            print(f"Warning: Request file not found for policy {idx}: {requests_file}")
            continue
        
        try:
            # Process this policy-request pair
            results = identify_misclassified_and_augment(policy_file, requests_file, output_file)
            
            # Store summary
            results_summary.append({
                'policy_idx': idx,
                'accuracy': results.get('accuracy', 0),
                'total_requests': results['total_requests'],
                'misclassified_count': results['misclassified_count'],
                'misclassified_ids': results['misclassified_ids'],
                'output_file': results['output_file']
            })
            
            print(f"Policy {idx} completed:")
            print(f"  Misclassified: {results['misclassified_count']}/{results['total_requests']}")
            print(f"  Output: {results['output_file']}")
            
        except Exception as e:
            print(f"Error processing policy {idx}: {e}")
            logging.error(f"Error processing policy {idx}: {e}")
            
            results_summary.append({
                'policy_idx': idx,
                'accuracy': 0,
                'total_requests': 0,
                'misclassified_count': 0,
                'misclassified_ids': [],
                'error': str(e)
            })
    
    print(f"\n{'='*80}")
    print("FINAL SUMMARY")
    print(f"{'='*80}")
    
    total_processed = len([r for r in results_summary if 'error' not in r])
    total_errors = len([r for r in results_summary if 'error' in r])
    total_misclassified = sum(r['misclassified_count'] for r in results_summary if 'error' not in r)
    total_requests = sum(r['total_requests'] for r in results_summary if 'error' not in r)
    
    print(f"Total policies processed: {total_processed}")
    print(f"Total errors: {total_errors}")
    print(f"Total requests processed: {total_requests}")
    print(f"Total misclassified requests: {total_misclassified}")
    
    if total_requests > 0:
        overall_misclassification_rate = (total_misclassified / total_requests) * 100
        print(f"Overall misclassification rate: {overall_misclassification_rate:.2f}%")
    
    # Show per-policy results
    print(f"\nPER-POLICY RESULTS:")
    for result in results_summary:
        idx = result['policy_idx']
        if 'error' in result:
            print(f"  Policy {idx}: ERROR - {result['error']}")
        else:
            misclass = result['misclassified_count']
            total = result['total_requests']
            print(f"  Policy {idx}: {misclass}/{total} misclassified requests")
    
    # Save summary to file
    summary_file = os.path.join(OUTPUT_DIR, "processing_summary.json")
    with open(summary_file, 'w') as f:
        json.dump(results_summary, f, indent=2)
    print(f"\nSummary saved to: {summary_file}")

if __name__ == "__main__":
    main()
