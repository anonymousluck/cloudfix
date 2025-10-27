import json
import sys
from typing import Dict, List, Any

def generate_request_signature(request: Dict[str, Any]) -> str:
    """Generate a unique signature for a request to check for duplicates"""
    signature_parts = []
    
    # Add Action (sorted if list)
    if "Action" in request:
        actions = request["Action"]
        if isinstance(actions, list):
            actions = sorted(actions)
        signature_parts.append(f"Action:{json.dumps(actions, sort_keys=True)}")
    
    # Add Resource (sorted if list)
    if "Resource" in request:
        resources = request["Resource"]
        if isinstance(resources, list):
            resources = sorted(resources)
        signature_parts.append(f"Resource:{json.dumps(resources, sort_keys=True)}")
    
    # Add Principal
    if "Principal" in request:
        principal = request["Principal"]
        signature_parts.append(f"Principal:{json.dumps(principal, sort_keys=True)}")
    
    # Add Condition (normalized)
    if "Condition" in request:
        condition = request["Condition"]
        signature_parts.append(f"Condition:{json.dumps(condition, sort_keys=True)}")
    
    # Add Effect
    if "Effect" in request:
        signature_parts.append(f"Effect:{request['Effect']}")
    
    return "|".join(signature_parts)

def check_file_uniqueness(file_path: str, show_details: bool = True) -> Dict[str, Any]:
    """Check uniqueness of requests in an existing file"""
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        
        requests = data.get("Requests", [])
        if not requests:
            print(f"No requests found in {file_path}")
            return {"error": "No requests found"}
        
        # Track signatures and find duplicates
        signatures = {}
        duplicates = []
        
        for i, request in enumerate(requests):
            signature = generate_request_signature(request)
            
            if signature in signatures:
                # Found a duplicate
                original_index = signatures[signature]
                duplicates.append({
                    "signature": signature,
                    "original_index": original_index,
                    "duplicate_index": i,
                    "original_request": requests[original_index],
                    "duplicate_request": request
                })
            else:
                signatures[signature] = i
        
        # Calculate statistics
        total_requests = len(requests)
        unique_requests = len(signatures)
        duplicate_count = len(duplicates)
        
        # Print summary
        print(f"\n=== Uniqueness Analysis for {file_path} ===")
        print(f"Total requests: {total_requests}")
        print(f"Unique requests: {unique_requests}")
        print(f"Duplicate requests: {duplicate_count}")
        print(f"Uniqueness rate: {unique_requests/total_requests:.1%}")
        
        if duplicate_count > 0:
            print(f"\n DUPLICATES FOUND!")
            
            if show_details:
                print(f"\nDuplicate Details:")
                for i, dup in enumerate(duplicates):
                    print(f"\n  Duplicate #{i+1}:")
                    print(f"    Original request index: {dup['original_index']}")
                    print(f"    Duplicate request index: {dup['duplicate_index']}")
                    print(f"    Request ID (original): {dup['original_request'].get('id', 'N/A')}")
                    print(f"    Request ID (duplicate): {dup['duplicate_request'].get('id', 'N/A')}")
                    
                    # Show first difference if any
                    orig = dup['original_request']
                    dupl = dup['duplicate_request']
                    
                    # Check if IDs are different but everything else is same
                    orig_copy = {k: v for k, v in orig.items() if k != 'id'}
                    dupl_copy = {k: v for k, v in dupl.items() if k != 'id'}
                    
                    if orig_copy == dupl_copy:
                        print(f"    Note: Requests are identical except for ID")
                    else:
                        print(f"    Note: Requests differ in content beyond ID")
                    
                    if i >= 9:  # Show max 10 duplicates
                        remaining = len(duplicates) - 10
                        if remaining > 0:
                            print(f"\n  ... and {remaining} more duplicates")
                        break
        else:
            print(f"\n NO DUPLICATES FOUND - All requests are unique!")
        
        # Calculate combinations
        total_combinations = 0
        allow_combinations = 0
        deny_combinations = 0
        
        for req in requests:
            actions = req.get("Action", [])
            resources = req.get("Resource", [])
            if not isinstance(actions, list):
                actions = [actions]
            if not isinstance(resources, list):
                resources = [resources]
            
            combinations = len(actions) * len(resources)
            total_combinations += combinations
            
            if req.get("Effect") == "allow":
                allow_combinations += combinations
            else:
                deny_combinations += combinations
        
        print(f"\nCombination Analysis:")
        print(f"Total individual combinations: {total_combinations}")
        print(f"Allow combinations: {allow_combinations}")
        print(f"Deny combinations: {deny_combinations}")
        if total_combinations > 0:
            print(f"Allow ratio: {allow_combinations/total_combinations:.1%}")
        
        return {
            "total_requests": total_requests,
            "unique_requests": unique_requests,
            "duplicate_count": duplicate_count,
            "duplicates": duplicates,
            "total_combinations": total_combinations,
            "allow_combinations": allow_combinations,
            "deny_combinations": deny_combinations
        }
        
    except FileNotFoundError:
        print(f"Error: File not found - {file_path}")
        return {"error": "File not found"}
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in file - {e}")
        return {"error": "Invalid JSON"}
    except Exception as e:
        print(f"Error: {e}")
        return {"error": str(e)}

def remove_duplicates_from_file(input_file: str, output_file: str = None):
    """Remove duplicates from a file and save the cleaned version"""
    try:
        with open(input_file, 'r') as file:
            data = json.load(file)
        
        requests = data.get("Requests", [])
        if not requests:
            print(f"No requests found in {input_file}")
            return
        
        # Remove duplicates
        signatures = set()
        unique_requests = []
        
        for request in requests:
            signature = generate_request_signature(request)
            
            if signature not in signatures:
                signatures.add(signature)
                unique_requests.append(request)
        
        # Update data
        data["Requests"] = unique_requests
        
        # Determine output file
        if output_file is None:
            output_file = input_file.replace('.json', '_unique.json')
        
        # Save cleaned version
        with open(output_file, 'w') as file:
            json.dump(data, file, indent=2)
        
        print(f"\n=== Duplicates Removed ===")
        print(f"Original requests: {len(requests)}")
        print(f"Unique requests: {len(unique_requests)}")
        print(f"Duplicates removed: {len(requests) - len(unique_requests)}")
        print(f"Cleaned file saved to: {output_file}")
        
    except Exception as e:
        print(f"Error removing duplicates: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python uniqueness_checker.py <file_path(s)> [options]")
        print("\nOptions:")
        print("  --no-details    : Don't show detailed duplicate information")
        print("  --clean         : Remove duplicates and save to new file")
        print("  --clean-output <file> : Remove duplicates and save to specified file (single file only)")
        print("\nExamples:")
        print("  python uniqueness_checker.py requests/request-25/0.json")
        print("  python uniqueness_checker.py requests/request-25/*.json")
        print("  python uniqueness_checker.py requests/request-25/0.json --no-details")
        print("  python uniqueness_checker.py requests/request-25/0.json --clean")
        print("  python uniqueness_checker.py requests/request-25/0.json --clean-output cleaned.json")
        return 1
    
    # Parse arguments
    args = sys.argv[1:]
    files = []
    options = []
    
    # Separate files from options
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith('--'):
            if arg == '--clean-output' and i + 1 < len(args):
                options.extend([arg, args[i + 1]])
                i += 2
            else:
                options.append(arg)
                i += 1
        else:
            files.append(arg)
            i += 1
    
    if not files:
        print("Error: No files specified")
        return 1
    
    # Parse options
    show_details = "--no-details" not in options
    clean_mode = "--clean" in options
    
    # Handle clean output
    clean_output = None
    if "--clean-output" in options:
        try:
            output_index = options.index("--clean-output") + 1
            clean_output = options[output_index]
            clean_mode = True
            if len(files) > 1:
                print("Warning: --clean-output only works with single file. Using --clean for multiple files.")
                clean_output = None
        except (IndexError, ValueError):
            print("Error: --clean-output requires a filename")
            return 1
    
    total_files = len(files)
    files_with_duplicates = 0
    total_duplicates = 0
    
    for i, file_path in enumerate(files):
        if total_files > 1:
            print(f"\n{'='*60}")
            print(f"Processing file {i+1}/{total_files}: {file_path}")
            print(f"{'='*60}")
        
        result = check_file_uniqueness(file_path, show_details and total_files <= 3)  # Show details for ≤3 files
        
        if "error" in result:
            print(f" Failed to process {file_path}")
            continue
        
        if result["duplicate_count"] > 0:
            files_with_duplicates += 1
            total_duplicates += result["duplicate_count"]
        
        if clean_mode:
            if result["duplicate_count"] > 0:
                remove_duplicates_from_file(file_path, clean_output if len(files) == 1 else None)
            elif len(files) == 1:
                print("\nNo cleaning needed - file already contains only unique requests.")
    
    # Summary for multiple files
    if total_files > 1:
        print(f"\n{'='*60}")
        print(f"SUMMARY FOR {total_files} FILES")
        print(f"{'='*60}")
        print(f"Files with duplicates: {files_with_duplicates}/{total_files}")
        print(f"Total duplicates found: {total_duplicates}")
        if files_with_duplicates == 0:
            print(" All files contain only unique requests!")
        else:
            print(f" {files_with_duplicates} files contain duplicates")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())