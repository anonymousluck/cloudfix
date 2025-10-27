# CloudFix: Automated Policy Repair for Cloud Access Control Policies Using Large Language Models


**CloudFix** is a research framework for the **automatic repair of misconfigured AWS IAM policies** using **Large Language Models (LLMs)** guided by **Fault Localization (FL)** and **symbolic validation**.

The system identifies faulty IAM policy statements, generates candidate repairs using LLMs, and validates repaired policies using an SMT-based verifier to ensure both **security** and **functionality**.

This repository contains the complete experimental pipeline, from dataset preparation to evaluation and visualization, used to support our research results.



CloudFix implements:

1. **Fault Localization** — Identify the faulty statement(s) in a policy.  
2. **Repair Generation** — Use an LLM to propose candidate repairs.  
3. **Validation** — Verify repaired policies against access-request specifications.  
4. **Iteration** — Repeat until all requests are satisfied or the iteration limit is reached. 

## Repository Structure

```text
FL/
├── original_policy/         # Original (unrepaired) IAM policies
├── figures/                 # Figures and visualizations from experiments
└── src/
    ├── requests/            # Access-request specifications
    ├── result/              # Outputs from Baseline and FL repair experiments
    ├── baseline_model.py    # Baseline (unguided) LLM repair pipeline
    ├── fl_model.py          # Fault-Localization-guided repair pipeline
    ├── evaluate.py          # Evaluation and validation script
    ├── req_checker.py       # Access-request compliance checker
    ├── request_augment.py   # Request augmentation utilities
    ├── request_generate.py  # Request generation script
    └── viz.ipynb            # Visualization notebook




