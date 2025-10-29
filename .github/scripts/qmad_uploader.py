import os
import sys
import time
import json
import xml.etree.ElementTree as ET
from google.cloud import firestore
import requests

# -------------------------------------------------------------------
#  Script to poll SonarCloud for results and upload to Firebase
# -------------------------------------------------------------------

def get_env_var(var_name, is_secret=False, required=True):
    """Gets an environment variable."""
    value = os.environ.get(var_name)
    if not value and required:
        print(f"Error: Environment variable {var_name} is not set.")
        sys.exit(1)
    if value:
        if is_secret:
            print(f"Successfully loaded secret {var_name}.")
        else:
            print(f"Loaded config {var_name}: {value}")
    return value

def parse_coverage_xml(xml_file="coverage.xml"):
    """Parses the coverage.xml file to get the line-rate."""
    try:
        if not os.path.exists(xml_file):
            print(f"Warning: Coverage file '{xml_file}' not found. Defaulting to 0 coverage.")
            return 0.0
        tree = ET.parse(xml_file)
        root = tree.getroot()
        coverage_percent = float(root.attrib.get("line-rate", 0)) * 100
        return round(coverage_percent, 2)
    except Exception as e:
        print(f"Warning: Could not parse {xml_file}. Defaulting to 0 coverage. Error: {e}")
        return 0.0

def get_sonar_task_id(report_file=".sonar/scanner-report/report-task.txt"):
    """
    Reads the SonarCloud compute engine task ID from the report file.
    Note: The path changed in newer sonar-scanner versions.
    """
    # Try the new path first
    if not os.path.exists(report_file):
        report_file = ".sonar/scanner/report-task.txt" # Try the old path
        
    try:
        if not os.path.exists(report_file):
            print(f"Warning: Sonar report file '{report_file}' not found. Skipping Sonar metrics.")
            return None
        with open(report_file, 'r') as f:
            props = dict(line.strip().split('=', 1) for line in f if '=' in line)
            return props.get("ceTaskId")
    except Exception as e:
        print(f"Error: Could not read Sonar report file at {report_file}. Error: {e}")
        return None

def poll_sonar_analysis(task_id, sonar_token, sonar_host):
    """Polls SonarCloud's API until the analysis is complete."""
    api_url = f"{sonar_host}/api/ce/task?id={task_id}"
    headers = {"Authorization": f"Bearer {sonar_token}"}
    
    for i in range(20):  # Poll for up to 100 seconds (20 * 5s)
        try:
            res = requests.get(api_url, headers=headers)
            res.raise_for_status()
            task_data = res.json().get("task", {})
            status = task_data.get("status")
            
            if status == "SUCCESS":
                print(f"SonarCloud analysis is complete (Attempt {i+1}).")
                return task_data.get("analysisId")
            elif status in ["FAILED", "CANCELED"]:
                print(f"Error: SonarCloud analysis {status}.")
                return None # Don't exit, just return None and let fallback run
            else:
                print(f"SonarCloud analysis in progress (Status: {status}). Waiting 5 seconds...")
                time.sleep(5)
        except Exception as e:
            print(f"Error polling SonarCloud API: {e}")
            time.sleep(5)
            
    print("Error: SonarCloud analysis timed out.")
    return None # Don't exit, let fallback run

def _parse_sonar_measures(measures):
    """Helper function to parse the list of metrics from SonarCloud."""
    metrics = {}
    for m in measures:
        metric_key = m.get("metric")
        value_str = m.get("value", "0")

        if metric_key in ["security_rating", "reliability_rating", "sqale_rating"]:
            # These are 'A', 'B', 'C' ratings (strings)
            metrics[metric_key] = value_str
        elif metric_key == "coverage":
            # This is a float (e.g., '75.0')
            try:
                metrics[metric_key] = round(float(value_str), 2)
            except ValueError:
                metrics[metric_key] = 0.0
        else:
            # All others (bugs, vulnerabilities, code_smells) are ints
            try:
                metrics[metric_key] = int(value_str)
            except ValueError:
                metrics[metric_key] = 0
    return metrics

def get_sonar_metrics(analysis_id, project_key, sonar_token, sonar_host):
    """Fetches the final metrics from SonarCloud using the analysisId."""
    api_url = f"{sonar_host}/api/measures/component"
    params = {
        "component": project_key,
        "analysisId": analysis_id,
        "metricKeys": "bugs,vulnerabilities,code_smells,coverage,security_rating,reliability_rating,sqale_rating"
    }
    headers = {"Authorization": f"Bearer {sonar_token}"}
    
    try:
        res = requests.get(api_url, headers=headers, params=params)
        res.raise_for_status()
        measures = res.json().get("component", {}).get("measures", [])
        
        metrics = _parse_sonar_measures(measures) # Use helper
        print(f"Successfully fetched SonarCloud metrics: {metrics}")
        return metrics
    except Exception as e:
        print(f"Error fetching SonarCloud metrics: {e}")
        print(f"Response: {res.text}")
        return {}
        
def get_sonar_metrics_fallback(project_key, sonar_token, sonar_host, sonar_org):
    """Fetches the *latest* metrics from SonarCloud (fallback method)."""
    print("Using SonarCloud fallback metrics API...")
    api_url = f"{sonar_host}/api/measures/component"
    params = {
        "component": project_key,
        "metricKeys": "bugs,vulnerabilities,code_smells,coverage,security_rating,reliability_rating,sqale_rating"
    }
    headers = {"Authorization": f"Bearer {sonar_token}"}
    
    try:
        res = requests.get(api_url, headers=headers, params=params)
        if res.status_code == 401:
            print("Bearer token failed. Trying basic auth.")
            res = requests.get(api_url, auth=(sonar_token, ""), params=params)
        
        res.raise_for_status()
        measures = res.json().get("component", {}).get("measures", [])
        
        metrics = _parse_sonar_measures(measures) # Use helper
        
        print(f"Successfully fetched SonarCloud (fallback) metrics: {metrics}")
        return metrics
    except Exception as e:
        print(f"Error fetching SonarCloud fallback metrics: {e}")
        if "res" in locals():
             print(f"Response: {res.text}")
        return {}


def main():
    print("Starting Q-MAD data uploader...")

    # --- 1. Get All Environment Variables ---
    project_id = get_env_var("QMAD_PROJECT_ID")
    commit_sha = get_env_var("GITHUB_SHA")
    repo_name = get_env_var("GITHUB_REPOSITORY")
    run_id = get_env_var("GITHUB_RUN_ID")
    
    service_account_json = get_env_var("QMAD_FIREBASE_SERVICE_ACCOUNT", is_secret=True)
    
    sonar_token = get_env_var("SONAR_TOKEN", is_secret=True, required=False)
    sonar_project_key = get_env_var("SONAR_PROJECT_KEY", required=False)
    sonar_org = get_env_var("SONAR_ORGANIZATION", required=False)

    sonar_host = "https://sonarcloud.io"
    test_result = get_env_var("PYTEST_RESULT")
    
    github_run_url = f"https://github.com/{repo_name}/actions/runs/{run_id}"
    short_commit = commit_sha[:7]
    sonar_metrics = {}

    # --- 2. Initialize Firebase ---
    try:
        creds_dict = json.loads(service_account_json)
        db = firestore.Client.from_service_account_info(creds_dict)
        print("Firebase connection successful.")
    except Exception as e:
        print(f"Error: Could not connect to Firebase. Check QMAD_FIREBASE_SERVICE_ACCOUNT. Error: {e}")
        sys.exit(1)

    # --- 3. Get Local Metrics (Test & Coverage) ---
    print("Parsing local test and coverage results...")
    coverage_percent = parse_coverage_xml("coverage.xml")
    print(f"Test Result: {test_result}, Coverage: {coverage_percent}%")
    
    # --- 4. Get SonarCloud Metrics (if configured) ---
    if sonar_token and sonar_project_key and sonar_org:
        print("Fetching SonarCloud analysis results...")
        task_id = get_sonar_task_id()
        if task_id:
            analysis_id = poll_sonar_analysis(task_id, sonar_token, sonar_host)
            if analysis_id:
                sonar_metrics = get_sonar_metrics(analysis_id, sonar_project_key, sonar_token, sonar_host)
            else:
                print("Warning: Could not get SonarCloud analysisId. Using fallback.")
                sonar_metrics = get_sonar_metrics_fallback(sonar_project_key, sonar_token, sonar_host, sonar_org)
        else:
            print("Warning: Could not find SonarCloud task ID. Using fallback.")
            sonar_metrics = get_sonar_metrics_fallback(sonar_project_key, sonar_token, sonar_host, sonar_org)
    else:
        print("Skipping SonarCloud metrics: SONAR_TOKEN, SONAR_PROJECT_KEY, or SONAR_ORGANIZATION not set.")
    
    # --- 5. Prepare Data Packet ---
    timestamp = firestore.SERVER_TIMESTAMP
    
    # Use local pytest coverage as the primary source
    final_coverage = coverage_percent
    if sonar_metrics.get("coverage", 0) > 0 and final_coverage == 0:
        # Use sonar coverage only if local parsing failed
        final_coverage = sonar_metrics.get("coverage", 0)

    metrics_data = {
        "id": short_commit,
        "testResult": test_result,
        "coverage": final_coverage, # Use the most reliable coverage
        "vulnerabilities": sonar_metrics.get("vulnerabilities", 0),
        "bugs": sonar_metrics.get("bugs", 0),
        "codeSmells": sonar_metrics.get("code_smells", 0),
        "maintainability": sonar_metrics.get("sqale_rating", "N/A"),
        "reliability": sonar_metrics.get("reliability_rating", "N/A"),
        "security": sonar_metrics.get("security_rating", "N/A"),
        "timestamp": timestamp,
        "githubRunUrl": github_run_url,
    }

    # Determine overall risk
    risk = "GREEN"
    if test_result == "FAIL" or sonar_metrics.get("vulnerabilities", 0) > 0 or (sonar_metrics.get("security_rating", "A") > "C" and sonar_metrics.get("security_rating") != "N/A"):
        risk = "RED"
    elif final_coverage < 70 or sonar_metrics.get("bugs", 0) > 5 or (sonar_metrics.get("sqale_rating", "A") > "B" and sonar_metrics.get("sqale_rating") != "N/A"):
        risk = "YELLOW"

    project_summary_data = {
        "projectName": repo_name,
        "latestMetrics": metrics_data,
        "latestCommit": short_commit,
        "latestStatus": test_result,
        "riskScore": risk,
        "lastAnalyzed": timestamp,
        "githubRepoUrl": f"https://github.com/{repo_name}"
    }

    # --- 6. Upload to Firebase ---
    try:
        print(f"Uploading data for project: {project_id}")
        
        metrics_ref = db.collection("projects").document(project_id).collection("metrics").document(short_commit)
        metrics_ref.set(metrics_data)
        print(f"Successfully wrote metrics to doc: {short_commit}")

        project_ref = db.collection("projects").document(project_id)
        project_ref.set(project_summary_data, merge=True)
        print(f"Successfully updated project summary: {project_id}")

        print("\nQ-MAD upload complete! Check your dashboard.")
        
    except Exception as e:
        print(f"Error: Failed to write to Firebase. Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

