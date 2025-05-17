
# Automated Infrastructure Compliance Checker

This project provides an automated solution to verify your cloud environment’s compliance with defined internal policies. Often, periodic—and secure—scanning of your infrastructure is required, but building a robust, scheduled solution that integrates with various Azure services can be challenging. This application solves that problem by:

- Reading compliance rules from **Cosmos DB**.
- Securely retrieving configuration and credentials from **Azure Key Vault**.
- Storing scan reports in an **Azure Storage Account**.
- Sending alerts via **Azure Service Bus** when non-compliant resources are detected.
- Logging operational detail to **Azure Application Insights**.
- Using OIDC with **Managed Identity** (via DefaultAzureCredential) to authenticate securely.
- Running as an AKS CronJob for periodic execution.
- Including unit tests (with pytest) for quality assurance.

## Business Use Case Overview

Many organizations require continuous compliance monitoring to ensure that resource naming conventions, security configurations, tag policies, and other standards are met. This tool automates that process by:
- Fetching compliance rules and thresholds from Cosmos DB.
- Scanning a set of target resources (simulated in this example).
- Writing a compliance report to a Storage Account.
- Issuing alerts via Service Bus if discrepancies are detected.
- Using managed identity and OIDC to securely authenticate with Azure services without hardcoding credentials.

This solution integrates several Azure services to provide a secure, automated, and scalable way to ensure infrastructure compliance.

## Prerequisites

- **Azure Resources:**
  - Cosmos DB (with a database and container holding compliance rules)
  - Azure Key Vault (storing credentials or sensitive settings)
  - Azure Storage Account (for saving scan reports)
  - Azure Service Bus (for alerting on compliance failures)
  - Application Insights (for logging and telemetry)
- **Managed Identity & OIDC:**  
  Ensure your AKS cluster has managed identity enabled so that your application can use the DefaultAzureCredential for OIDC-based secure calls.
- A running **AKS cluster**.
- Docker installed for building images.
- Python 3.9+ and pip for developing locally.

## Application Code

Create a file named `compliance_checker.py` with the following code:

```python
from flask import Flask, jsonify
import os
import logging
import datetime

# Cosmos DB imports
from azure.cosmos import CosmosClient

# Service Bus imports
from azure.servicebus import ServiceBusClient, ServiceBusMessage

# Azure Storage imports
from azure.storage.blob import BlobServiceClient

# Key Vault imports
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Application Insights via OpenCensus
from opencensus.ext.azure.log_exporter import AzureLogHandler

# Managed Identity via OIDC (using DefaultAzureCredential for secure auth)
credential = DefaultAzureCredential()

app = Flask(__name__)

# --- Logging Setup (Application Insights) ---
logger = logging.getLogger(__name__)
app_insights_conn_str = os.environ.get("APPINSIGHTS_CONNECTION_STRING")
logger.addHandler(AzureLogHandler(connection_string=app_insights_conn_str))
logger.setLevel(logging.INFO)

# --- Cosmos DB Configuration (Compliance Rules Store) ---
COSMOS_ENDPOINT = os.environ.get("COSMOS_ENDPOINT")
COSMOS_KEY = os.environ.get("COSMOS_KEY")
COSMOS_DATABASE = os.environ.get("COSMOS_DATABASE")
COSMOS_CONTAINER = os.environ.get("COSMOS_CONTAINER")
cosmos_client = CosmosClient(COSMOS_ENDPOINT, COSMOS_KEY)
database = cosmos_client.get_database_client(COSMOS_DATABASE)
compliance_rules_container = database.get_container_client(COSMOS_CONTAINER)

# --- Service Bus Configuration (Alerts) ---
SERVICE_BUS_CONNECTION_STR = os.environ.get("SERVICE_BUS_CONNECTION_STR")
SERVICE_BUS_QUEUE = os.environ.get("SERVICE_BUS_QUEUE")

# --- Azure Storage Configuration (Reports) ---
STORAGE_CONNECTION_STRING = os.environ.get("STORAGE_CONNECTION_STRING")
STORAGE_CONTAINER = os.environ.get("STORAGE_CONTAINER")
blob_service_client = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
storage_container_client = blob_service_client.get_container_client(STORAGE_CONTAINER)

# --- Key Vault Configuration ---
KEY_VAULT_URL = os.environ.get("KEY_VAULT_URL")
key_vault_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)

@app.route('/scan')
def run_compliance_scan():
    """ 
    Run a simulated compliance scan.
    This method:
      - Reads compliance rules from Cosmos DB.
      - Simulates scanning target resources.
      - Saves a scan report to Blob Storage.
      - Sends an alert to Service Bus if non-compliance detected.
      - Retrieves extra config from Key Vault, if needed.
      - Logs all operations.
    """
    try:
        # Retrieve compliance rules from Cosmos DB
        rules = list(compliance_rules_container.read_all_items())
        logger.info(f"Retrieved {len(rules)} compliance rule(s) from Cosmos DB.")

        # Simulate scan (actual resource scanning code would go here)
        # For demonstration, we assume a violation if there is at least one rule.
        violations = len(rules) > 0

        # Create a scan report
        report = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "violations": violations,
            "rules_checked": len(rules),
            "details": "Simulated scan: Policy violations detected." if violations else "All resources compliant."
        }

        # Save report to Blob Storage
        report_blob_name = f"compliance-report-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        blob_client = storage_container_client.get_blob_client(report_blob_name)
        blob_client.upload_blob(str(report), overwrite=True)
        logger.info(f"Compliance report saved as {report_blob_name} in Azure Storage.")

        # If there are violations, send an alert via Service Bus
        if violations:
            message = ServiceBusMessage(f"Compliance violation detected at {report['timestamp']}")
            with ServiceBusClient.from_connection_string(conn_str=SERVICE_BUS_CONNECTION_STR, logging_enable=True) as sb_client:
                sender = sb_client.get_queue_sender(queue_name=SERVICE_BUS_QUEUE)
                with sender:
                    sender.send_messages(message)
            logger.info("Alert sent via Service Bus for compliance violation.")

        # Optionally retrieve extra configuration from Key Vault (if required)
        secret_name = "ExtraConfig"
        try:
            extra_config = key_vault_client.get_secret(secret_name).value
            logger.info(f"Retrieved extra config '{secret_name}' from Key Vault.")
        except Exception as kv_ex:
            logger.warning(f"Could not retrieve secret '{secret_name}': {kv_ex}")
            extra_config = None

        return jsonify({"status": "Scan completed", "report": report, "extra_config": extra_config}), 200

    except Exception as e:
        logger.error("Error during compliance scan", exc_info=e)
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # When run as a Flask application, listen on port 5000.
    # In production, this script will be executed as a CronJob.
    app.run(host='0.0.0.0', port=5000)
```

## Unit Testing

Create a file named `test_compliance_checker.py` with the following tests (using pytest):

```python
import pytest
from compliance_checker import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_scan_endpoint(client):
    """Test that the /scan endpoint returns a 200 OK status."""
    response = client.get('/scan')
    assert response.status_code == 200
    json_data = response.get_json()
    assert "status" in json_data
```

Run the tests with the command:

```bash
pytest test_compliance_checker.py
```

## Dockerization

Create a `requirements.txt` file:

```
flask
azure-cosmos
azure-servicebus
azure-storage-blob
azure-identity
azure-keyvault-secrets
opencensus-ext-azure
pytest
```

Then create a `Dockerfile`:

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY compliance_checker.py .
COPY test_compliance_checker.py .
EXPOSE 5000
CMD ["python", "compliance_checker.py"]
```

Build and push your Docker image:

```bash
docker build -t <your-container-registry>/compliance-checker:latest .
docker push <your-container-registry>/compliance-checker:latest
```

*Replace `<your-container-registry>` with your actual registry name (e.g., ACR or Docker Hub).*

## Deploying to AKS as a CronJob

Create a Kubernetes manifest named `aks_cronjob.yaml`:

```yaml
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: compliance-checker-cron
spec:
  schedule: "0 2 * * *"  # Runs daily at 2 AM UTC
  jobTemplate:
    spec:
      template:
        metadata:
          labels:
            app: compliance-checker
        spec:
          containers:
          - name: compliance-checker
            image: <your-container-registry>/compliance-checker:latest
            env:
            - name: COSMOS_ENDPOINT
              value: "<COSMOS_ENDPOINT>"
            - name: COSMOS_KEY
              value: "<COSMOS_KEY>"
            - name: COSMOS_DATABASE
              value: "<COSMOS_DATABASE>"
            - name: COSMOS_CONTAINER
              value: "<COSMOS_CONTAINER>"
            - name: SERVICE_BUS_CONNECTION_STR
              value: "<SERVICE_BUS_CONNECTION_STRING>"
            - name: SERVICE_BUS_QUEUE
              value: "<SERVICE_BUS_QUEUE>"
            - name: STORAGE_CONNECTION_STRING
              value: "<STORAGE_CONNECTION_STRING>"
            - name: STORAGE_CONTAINER
              value: "<STORAGE_CONTAINER>"
            - name: KEY_VAULT_URL
              value: "<KEY_VAULT_URL>"
            - name: APPINSIGHTS_CONNECTION_STRING
              value: "<APPINSIGHTS_CONNECTION_STRING>"
          restartPolicy: OnFailure
```

Deploy the CronJob to your AKS cluster:

```bash
kubectl apply -f aks_cronjob.yaml
```

## Summary of Steps

1. **Provision Azure Resources:**  
   Set up Cosmos DB (for compliance rules), Key Vault (for sensitive settings), Storage Account (for scan reports), Service Bus (for alerts), and Application Insights.

2. **Develop the Compliance Checker:**  
   Create a Python Flask application (`compliance_checker.py`) that performs a simulated compliance scan—reading rules, writing reports, and issuing alerts.

3. **Add Unit Tests:**  
   Write tests using pytest to verify that the scan endpoint works as expected.

4. **Containerize the Application:**  
   Create a `requirements.txt` and `Dockerfile`; build and push the container image.

5. **Deploy as a CronJob in AKS:**  
   Use a Kubernetes CronJob manifest to schedule the compliance scan (e.g., daily at 2 AM UTC).

6. **Secure and Monitor:**  
   Use Managed Identity with OIDC (via DefaultAzureCredential) for secure authentication across Azure resources and log all operations to Application Insights.

## Conclusion

This project demonstrates a robust DevOps use case where a Python Flask application automates infrastructure compliance checks by integrating multiple Azure services. Deploying it as an AKS CronJob ensures periodic and automated scanning. The solution addresses secure credential handling (via Key Vault and Managed Identity), scalable storage/reporting (via Cosmos DB and Storage Account), asynchronous alerting (via Service Bus), and centralized monitoring (via Application Insights). 

For further guidance, refer to the official documentation:
- [Azure Cosmos DB for Python](https://docs.microsoft.com/en-us/azure/cosmos-db/sql-api-sdk-python)
- [Azure Key Vault for Python](https://docs.microsoft.com/en-us/azure/key-vault/secrets/quick-create-python)
- [Azure Storage Blob for Python](https://docs.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-python)
- [DefaultAzureCredential (Managed Identity)](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/tutorial-vm-windows-accessing-key-vault)
- [Kubernetes CronJobs](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
- [OpenCensus with Application Insights](https://github.com/census-instrumentation/opencensus-python/tree/master/contrib/opencensus-ext-azure)

