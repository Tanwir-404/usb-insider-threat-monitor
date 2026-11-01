# USB Guard Admin Console (Phase 1)

## Run on Mac (mock mode)
    python3 -m venv venv && source venv/bin/activate
    pip install -r requirements.txt
    python app.py
Open http://127.0.0.1:5000  (login: admin / admin123)

## Run on Linux endpoint (real mode)
    MODE=real WAZUH_INDEXER=https://<wazuh-ip>:9200 WAZUH_PASS=<password> python app.py
The user running Flask needs passwordless sudo for `usbguard` only (see sudoers note below).
    echo "youruser ALL=(root) NOPASSWD: /usr/bin/usbguard" | sudo tee /etc/sudoers.d/usbguard-admin
Change ADMIN_PASS and SECRET_KEY environment variables before real use.
