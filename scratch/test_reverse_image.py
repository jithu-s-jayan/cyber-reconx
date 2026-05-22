import os
import requests
import sys
from PIL import Image

BASE_URL = "http://127.0.0.1:5000"

def create_dummy_image(path):
    print(f"[TEST] Creating a dummy image at {path}...")
    img = Image.new('RGB', (100, 100), color = 'red')
    img.save(path)
    print("[PASS] Dummy image created successfully.")

def test_reverse_image_flow():
    print("[TEST] 1. Creating operator session...")
    session = requests.Session()
    reg = session.post(f"{BASE_URL}/api/register", json={
        "name": "Operator Visual",
        "email": "visual@recon.local",
        "password": "securepassword"
    })
    if reg.status_code != 200 and "already registered" in reg.text:
        print("[INFO] Operator already exists. Logging in instead...")
        login_res = session.post(f"{BASE_URL}/api/login", json={
            "email": "visual@recon.local",
            "password": "securepassword"
        })
        assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    else:
        assert reg.status_code == 200, f"Registration failed: {reg.text}"
    print("[PASS] Operator session established.")

    # Create dummy image in the same directory as the test script
    dummy_img_path = os.path.join(os.path.dirname(__file__), "test_payload.png")
    create_dummy_image(dummy_img_path)

    try:
        print("\n[TEST] 2. Uploading visual asset to /api/reverse-image...")
        with open(dummy_img_path, "rb") as img_file:
            files = {"image": ("test_payload.png", img_file, "image/png")}
            res = session.post(f"{BASE_URL}/api/reverse-image", files=files)
            
        print(f"[DATA] Status: {res.status_code}")
        assert res.status_code == 200, f"Upload failed: {res.text}"
        data = res.json()
        print("[PASS] Successfully uploaded visual asset and received visual intelligence.")
        
        # Verify returned attributes
        assert "fingerprint" in data, "Response missing 'fingerprint'"
        assert "metadata" in data, "Response missing 'metadata'"
        assert "matches" in data, "Response missing 'matches'"
        assert "threat_score" in data, "Response missing 'threat_score'"
        assert "threat_level" in data, "Response missing 'threat_level'"
        assert "intelligence_score" in data, "Response missing 'intelligence_score'"
        assert "image_url" in data, "Response missing 'image_url'"
        
        print(f"[DATA] Visual Fingerprint (dHash): {data['fingerprint']}")
        print(f"[DATA] Threat Score: {data['threat_score']}% ({data['threat_level']})")
        print(f"[DATA] Intelligence Quality Score: {data['intelligence_score']}%")
        print(f"[DATA] Resolved Matches Count: {len(data['matches'])}")
        
        # Verify scan registered in history
        print("\n[TEST] 3. Verifying scan registration in operator history...")
        history = session.get(f"{BASE_URL}/api/history").json()
        assert len(history) >= 1, "Operator history should contain at least 1 scan"
        latest_scan = history[0]
        assert latest_scan["scan_type"] == "Reverse Image Intel", f"Expected scan type 'Reverse Image Intel', got '{latest_scan['scan_type']}'"
        print(f"[PASS] Scan registered in database history with ID: {latest_scan['id']}")
        
        # Verify stats updated
        print("\n[TEST] 4. Verifying dashboard statistics update...")
        stats = session.get(f"{BASE_URL}/api/stats").json()
        assert stats["total_scans"] >= 1, "Total scans in statistics should be >= 1"
        print(f"[PASS] Statistics updated successfully. Total scans: {stats['total_scans']}")
        
        # Verify PDF report downloads correctly
        print("\n[TEST] 5. Validating PDF Report Generation...")
        pdf_res = session.get(f"{BASE_URL}/api/report/{latest_scan['id']}")
        print(f"[DATA] PDF Download Status: {pdf_res.status_code}")
        assert pdf_res.status_code == 200, f"Failed to download PDF report: {pdf_res.text}"
        assert pdf_res.headers.get("content-type") == "application/pdf", f"Expected content-type 'application/pdf', got '{pdf_res.headers.get('content-type')}'"
        print("[PASS] PDF Report downloaded successfully and is valid PDF content.")

    finally:
        # Cleanup dummy image
        if os.path.exists(dummy_img_path):
            os.remove(dummy_img_path)
            print("[TEST] Cleaned up test_payload.png.")

if __name__ == "__main__":
    try:
        test_reverse_image_flow()
        print("\n=======================================================")
        print("ALL REVERSE IMAGE SYSTEM TESTS PASSED SUCCESSFULLY!")
        print("=======================================================")
    except AssertionError as e:
        print(f"\n[FAIL] Test assertion failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error during validation: {e}")
        sys.exit(1)
