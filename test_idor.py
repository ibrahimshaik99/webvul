import requests
import time
from prettytable import PrettyTable

def send_request(url, data=None, allow_redirects=True, timeout=10):
    """Send an HTTP request to the specified URL."""
    try:
        if data:
            response = requests.post(url, data=data, allow_redirects=allow_redirects, timeout=timeout)
        else:
            response = requests.get(url, allow_redirects=allow_redirects, timeout=timeout)
        return response
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

def test_idor(url, object_ids):
    """Test for Insecure Direct Object Reference (IDOR) vulnerabilities using the provided object IDs."""
    table = PrettyTable(["URL", "Object ID", "Status Code", "IDOR Detected", "Error Message"])
    table.align["IDOR Detected"] = "l"

    for obj_id in object_ids:
        test_url = f"{url.rstrip('/')}/user/{obj_id}"  # Ensure well-formed URLs
        idor_detected = "No"
        error_message = "N/A"

        try:
            response = send_request(test_url, allow_redirects=False, timeout=10)
            if response:
                status_code = response.status_code

                # Determine if IDOR vulnerability exists
                if status_code == 200 and "success" in response.text.lower():
                    idor_detected = "Yes"
                elif status_code == 401 or status_code == 403:
                    error_message = "Unauthorized access"
                elif status_code == 404:
                    error_message = "Object not found"

                table.add_row([test_url, obj_id, status_code, idor_detected, error_message])
                if idor_detected == "Yes":
                    print(f"[+] IDOR detected: {test_url}")
            else:
                table.add_row([test_url, obj_id, "No Response", idor_detected, "No response from server"])
        except requests.exceptions.Timeout as e:
            table.add_row([test_url, obj_id, "Timeout", "N/A", str(e)])
            print(f"[!] Timeout error for {test_url}: {e}")
        except requests.exceptions.RequestException as e:
            table.add_row([test_url, obj_id, "Error", "N/A", str(e)])
            print(f"[!] Request error for {test_url}: {e}")
        time.sleep(0.1)  # Avoid overloading the server

    print(table)

    # Perform additional checks for IDOR
    print("\nAdditional Checks:")
    additional_table = PrettyTable(["URL", "Check Type", "Result"])
    additional_table.align["Check Type"] = "l"

    for obj_id in object_ids:
        test_url = f"{url.rstrip('/')}/user/{obj_id}"
        try:
            response = send_request(test_url, allow_redirects=False, timeout=10)
            if response:
                # Look for specific keywords indicating common vulnerabilities
                if "insecure direct object reference" in response.text.lower():
                    additional_table.add_row([test_url, "Insecure Direct Object Reference", "Detected"])
                    print(f"[!] Insecure direct object reference detected: {test_url}")
                
                if "missing access control" in response.text.lower():
                    additional_table.add_row([test_url, "Missing Access Control", "Detected"])
                    print(f"[!] Missing access control detected: {test_url}")
                
                if "horizontal privilege escalation" in response.text.lower():
                    additional_table.add_row([test_url, "Horizontal Privilege Escalation", "Detected"])
                    print(f"[!] Horizontal privilege escalation detected: {test_url}")
        except requests.exceptions.RequestException as e:
            print(f"[!] Request error for {test_url}: {e}")
        time.sleep(0.1)

    print(additional_table)


# Example object IDs for testing
object_ids = [
    "1", "2", "3", "4", "5", 
    "100", "101", "200", "201", "300"
]

if __name__ == "__main__":
    url = input("Enter the base URL to test (e.g., http://example.com): ")
    if not url.startswith("http"):
        print("Please provide a valid URL (e.g., including http:// or https://).")
    else:
        test_idor(url, object_ids)

