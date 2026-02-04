#!/usr/bin/env python
# encoding: utf-8
"""
Dragos Script Alert Action
Executes custom scripts for Dragos alerts and notifications
(e.g. ticket creation, SOAR integration, automation hooks)
"""

import sys
import os
import json
import subprocess
import tempfile

# Ensure local lib path is available
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))


def execute_script(config, payload):
    """Execute a user-supplied script with the alert payload"""

    script_name = config.get("script_name", "")
    script_args = config.get("script_args", "")
    pass_payload = config.get("pass_payload", "1") == "1"

    if not script_name:
        return False, "No script name configured"

    # Resolve script path (relative to bin/)
    bin_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(bin_dir, script_name)

    if not os.path.exists(script_path):
        return False, f"Script not found: {script_path}"

    # Base command
    cmd = [sys.executable, script_path]

    # Append script arguments
    if script_args:
        cmd.extend(script_args.split())

    payload_file = None

    # Write payload to temp file if requested
    if pass_payload:
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as fh:
                json.dump(payload, fh)
                payload_file = fh.name
            cmd.append(payload_file)
        except Exception as e:
            return False, f"Failed to create payload file: {e}"

    # Execute script
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute hard limit
        )

        # Cleanup
        if payload_file and os.path.exists(payload_file):
            os.remove(payload_file)

        if result.returncode != 0:
            return False, (
                f"Script exited with code {result.returncode}: "
                f"{result.stderr}"
            )

        return True, f"Script executed successfully: {result.stdout}"

    except subprocess.TimeoutExpired:
        return False, "Script execution timed out"
    except Exception as e:
        return False, f"Script execution failed: {str(e)}"


def main():
    """Splunk alert action entry point"""

    if len(sys.argv) < 2:
        print("ERROR: No payload file provided", file=sys.stderr)
        sys.exit(1)

    payload_file = sys.argv[1]

    try:
        with open(payload_file, "r") as fh:
            payload = json.load(fh)
    except Exception as e:
        print(f"ERROR: Failed to read payload: {e}", file=sys.stderr)
        sys.exit(1)

    config = payload.get("configuration", {})

    success, message = execute_script(config, payload)

    if success:
        print(f"INFO: {message}")
        sys.exit(0)
    else:
        print(f"ERROR: {message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
