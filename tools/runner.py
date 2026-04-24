import subprocess
import shlex
from config import TIMEOUT_CMD


def run_cmd(cmd: str, timeout: int = TIMEOUT_CMD,
            stdin: str = None, shell: bool = False) -> dict:
    """
    Execute a shell command safely. Returns a dict with:
        stdout, stderr, returncode, error (None if OK)
    """
    try:
        args = cmd if shell else shlex.split(cmd)
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin,
            shell=shell,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "", "returncode": -1,
                "error": f"Timed out after {timeout}s"}
    except FileNotFoundError as e:
        return {"stdout": "", "stderr": "", "returncode": -1,
                "error": f"Tool not found: {e}"}
    except Exception as e:
        return {"stdout": "", "stderr": "", "returncode": -1,
                "error": str(e)}


def tool_available(name: str) -> bool:
    """Check if a CLI tool is installed."""
    r = run_cmd(f"which {name}", timeout=5)
    return r["returncode"] == 0