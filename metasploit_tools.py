from pymetasploit3.msfrpc import MsfRpcClient
import time

class MetasploitSession:
    def __init__(self, host, port, user, password):
        print(f"--- Connecting to Metasploit RPC ({host}:{port}) ---")
        # SSL is True by default for msfrpcd unless you specifically disabled it
        self.client = MsfRpcClient(password, username=user, server=host, port=port, ssl=True)

        # Create a persistent console
        self.console = self.client.consoles.console()
        self.cid = self.console.cid
        print(f"--- Console Created (ID: {self.cid}) ---")

    def send_command(self, command, timeout=60):
        """Sends a command and waits for the prompt to return."""
        # Clean the command
        command = command.strip()

        # Write to the persistent console
        self.console.write(command + "\n")

        output = ""
        start_time = time.time()

        while time.time() - start_time < timeout:
            response = self.console.read()
            chunk = response.get('data', '')
            output += chunk

            # STOPPING CONDITION:
            # We stop if we see the standard prompt (msf6 >) OR
            # if we see a shell prompt (C:\>, #, $) if we are inside a session.
            # We also check if 'busy' is False, but MSF is tricky with that.
            if not response.get('busy') and len(output) > 0:
                # Slight delay to ensure buffer is flushed
                time.sleep(0.5)
                # One last read to catch tail end
                output += self.console.read().get('data', '')
                break

            time.sleep(1)

        return output

    def cleanup(self):
        """Destroy the console to free memory on Kali."""
        try:
            self.client.consoles.destroy(self.cid)
            print(f"--- Console {self.cid} Destroyed ---")
        except:
            pass


# --- GLOBAL SESSION INSTANCE ---
# Initialize this ONCE at the top of your script
msf_session = MetasploitSession(
    host="192.168.34.6",
    port=55553,
    user="kali",
    password="kali"
)