import paramiko
import sys
import time

# metadata settings
KALI_IP = "192.168.34.4"
KALI_USER = "kali"
KALI_PASS = "kali"
REMOTE_WORK_DIR = "~/CREMEv2/CREME_backend_execution/scripts/02_scenario"
REMOTE_ENV = "~/.venvs/redteamingenv/bin/activate"
LOG_FOLDER_NAME = "creme_logs"

def run_step_03_remote():
    """
    從 Windows 連線到 Kali 並執行 02_step 腳本，同時即時串流回傳輸出。
    這個函數專門設計用來呼叫 Kali 上的 Metasploit 自動化腳本。
    """
    print(f"=== [Windows Controller] 正在連線到 Kali ({KALI_IP}) 執行 Step 02 ===")

    # 建立 SSH Client
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # 1. 建立連線
        ssh.connect(KALI_IP, username=KALI_USER, password=KALI_PASS, timeout=10)
        print("[Windows Controller] SSH 連線成功！")

        # 2. 組合指令
        # python3 -u 代表 "Unbuffered" (不緩衝)，這對即時看到輸出很重要
        # 確保遠端腳本路徑是絕對路徑，避免找不到檔案
        command = (
            f"source {REMOTE_ENV} && "
            f"cd {REMOTE_WORK_DIR} && "
            f"python3 03_ransomware/python_files/attacker_server/test3.py {LOG_FOLDER_NAME} {KALI_IP} {TARGET_IP}"
        )

        print(f"[Windows Controller] 發送遠端指令: {command}")
        print("-" * 60)

        # 3. 執行指令
        stdin, stdout, stderr = ssh.exec_command(command)

        # --- [關鍵] 即時串流讀取輸出 (Streaming Output) ---
        # 這段迴圈會一行一行讀取 Kali 傳回來的資料，直到腳本結束
        # 這樣可以完美配合您在 Kali 端寫的 console.read() polling loop

        output_buffer = []

        for line in iter(stdout.readline, ""):
            # line 本身已包含換行符號
            print(line, end="")
            sys.stdout.flush()  # 確保 Windows console 立即顯示
            output_buffer.append(line)

        # 讀取錯誤輸出 (如果有)
        # 有時候 Metasploit 的非致命警告也會出現在 stderr
        err_output = stderr.read().decode()
        if err_output:
            print(f"\n[Remote STDERR]:\n{err_output}")

        # 獲取離開代碼 (0 代表成功)
        exit_status = stdout.channel.recv_exit_status()

        print("-" * 60)
        if exit_status == 0:
            print(f"[Windows Controller] Step 02 執行完成 (Exit Code: 0)")
            return True, "".join(output_buffer)
        else:
            print(f"[Windows Controller] Step 02 執行失敗 (Exit Code: {exit_status})")
            return False, "".join(output_buffer) + f"\nError: {err_output}"

    except paramiko.AuthenticationException:
        print("[Windows Controller] SSH 認證失敗，請檢查帳號密碼。")
        return False, "SSH Authentication Failed"
    except paramiko.SSHException as e:
        print(f"[Windows Controller] SSH 連線錯誤: {e}")
        return False, f"SSH Error: {e}"
    except Exception as e:
        print(f"[Windows Controller] 發生未預期的錯誤: {e}")
        return False, f"Unexpected Error: {e}"
    finally:
        ssh.close()


# --- 主程式執行區 (測試用) ---
if __name__ == "__main__":
    TARGET_IP = "192.168.34.101"
    LOG_FOLDER = "creme_logs"

    # 執行
    success, logs = run_step_03_remote()

    if success:
        print(">> [Result] 任務成功！")
    else:
        print(">> [Result] 任務失敗。")