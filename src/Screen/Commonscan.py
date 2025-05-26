import flet as ft, queue, threading
from queue import Queue
from Screen.HeuristicScan import analyze_file
from Screen.ListFiles import listfiles
def worker(file_queue, malware_count, compiled_rule, txt, info, progress_ring, count, page, lock, processed_count, flag, exclusionfiles):
    batch_size = 100 if compiled_rule is None else 10 if count < 100 else 100 if count < 500 else 200 if count < 1000 else 800 if not flag else 700
    while not file_queue.empty():
        try:
            file_path = file_queue.get_nowait()
            with lock:
                processed_count[0] += 1
                index = processed_count[0]
            if file_path in exclusionfiles:
                file_queue.task_done()
                continue
            is_suspicious = compiled_rule.match(file_path) if compiled_rule else False
            if flag and not is_suspicious:
                try:
                    is_suspicious = analyze_file(file_path)
                except Exception:
                    pass
            if is_suspicious:
                malware_count.add(file_path)
            if index % batch_size == 0 or index == count:
                progress = max(progress_ring.value,index/count)
                progress_ring.value = progress
                txt.value = f"Scanning: {file_path}"
                info.value = f"{round(progress * 100, 2)}% scanned"
                page.update()
            file_queue.task_done()
        except queue.Empty:
            break
        except Exception:
            file_queue.task_done()
def scan_drives(page:ft.Page,txt,info,count,files,progress_ring,malware_count,compiled_rule,bs,flag,exclusionfiles,VAULT_DIR):
    file_queue = Queue()
    for file in files:
        file_queue.put(file)
    num_threads=50 if compiled_rule is None else 50 if count < 100 else 100 if count < 500 else 1500 if not flag else 1000
    threads=[]
    processed_count = [0]
    lock = threading.Lock()
    for _ in range(num_threads):
        thread = threading.Thread(
            target=worker,
            args=(file_queue,malware_count,compiled_rule,txt,info,progress_ring,count,page,lock,processed_count,flag,exclusionfiles)
        )
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    progress_ring.value=100
    page.update()
    listfiles(page,idp="Result",path=malware_count,exclusion=exclusionfiles,VAULT_DIR=VAULT_DIR)