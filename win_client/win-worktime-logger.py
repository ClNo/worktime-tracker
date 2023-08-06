import win32api
from time import sleep
from datetime import datetime, timedelta
import ctypes
import json

savedpos = win32api.GetCursorPos()
mouse_work_active = False
last_mouse_move = datetime.now()
locked_active = False

user32 = ctypes.windll.User32

with open('worktime-config.json', 'r') as f:
    config = json.load(f)
    mouse_timeout = timedelta(minutes = config['mouse_timeout_min'])

print(f'--- Work log started at {datetime.now()} --- config:')
print(config)

def is_locked():
    return user32.GetForegroundWindow() == 0

while(True):

    try:
        curpos = win32api.GetCursorPos()
        if savedpos != curpos:
            savedpos = curpos
            last_mouse_move = datetime.now()
            if not mouse_work_active:
                print(f"mouse movement active {datetime.now()}")
                mouse_work_active = True
        if ((datetime.now() - last_mouse_move) > mouse_timeout) and mouse_work_active:
                print(f"mouse movement NOT active {datetime.now()}")
                mouse_work_active = False
            
    except Exception as e:
        # assume the screen lock is on
        if not locked_active:
            locked_active = True
            mouse_work_active = False
            print(f'Locked {datetime.now()} (mouse pos is not accessible)')
    
    if not locked_active and is_locked():
        locked_active = True
        print(f'Locked {datetime.now()}')
    if locked_active and not is_locked():
        locked_active = False
        print(f'Unlocked at {datetime.now()}')
    
    sleep(1)
