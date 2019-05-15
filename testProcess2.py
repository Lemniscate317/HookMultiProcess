# -*- coding: utf-8 -*-
import codecs
import frida
import sys
import threading


#device = frida.get_remote_device()
device = frida.get_device_manager().enumerate_devices()[-1]
print(device)


pending = []
sessions = []
scripts = []
event = threading.Event()

jscode = """
Java.perform(function () {
    var MainActivity = Java.use('com.l.testprocess.MainActivity1');
    var clazz = Java.use('java.lang.Class');
	MainActivity.onCreate.implementation = function(savedInstanceState){
		send('MainActivity')
		this.onCreate(savedInstanceState);
	}
	
});
"""

def on_spawned(spawn):
	print('on_spawned:', spawn)
	pending.append(spawn)
	event.set()

def spawn_added(spawn):
	print('spawn_added:', spawn)
	event.set()
	if(spawn.identifier.startswith('com.l.testprocess')):
		session = device.attach(spawn.pid)
		script = session.create_script(jscode)
		script.on('message', on_message)
		script.load()
		device.resume(spawn.pid)
		
def spawn_removed(spawn):
	print('spawn_added:', spawn)
	event.set()

def on_message(spawn, message, data):
	print('on_message:', spawn, message, data)
	
def on_message(message, data):
	if message['type'] == 'send':
		print("[*] {0}".format(message['payload']))
	else:
		print(message)

device.on('spawn-added', spawn_added)
device.on('spawn-removed', spawn_removed)
device.on('child-added', on_spawned)
device.on('child-removed', on_spawned)
device.on('process-crashed', on_spawned)
device.on('output', on_spawned)
device.on('uninjected', on_spawned)
device.on('lost', on_spawned)
device.enable_spawn_gating()
event = threading.Event()
print('Enabled spawn gating')

pid = device.spawn(["com.l.testprocess"])




session = device.attach(pid)
print("[*] Attach Application id:",pid)
device.resume(pid)
# print("[*] Application onResume")
# script = session.create_script(jscode)
# script.on('message', on_message)
# print('[*] Running CTF')
# script.load()
sys.stdin.read()