from ids_system import IntrusionDetectionSystem, get_default_interface

if __name__ == "__main__":
    interface = get_default_interface()

    if interface is None:
        print("[!] Could not find a network interface.")
        print("[*] Please connect to a network and try again.")
    else:
        ids = IntrusionDetectionSystem(interface=interface)
        ids.start()
