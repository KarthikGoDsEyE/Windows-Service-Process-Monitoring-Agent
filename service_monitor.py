import wmi

def get_services():
    c = wmi.WMI()
    services = []

    for service in c.Win32_Service():
        services.append({
            "name": service.Name,
            "path": str(service.PathName),
            "state": service.State
        })

    return services