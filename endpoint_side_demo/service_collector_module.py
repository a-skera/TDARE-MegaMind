#This module is used as ServiceCollector for TDARE clientSide
import psutil
import json
import socket

class ServiceCollector:
    """
    Collects information about Windows services.
    """

    def __init__(self):
        pass
        self.hostname = socket.gethostname()
        self.ip_address = socket.gethostbyname(self.hostname)

    def collect_services(self):

        services = []

        for service_id, service in enumerate(psutil.win_service_iter(), start=1):
            try:
                service_info = self.get_service_info(service)
                service_info["id"] = service_id
                services.append(service_info)
                

            except Exception as e:
                print(f"Failed to collect '{service.name()}': {e}")

        return services

    def get_service_info(self, service):
       
        try:
            info = service.as_dict()

            return {
                "hostname": self.hostname,
                "ip_addr": self.ip_address,
                "service_name": info.get("name"),
                "display_name": info.get("display_name"),
                "status": info.get("status"),
                "start_type": info.get("start_type"),
                "binary_path": info.get("binpath"),
                "pid": info.get("pid"),
                "description": info.get("description"),
            }

        except Exception as e:
            print(f"Failed to read service: {e}")
            return None
        

# Notice in printing or returning the data to display dont forget to use the json to be the output format