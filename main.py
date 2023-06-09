import argparse
import os
from pprint import pformat as pf
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Process, Queue
from lib.clients.factory import create_device_client
from lib.clients.netbox import NetboxClient
from lib.utils.csv import CsvHandler
from lib.utils.secrets import get_credentials
from lib.utils.logs import create_logger_process, create_logger
from dotenv import load_dotenv

parser = argparse.ArgumentParser(description='Discover devices from a csv file')
parser.add_argument('--csv', dest="csv_file", help='The csv file to discover', required=True)
args = parser.parse_args()
logger = create_logger()
logger.debug(f'args = {args}')


def main():
    logger.info(f'Starting discovery program')
    logger.info(f'Loading devices from CSV file')
    devices = CsvHandler(args.csv_file).read()
    with ProcessPoolExecutor(max_workers=10) as executor:
        futures = []
        for device_data in devices:
            futures.append(executor.submit(discover_process, device_data, os.environ["NETBOX_URL"],
                                           os.environ["NETBOX_TOKEN"]))
        results = [future.result() for future in as_completed(futures)]
        print(results)
    return 0


def discover_process(device_data: dict, netbox_url: str, netbox_token: str) -> dict[str, bool]:
    results = {
        "device": device_data["name"],
        "discovery": False,
        "validate": False,
        "update": False,
        "exceptions": []
    }
    logger.info(f'Starting discovery of device {device_data["name"]}')
    logger.info(f'Creating Netbox Client')
    try:
        netbox_client = NetboxClient(netbox_url, netbox_token)
    except Exception as e:
        logger.error(f'Failed to create Netbox Client: {e}')
        results["exceptions"].append(e)
        return results
    logger.info(f'Creating Platform Client for device {device_data["name"]}')
    try:
        device_client = create_device_client(device_data, password_handler=get_credentials)
    except Exception as e:
        logger.exception(f'Failed to create Platform Client: {e}')
        results["exceptions"].append(e)
        return results
    logger.info(f'Discovering Platform {device_data["platform"]} of device {device_data["name"]}')
    try:
        discoverer = device_client.discover()
    except Exception as e:
        logger.exception(f'Failed to discover device: {e}')
        results["exceptions"].append(e)
        raise e
    if discoverer:
        results["discovery"] = True
        logger.info(f'Discovered Platform {device_data["platform"]} of device {device_data["name"]} successfully')
        logger.info(f'Validating device {device_data["name"]}')
        try:
            if device_client.is_valid():
                results["validate"] = True
                logger.info(f'Device {device_data["name"]} data is valid')
            else:
                logger.error(f'Device {device_data["name"]} data failed validation check. Not updating in Netbox')
                return results
        except Exception as e:
            logger.exception(f'Failed to validate device: {e}')
            results["exceptions"].append(e)
            return results
        logger.info(f'Creating Netbox objects from discovered validated data on device {device_data["name"]}')
        try:
            push = device_client.push(netbox_client)
            if push:
                results["update"] = True
                logger.info(f'Updated device {device_data["name"]} in Netbox successfully')
                logger.debug(f'Objects created: {pf(push)}')
            else:
                raise ValueError(f'No objects created in Netbox for device {device_data["name"]}')
        except Exception as e:
            logger.exception(f'Failed to update device in Netbox: {e}')
            results["exceptions"].append(e)
            return results
    else:
        logger.error(f'Failed to discover Platform {device_data["platform"]} of device {device_data["name"]}')
    return results


if __name__ == '__main__':
    logger_queue = Queue(-1)
    logger_process = Process(target=create_logger_process, args=(logger_queue, logger,))
    logger_process.start()
    load_dotenv()
    main()
    logger_queue.put(None)
    logger_process.join(timeout=5)
