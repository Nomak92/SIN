import csv
import logging
import pprint

logger = logging.getLogger()


class CsvHandler:
    def __init__(self, filename):
        logger.debug(f"Initializing CSV Handler with filename {filename}")
        self.filename = filename
        self.data = []

    def read(self):
        logger.debug(f"Reading CSV file {self.filename}")
        with open(self.filename, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.data.append(row)
        logger.debug(f"Read {len(self.data)} rows from CSV file")
        logger.debug(f"device_data = {pprint.pformat(self.data)}")
        return self.data
