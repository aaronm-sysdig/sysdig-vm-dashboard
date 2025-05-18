import logging
import requests
import os
from urllib.parse import unquote
import sys
import gzip

logging.basicConfig(level=getattr(logging, 'INFO'), format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

if os.getenv('REPORT_SCHEDULE_ID') is not None:
    REPORT_SCHEDULE_ID = os.getenv('REPORT_SCHEDULE_ID')
else:
    logging.error(f"ENV Var REPORT_SCHEDULE_ID not set")
    exit(1)

if os.getenv('SYSDIG_SECURE_API_TOKEN') is not None:
    SYSDIG_SECURE_API_TOKEN = os.getenv('SYSDIG_SECURE_API_TOKEN')
else:
    logging.error(f"ENV Var SYSDIG_SECURE_API_TOKEN not set")
    exit(1)

if os.getenv('SYSDIG_REGION_URL') is not None:
    SYSDIG_REGION_URL = os.getenv('SYSDIG_REGION_URL')
else:
    logging.error(f"ENV Var SYSDIG_REGION_URL not set")
    exit(1)

# Directory where the files should be downlaoded to 
if os.getenv('REPORT_DOWNLOADS') is not None:
    REPORT_DOWNLOADS = os.getenv('REPORT_DOWNLOADS')
else:
    logging.error(f"ENV Var REPORT_DOWNLOADS not set")
    exit(1)

headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {SYSDIG_SECURE_API_TOKEN}'
    }


# def create_report_directories():
#    if not os.path.exists(REPORT_DOWNLOADS):
#        os.makedirs(REPORT_DOWNLOADS)

#    if not os.path.exists(REPORT_ARCHIVE_DIR):
#        os.makedirs(REPORT_ARCHIVE_DIR)


def is_valid_gz_file(filepath):
    try:
        with gzip.open(filepath, 'rb') as f:
            while f.read(1024*1024):
                pass
        logging.info(f"Valid gzip file: {filepath}")
        return True
    except gzip.BadGzipFile as e:
        logging.info(f"Invalid gzip file: {filepath}, reason: {e}")
        return False


def download_file_from_content_disposition(url, filepath=None, retries=3):
    """Downloads a file from a URL, using the filename from Content-Disposition.

    Args:
        url: The URL of the file to download.
        filepath: Optional. The path where the file should be saved.  If None,
                  the current directory is used, and the filename is taken from
                  Content-Disposition.
        retries: Number of times to retry the download if the file is not valid.

    Returns:
        The full path to the downloaded file, or None if an error occurred.
    """
    attempt = 0
    while attempt < retries:
        try:
            response = requests.get(url, stream=True, headers=headers)  # stream=True is crucial for large files
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

            content_disposition = response.headers.get('Content-Disposition')

            if content_disposition:
                # Extract filename from Content-Disposition
                parts = content_disposition.split(';')
                filename = None
                for part in parts:
                    if 'filename=' in part.lower():
                        filename = part.split('=', 1)[1]
                        # Handle different filename encodings (important!)
                        if filename.startswith('"') and filename.endswith('"'):
                            filename = filename[1:-1]  # Remove quotes
                        filename = unquote(filename)  # Decode URL-encoded filenames
                        break  # Stop searching once filename is found

                if filename:
                    if filepath:
                        filepath = os.path.join(filepath, filename) if os.path.isdir(filepath) else filepath
                    else:
                        filepath = filename

                    total_bytes = 0
                    with open(filepath, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                                total_bytes += len(chunk)
                    logging.info(f"Downloaded report: {filepath} ({total_bytes:,} bytes)")

                    if is_valid_gz_file(filepath):
                        logging.info(f"Downloaded file {filepath} is a valid gz file.")
                        return filepath
                    else:
                        logging.warning(f"Downloaded file {filepath} is not a valid gz file. Retrying Download...")
                        attempt += 1
                        continue
                else:
                    logging.error("Filename not found in Content-Disposition header.")
                    return None  # Indicate failure

            else:
                logging.error("Content-Disposition header not found.")
                return None  # Indicate failure

        except requests.exceptions.RequestException as e:
            logging.error(f"Error during download: {e}")
            return None
        except OSError as e:
            logging.error(f"Error saving file: {e}")
            return None

    logging.error(f"Failed to download a valid gz file after {retries} attempts.")
    return None


def download_report(report_index):
    url = SYSDIG_REGION_URL + '/api/scanning/reporting/v2/schedules/' + REPORT_SCHEDULE_ID + '/reports'
    logging.debug(f"Getting list of Reports from: {url}")
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        reports_available = response.json()  # List of reports available to download
    else:
        logging.error(f"Failed to get list of reports: {response.status_code}")
        return False

    # If this is run with the argument all, then download all daily reports available for last 14 days and load them to the DB
    if report_index == "all":
        logging.info(f"Downloading all reports for schedule...")
        for report in reports_available:
            logging.info(f"Downloading Report: {report['id']} from {report['completedAt']}")
            url = SYSDIG_REGION_URL + '/api/scanning/reporting/v2/schedules/' + REPORT_SCHEDULE_ID + '/reports/' + report['id'] + '/download'
            if not download_file_from_content_disposition(url, REPORT_DOWNLOADS):
                return False
    else:
        report_to_download = int(report_index)  # Expect this to be an int 0-13 where 0 means download today, 1 means 1 day ago etc...
        logging.info(f"Downloading report from {report_to_download} days ago to {REPORT_DOWNLOADS}...")
        url = SYSDIG_REGION_URL + '/api/scanning/reporting/v2/schedules/' + REPORT_SCHEDULE_ID + '/reports/' + reports_available[report_to_download]['id'] + '/download'
        logging.debug(f"Downloading report: '{url}")
        if not download_file_from_content_disposition(url, REPORT_DOWNLOADS):
            return False

    return True


if __name__ == "__main__":  # This block only runs when executed directly
    if sys.argv[1] != "all":
        download_report(sys.argv[1])   # Will download the report from the specified day. 0 for today, 1 for yesterday etc...
    else:
        download_report("all")  # Will downlaod all available(14) days of reports.
