import os
from datetime import datetime, timedelta
import xxhash
import clickhouse_connect
import pandas as pd
import download_sysdig_reports
import psutil
import logging
from urllib.parse import urlparse

if os.getenv('LOG_LEVEL') is not None:
    LOG_LEVEL = os.getenv('LOG_LEVEL')
else:
    logging.error(f"ENV Var LOG_LEVEL not set")
    exit(1)

logging.basicConfig(level=getattr(logging, LOG_LEVEL), format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S', force=True,)


def extract_port(value: str, default: str = '8123') -> str:
    try:
        # If it's a raw port (e.g., "8123"), return it directly
        if value.isdigit():
            return value
        # Otherwise, try to parse it as a URL
        parsed = urlparse(value)
        if parsed.port:
            return str(parsed.port)
    except Exception:
        pass
    return default


# Directory where the GZ CSV files are to be imported from
if os.getenv('REPORT_DOWNLOADS') is not None:
    REPORT_DOWNLOADS = os.getenv('REPORT_DOWNLOADS')
else:
    logging.error(f"ENV Var REPORT_DOWNLOADS not set")
    exit(1)

# Directory where the GZ CSV files are to be archived after processing
if os.getenv('REPORT_ARCHIVE_DIR') is not None:
    REPORT_ARCHIVE_DIR = os.getenv('REPORT_ARCHIVE_DIR')
else:
    logging.error(f"ENV Var REPORT_ARCHIVE_DIR not set")
    exit(1)

if os.getenv('VULN_NOT_SEEN_CLOSE') is not None:
    VULN_NOT_SEEN_CLOSE = os.getenv('VULN_NOT_SEEN_CLOSE')
else:
    logging.error(f"ENV Var VULN_NOT_SEEN_CLOSE not set")
    exit(1)

if os.getenv('ALL_VULNS_TABLE_NAME') is not None:
    ALL_VULNS_TABLE_NAME = os.getenv('ALL_VULNS_TABLE_NAME')
else:
    logging.error(f"ENV Var ALL_VULNS_TABLE_NAME not set")
    exit(1)

if os.getenv('VULN_SEVERITY_TO_KEEP') is not None:
    VULN_SEVERITY_TO_KEEP = os.getenv('VULN_SEVERITY_TO_KEEP', 'High,Critical').split(',')
else:
    logging.error(f"ENV Var VULN_SEVERITY_TO_KEEP not set")
    exit(1)

if os.getenv('CLICKHOUSE_HOSTNAME') is not None:
    CLICKHOUSE_HOSTNAME = os.getenv('CLICKHOUSE_HOSTNAME')
else:
    logging.error(f"ENV Var CLICKHOUSE_HOSTNAME not set")
    exit(1)

if os.getenv('CLICKHOUSE_USER') is not None:
    CLICKHOUSE_USER = os.getenv('CLICKHOUSE_USER')
else:
    logging.error(f"ENV Var CLICKHOUSE_USER not set")
    exit(1)

if os.getenv('CLICKHOUSE_PASSWORD') is not None:
    CLICKHOUSE_PASSWORD = os.getenv('CLICKHOUSE_PASSWORD')
else:
    logging.error(f"ENV Var CLICKHOUSE_PASSWORD not set")
    exit(1)

# Get Clickhouse port or run with default
CLICKHOUSE_PORT = extract_port(os.getenv('CLICKHOUSE_PORT', "8123"))

# Chunk batch size - how many rows to read from the CSV file at a time
# The larger the number the more memory is used but the faster the import
# 500,000 seems to use nearly 2GB of memory
if os.getenv('IMPORT_BATCH_SIZE') is not None:
    IMPORT_BATCH_SIZE = int(os.getenv('IMPORT_BATCH_SIZE'))
else:
    logging.error(f"ENV Var IMPORT_BATCH_SIZE not set")
    exit(1)

# Columns to keep from the CSV file downloaded
columns_to_keep = ['K8S cluster name', 
                   'K8S namespace name', 
                   'K8S workload name', 
                   'K8S workload type',
                   'K8S container name',
                   'Package name',
                   'Package path', 
                   'Package type',
                   'Vulnerability ID',
                   'Severity',
                   'In use',
                   'Risk accepted',
                   'Public Exploit']

# Columns to hash to create a unique package to trach vulnerabilities against
# Cluster | Namespace | Workload Name | Container Name | Package Name | Package Path
columns_to_hash = ['k8s_cluster_name', 
                   'k8s_namespace_name', 
                   'k8s_workload_name', 
                   'k8s_container_name',
                   'package_name',
                   'package_path']

# Columns to hash to create a unique workload to track
# Cluster | Namespace | Workload Name 
# workload_columns_to_hash = ['k8s_cluster_name',
#                   'k8s_namespace_name', 
#                   'k8s_workload_name']

# To rename columns to be database friendly
new_column_names = {col: col.lower().replace(' ', '_') for col in columns_to_keep}


def create_temp_import_table(table_name):
    # Create table if it doesn't exist
    logging.info(f"Creating table {table_name} if it doesn't exist...")
    create_table = f"""
        CREATE TABLE IF NOT EXISTS \"{table_name}\" (
            "k8s_cluster_name" text,
            "k8s_namespace_name" text,
            "k8s_workload_name" text,
            "k8s_workload_type" text,
            "k8s_container_name" text,
            "package_name" text,
            "package_path" text,
            "package_type" text,
            "in_use" bool,
            "risk_accepted" bool,
            "public_exploit" bool,
            "vulnerability_id" text,
            "severity" text,
            "unique_hash" UInt64
        )ENGINE = MergeTree()
        ORDER BY (unique_hash, vulnerability_id, k8s_workload_type, k8s_cluster_name, k8s_namespace_name, k8s_workload_name); 
    """
    client.command(create_table)


def create_vuln_table():
    # Create table if it doesn't exist
    logging.info(f"Creating table {ALL_VULNS_TABLE_NAME} if it doesn't exist...")
    create_table = f"""
        CREATE TABLE IF NOT EXISTS \"{ALL_VULNS_TABLE_NAME}\" (
            "k8s_cluster_name" text,
            "k8s_namespace_name" text,
            "k8s_workload_name" text,
            "k8s_workload_type" text,
            "k8s_container_name" text,
            "package_name" text,
            "package_path" text,
            "package_type" text,
            "in_use" bool,
            "risk_accepted" bool,
            "public_exploit" bool,
            "vulnerability_id" text,
            "severity" text,
            "unique_hash" UInt64,
            "vuln_first_seen" Date,
            "vuln_last_seen" Date,
            "vuln_status" String DEFAULT 'open',
            "age_days" UInt16 DEFAULT 0
        )ENGINE = MergeTree()
        ORDER BY (unique_hash, vulnerability_id, k8s_workload_type, k8s_cluster_name, k8s_namespace_name, k8s_workload_name); 
    """
    client.command(create_table)


def create_summary_table():
    logging.info(f"Creating summary table {ALL_VULNS_TABLE_NAME}_summary if it doesn't exist...")
    create_table = f"""
        CREATE TABLE IF NOT EXISTS {ALL_VULNS_TABLE_NAME}_summary (
            "k8s_cluster_name" text,
            "k8s_namespace_name" text,
            "k8s_workload_name" text,
            "k8s_workload_type" text,
            "severity" text,
            "vuln_count" UInt64,
            "in_use" bool,
            "risk_accepted" bool,
            "public_exploit" bool,
            "report_date" Date
        )ENGINE = MergeTree()
        ORDER BY (k8s_cluster_name, k8s_namespace_name, k8s_workload_name, k8s_workload_type, severity, report_date); 
    """
    client.command(create_table)


def create_files_processed_table():
    logging.info(f"Creating files processed table {ALL_VULNS_TABLE_NAME}_processed_files if it doesn't exist...")
    create_table = f"""
        CREATE TABLE IF NOT EXISTS {ALL_VULNS_TABLE_NAME}_processed_files (
            "report_date" Date,
            "filename" text,
            "date_processed" DateTime
        )ENGINE = MergeTree()
        ORDER BY (report_date, filename, date_processed ); 
    """
    client.command(create_table)


def log_memory_usage(message):
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    # logging.debug(f"RSS={mem_info.rss / (1024 * 1024):.2f} MB, VMS={mem_info.vms / (1024 * 1024):.2f} MB | [{message}] ")
    logging.debug(f"RSS={mem_info.rss / (1024 * 1024):.2f} MB | [{message}] ")


def get_date_from_filename(filename):
    date_str = filename.split('_')[-1].replace('.csv.gz', '')
    return datetime.strptime(date_str, '%Y-%m-%d')


def create_new_table_with_duplicate_records_removed(table_name):
    # Insert into new temp table deuplicated records (remove duplicates from file that were caused by updating image for workloads)
    temp_dedup_table_name = table_name + "_deduplicated"
    create_temp_import_table(temp_dedup_table_name)
    # This query has to exclude in_use, risk_accpeted and public_exploit as there maybe multiple records in the csv file with different values for these columns on the one day
    insert_query = f"""
        INSERT INTO {temp_dedup_table_name} (
            k8s_cluster_name, k8s_namespace_name, k8s_workload_name, k8s_workload_type, 
            k8s_container_name, package_name, package_path, package_type, 
            vulnerability_id, severity, unique_hash, in_use, public_exploit, risk_accepted
        )
        SELECT DISTINCT ON (
            k8s_cluster_name, k8s_namespace_name, k8s_workload_name, k8s_workload_type, 
            k8s_container_name, package_name, package_path, package_type, 
            vulnerability_id, severity, unique_hash
        ) 
            k8s_cluster_name, k8s_namespace_name, k8s_workload_name, k8s_workload_type, 
            k8s_container_name, package_name, package_path, package_type, 
            vulnerability_id, severity, unique_hash, in_use, public_exploit, risk_accepted
        FROM {table_name}
        """
    client.command(insert_query)
    logging.info(f"Inserted deduplicated records into {temp_dedup_table_name}")

    count_query = f"SELECT COUNT(*) FROM {temp_dedup_table_name}"
    count_result = client.command(count_query)
    logging.info(f"Number of records inserted into {temp_dedup_table_name}: {count_result}")

    return temp_dedup_table_name


def update_column_from_new_data(table_name, column_name, new_data_table_name, severity, value):
    # This function is used to update the vulns table with the latest values for in_use, risk_accepted and public_exploit as they may have changed in the latest report
    
    update_query = f"""
        ALTER TABLE {table_name}
        UPDATE {column_name} = '{value}'
        WHERE (unique_hash, vulnerability_id) IN (
            SELECT unique_hash, vulnerability_id
            FROM {new_data_table_name}
            WHERE severity = '{severity}'
            AND {column_name} = '{value}'
        )
    """
    # logging.debug(f"Update Column Query: {update_query}")
    client.command(update_query, settings={'mutations_sync': 2})  # mutations_sync=2 to wait for the update to complete
    # logging.info(f"Updated {column_name} column for severity {severity} in {table_name}")


def update_existing_vulns_table(vulns_table_name, dedup_table_name, report_date):
    # Get distinct severity levels from the dedup_table_name
    # This is to break up the update into smaller chunks (by severity) to reduce the memory demand on the DB
    severity_query = f"SELECT DISTINCT severity FROM {dedup_table_name}"
    severities_result = client.query(severity_query)
    severities = [row[0] for row in severities_result.result_rows]

    for severity in severities:
        # Update vuln_last_seen to report_date for records with the current severity

        update_report_date_query = f"""
            ALTER TABLE {vulns_table_name}
            UPDATE vuln_last_seen = '{report_date}'
            WHERE (unique_hash, vulnerability_id) IN (
                SELECT unique_hash, vulnerability_id
                FROM {dedup_table_name}
                WHERE severity = '{severity}'
            )
        """
        client.command(update_report_date_query, settings={'mutations_sync': 2})  # mutations_sync=2 to wait for the update to complete

        update_column_from_new_data(vulns_table_name, 'risk_accepted', dedup_table_name, severity, '1')
        update_column_from_new_data(vulns_table_name, 'risk_accepted', dedup_table_name, severity, '0')

        update_column_from_new_data(vulns_table_name, 'in_use', dedup_table_name, severity, '1')
        update_column_from_new_data(vulns_table_name, 'in_use', dedup_table_name, severity, '0')

        update_column_from_new_data(vulns_table_name, 'public_exploit', dedup_table_name, severity, '0')
        update_column_from_new_data(vulns_table_name, 'public_exploit', dedup_table_name, severity, '1')

        update_column_from_new_data(vulns_table_name, 'severity', dedup_table_name, severity, severity)  # Update severity to the current severity if it's been updated in latest report

        logging.info(f"Updated vuln_last_seen, risk_accept, in_use, public_exploit columns for severity {severity} in {vulns_table_name}")


def insert_new_vulns_into_vuln_table(vulns_table_name, dedup_table_name, report_date):
    # Insert new records into vuln table if the unique_hash and vulnerability_id don't exist already in the target table
    # We can use the vuln_last_seen when selecting from vulns_table_name as there is no point checking old records because the previous step would have set it to the report_date
    insert_query = f"""
        INSERT INTO {vulns_table_name}
            SELECT *, '{report_date}' AS vuln_first_seen, '{report_date}' AS vuln_last_seen, 'open' AS vuln_status, 0 AS age_days
            FROM {dedup_table_name} AS tb
            WHERE (tb.unique_hash, tb.vulnerability_id) NOT IN (
                SELECT unique_hash, vulnerability_id
                FROM {vulns_table_name}
                WHERE vuln_last_seen = '{report_date}'
            )
        """
    logging.info(f"Starting Insert of new records from {dedup_table_name} to {vulns_table_name}")
    client.command(insert_query)
    logging.info(f"Inserted new records into {vulns_table_name}")
    

def drop_table(table_name):
    drop_query = f"DROP TABLE {table_name}"
    client.command(drop_query)
    logging.info(f"Dropped temp table {table_name}")


def insert_summary_table(report_date, dedup_table_name):
    logging.info(f"Inserting into summary table for {report_date}...")
    insert_query = f"""
        INSERT INTO {ALL_VULNS_TABLE_NAME}_summary (k8s_cluster_name, k8s_namespace_name, k8s_workload_name, k8s_workload_type, severity, in_use, risk_accepted, public_exploit, vuln_count, report_date)
        SELECT k8s_cluster_name, k8s_namespace_name, k8s_workload_name, k8s_workload_type, severity, in_use, risk_accepted, public_exploit, count(*), '{report_date}'
        FROM {dedup_table_name}
        GROUP BY k8s_cluster_name, k8s_namespace_name, k8s_workload_name, k8s_workload_type, severity, in_use, risk_accepted, public_exploit
    """
    client.command(insert_query)


def insert_processes_files(file, report_date):
    insert_query = f"""
        INSERT INTO {ALL_VULNS_TABLE_NAME}_processed_files (report_date, filename, date_processed)
        VALUES ('{report_date}', '{file}', '{datetime.now()}')
    """
    client.command(insert_query)
    logging.info(f"Inserted details about {file} into {ALL_VULNS_TABLE_NAME}_processed_files")


def update_vuln_days():
    logging.info(f"Updating vuln_status days")

    update_query = f"""
        ALTER TABLE {ALL_VULNS_TABLE_NAME} 
        UPDATE age_days = (vuln_last_seen - vuln_first_seen)
        WHERE true
        """
    client.command(update_query)
    logging.info(f"Updated days_open in {ALL_VULNS_TABLE_NAME}")


def update_vuln_status_closed(report_date):

    date_to_close = report_date - timedelta(days=int(VULN_NOT_SEEN_CLOSE))  # Get the day before the report date

    # Before UPDATE count
    count_query = f"SELECT COUNT(*) FROM {ALL_VULNS_TABLE_NAME} WHERE vuln_last_seen < '{date_to_close}' AND vuln_status = 'open'"
    before_count = client.query(count_query).result_rows[0][0]
    
    update_query_closed = f"""
        ALTER TABLE {ALL_VULNS_TABLE_NAME}
        UPDATE vuln_status = 'closed'
        WHERE vuln_last_seen < '{date_to_close}' AND vuln_status = 'open'
        """
    client.command(update_query_closed, settings={'mutations_sync': 2})  # mutations_sync=2 to wait for the update to complete

    # After UPDATE count
    after_count = client.query(count_query).result_rows[0][0]
    # Calculate the number of rows updated
    rows_updated = before_count - after_count

    logging.info(f"Updated vuln_status to 'closed' for {rows_updated} vulnerabilities with vuln_last_seen older than {date_to_close} and currently open")


def update_vuln_status_open(report_date):
    # Assume that the vuln_status should be 'open' if the vuln_last_seen is the most recent date

    # Before UPDATE count
    query = f"SELECT COUNT(*) FROM {ALL_VULNS_TABLE_NAME} WHERE vuln_last_seen = '{report_date}' AND vuln_status != 'open'"
    before_count = client.query(query).result_rows[0][0]

    update_query_open = f"""
        ALTER TABLE {ALL_VULNS_TABLE_NAME}
        UPDATE vuln_status = 'open'
        WHERE vuln_last_seen='{report_date}' AND vuln_status != 'open'
    """
    client.command(update_query_open, settings={'mutations_sync': 2})  # mutations_sync=2 to wait for the update to complete

    # After UPDATE count
    after_count = client.query(query).result_rows[0][0]
    # Calculate the number of rows updated
    rows_updated = before_count - after_count

    logging.info(f"Updated vuln_status to 'open' for {rows_updated} vulnerabilities with vuln_last_seen equal to {report_date} and currently not open")


def process_files():
    # Get all files in the directory
    files = [f for f in os.listdir(REPORT_DOWNLOADS) if f.endswith('.gz') and not f.startswith('._')]
    # Sort files by date in filename
    files.sort(key=get_date_from_filename)

    # Process each file in date order
    for file in files:
        file_path = os.path.join(REPORT_DOWNLOADS, file)
        logging.info(f"Processing file: {file_path}")

        report_date = get_date_from_filename(file_path).date()
        # generate the import table name from the date in the filename
        import_table_name = ALL_VULNS_TABLE_NAME + "_" + report_date.strftime('%Y_%m_%d')

        create_temp_import_table(import_table_name)

        # Process the file in chunks and insert it into the temp import table
        dtype = 'str'
        for chunk in pd.read_csv(file_path, chunksize=IMPORT_BATCH_SIZE, dtype=dtype):
            log_memory_usage("Before Process Chunk")
            process_chunk(chunk, file_path, import_table_name)
            log_memory_usage("After Process Chunk")

        count_query = f"SELECT COUNT(*) FROM {import_table_name}"
        count_result = client.command(count_query)
        logging.info(f"Number of records inserted into {import_table_name}: {count_result}")

        # Create a new table with duplicate records removed
        dedup_table_name = create_new_table_with_duplicate_records_removed(import_table_name)

        # Update vuln_last_seen for records in ALL_VULNS_TABLE_NAME based on unique_hash and vulnerability_id from dedup_table_name
        log_memory_usage("Before Update Existing Vulns Table")
        update_existing_vulns_table(ALL_VULNS_TABLE_NAME, dedup_table_name, report_date)
        log_memory_usage("After Update Existing Vulns Table")

        # Insert new records into ALL_VULNS_TABLE_NAME from dedup_table_name if they don't already exist based on unique_hash and vulnerability_id
        insert_new_vulns_into_vuln_table(ALL_VULNS_TABLE_NAME, dedup_table_name, report_date)

        # Insert into summary table
        insert_summary_table(report_date, dedup_table_name)

        # Insert details about the files succesfully processed to the processed files table
        insert_processes_files(file, report_date)

        drop_table(import_table_name)
        drop_table(dedup_table_name)

        # Move the processed file to the archive directory
        os.rename(file_path, os.path.join(REPORT_ARCHIVE_DIR, file))
        logging.info(f"Finished proccessing file: {file_path} and moved to {REPORT_ARCHIVE_DIR}")

    # Only need to run these after all files processed
    update_vuln_status_closed(report_date)  # Update vuln_status to be closed if vuln_last_seen is older than the most recent date
    update_vuln_status_open(report_date)  # Update vuln_status to be open if vuln_last_seen is the most recent date
    update_vuln_days()  # Update days_open column


def process_chunk(chunk, file_path, table_name):
    log_memory_usage("Start Process Chunk")
    chunk = chunk[columns_to_keep]
    chunk = chunk.rename(columns=new_column_names)
    log_memory_usage("After Rename Columns")

    # Filter rows where severity is in the specified levels
    chunk = chunk[chunk['severity'].isin(VULN_SEVERITY_TO_KEEP)]
    log_memory_usage("After Filter Severity")
    
    # Replace NaN or None with empty string
    chunk = chunk.fillna("")
    log_memory_usage("After Fillna")
    
    # Convert boolean columns to integers
    bool_columns = ['in_use', 'risk_accepted', 'public_exploit']
    for col in bool_columns:
        chunk[col] = chunk[col].apply(lambda x: 1 if str(x).strip().upper() == 'TRUE' else 0)
    
    log_memory_usage("After Convert Bool Columns")
    
    chunk['unique_hash'] = chunk[columns_to_hash].apply(lambda row: int(xxhash.xxh64_hexdigest(''.join(row.values.astype(str))), 16), axis=1)
    # chunk['workload_hash'] = chunk[workload_columns_to_hash].apply(lambda row: int(xxhash.xxh64_hexdigest(''.join(row.values.astype(str))), 16), axis=1)
    log_memory_usage("After Calculate Hashes")

    client.insert_df(table_name, chunk)
    logging.info(f"Inserted {len(chunk)} new records into {table_name}")
    log_memory_usage("After Inserting new Records")


def create_report_directories():
    if not os.path.exists(REPORT_DOWNLOADS):
        os.makedirs(REPORT_DOWNLOADS)

    if not os.path.exists(REPORT_ARCHIVE_DIR):
        os.makedirs(REPORT_ARCHIVE_DIR)


if __name__ == "__main__":  # This block only runs when executed directly
    # Connect to Database
    logging.info(f"Connecting to Database...")
    client = clickhouse_connect.get_client(host=CLICKHOUSE_HOSTNAME, port=int(CLICKHOUSE_PORT), username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD, connect_timeout=600, send_receive_timeout=600, query_retries=5)

    create_vuln_table()  # Create table if it doesn't exist
    create_summary_table()  # Create summary table if it doesn't exist
    create_files_processed_table()  # Create files processed table if it doesn't exist

    create_report_directories()  # Create directories for reports to be downloaded to if they don't exist

    result = download_sysdig_reports.download_report(0)  # Download latest report
    if not result:
        logging.error("Failed to download the latest report. Exiting...")
        exit(1)

    # Check if there are files to process
    gz_files = [f for f in os.listdir(REPORT_DOWNLOADS) if f.endswith('.gz')]
    if gz_files:
        process_files()  # Process files in REPORT_DOWNLOADS directory
        logging.info(f"Finished processing all files in the {REPORT_DOWNLOADS} directory")
    else:
        logging.info(f"No report gz files to process in the {REPORT_DOWNLOADS} directory")
