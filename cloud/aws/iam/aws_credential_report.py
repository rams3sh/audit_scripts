from queue import Queue
from botocore.config import Config
from botocore.exceptions import ClientError as awsClientError
from threading import Thread
import time
import boto3
import logging
import csv
import traceback
import io

# Queues
profile_queue = Queue()
get_report_queue = Queue()
report_output_queue = Queue()

# aws Configuration to escape throttling
config = Config(
   retries = {
                'max_attempts': 10,
                'mode': 'adaptive'
   }
)

# Flags
gen_report_complete = False
get_report_complete = False


# Logging
logger =logging.getLogger(__name__)
FORMAT = "%(asctime)s — %(relativeCreated)6d — %(threadName)s — %(name)s — %(levelname)s — %(funcName)s:%(lineno)d — %(message)s"
logging.basicConfig(filename="credential-report-"+str(time.time())+".log", format=FORMAT)
logger.setLevel(logging.DEBUG)

def generate_credential_report():
    global profile_queue
    global get_report_queue
    global config

    while True:
        if get_report_queue.empty() and profile_queue.empty():
            logger.info(
                "IAM entity report generation is complete and IAM entity get report seems to have no issues and no report re-generation may be required, I am done :) !!")
            break
        else:
            while not profile_queue.empty():
                profile = profile_queue.get()
                session = boto3.Session(profile_name=profile)
                iam_client = session.client('iam', config=config)
                try:
                    # No need to bother for job as its an account level report
                    # Also no need to check the status of report generation as they falled under either
                    # COMPLETE | STARTED | INPROGRESS , and it has to be handled at the level of getting the report
                    # Just generate the report and leave here.
                    iam_client.generate_credential_report()
                    get_report_queue.put({'profile': profile,
                                      'iam_client': iam_client})
                except awsClientError as error:
                    if error.response['Error']['Code'] in [ "RequestTimeout",
                                                            "RequestTimeoutException",
                                                            "PriorRequestNotComplete",
                                                            "ConnectionError",
                                                            "HTTPClientError",
                                                            "Throttling",
                                                            "ThrottlingException",
                                                            "ThrottledException",
                                                            "RequestThrottledException",
                                                            "TooManyRequestsException",
                                                            "ProvisionedThroughputExceededException",
                                                            "TransactionInProgressException",
                                                            "RequestLimitExceeded",
                                                            "BandwidthLimitExceeded",
                                                            "LimitExceededException",
                                                            "RequestThrottled",
                                                            "SlowDown",
                                                            "EC2ThrottledException"]:
                        logger.error("Encountered Error: {} !! Sleeping for 20 seconds".format(error.response['Error']['Code']))
                        logger.info(traceback.format_exc())
                        time.sleep(20)
                    else:
                        logger.error("Encountered Error: {} !! Exiting .. ".format(error.response['Error']['Code']))
                        logger.info(traceback.format_exc())
                        logger.error("Omitted the processing for profile :{}".format(profile))
                profile_queue.task_done()
                logger.info("Generation of credential report for profile {} done!!".format(profile))
            # Sleeping for 10 seconds until the queue gets any job for regeneration of report
            logger.debug(
                "IAM entity report generation queue is empty and IAM entity report get worker(s) is/are running , going to sleep !!")
            time.sleep(10)
    logger.info("No more profiles to process !!")

def get_credential_report():
    global get_report_queue
    global profile_queue
    global report_output_queue
    global gen_report_complete

    while True:

        # Edge case in this checks will be in case of below scenario :-
        # All profiles but one being processed by the gen report method worker(s) . The queue is empty but the last profile(s) are being processed
        # Get Credential report has processed all credential reports and checks for the queue and the profile queue, finds it empty and then exists.
        # After exiting the workers fill the get_report queue with items staying there with no one to process!!
        # It's been handled as error reporting in the last instead of processing them as its a very rare edge case.
        # Assumption is threads of get_credential_report < gen_credential_report and time taken by get_credential_report is always more.
        # Hence this decision.
        if profile_queue.empty() and gen_report_complete:

            logger.info(
                "All IAM reports have been processed , I am done :) !!")
            break
        else:
            while not get_report_queue.empty():
                logger.debug("Starting to work on getting the report !!")
                report_get_details = get_report_queue.get()
                profile = report_get_details.get('profile')
                iam_client = report_get_details.get('iam_client')
                try:
                    response = iam_client.get_credential_report()
                    if 'Content' in response:
                        report_output_queue.put({'raw_report': response.get('Content'),
                                                 'profile' : profile
                                                 })
                    else:
                        # In case the report runs into an error, pushing the profile to generate a report once again
                        profile_queue.put(profile)
                except awsClientError as error:
                    if error.response['Error']['Code'] in [ "RequestTimeout",
                                                            "RequestTimeoutException",
                                                            "PriorRequestNotComplete",
                                                            "ConnectionError",
                                                            "HTTPClientError",
                                                            "Throttling",
                                                            "ThrottlingException",
                                                            "ThrottledException",
                                                            "RequestThrottledException",
                                                            "TooManyRequestsException",
                                                            "ProvisionedThroughputExceededException",
                                                            "TransactionInProgressException",
                                                            "RequestLimitExceeded",
                                                            "BandwidthLimitExceeded",
                                                            "LimitExceededException",
                                                            "RequestThrottled",
                                                            "SlowDown",
                                                            "EC2ThrottledException"]:
                        logger.error("Encountered Error: {} !! Sleeping for 20 seconds".format(error.response['Error']['Code']))
                        logger.info(traceback.format_exc())
                        time.sleep(20)
                    elif error.response['Error']['Code'] == "ReportInProgress":
                        logger.error(
                            "Encountered Error: {} !! The task has been put in queue for later processing".format(error.response['Error']['Code']))
                        # Since the report is in progress , adding this to the get_report queue to process later
                        get_report_queue.put({'profile': profile, 'iam_client': iam_client})
                    else:
                        logger.error("Encountered Error: {} !! Exiting .. ".format(error.response['Error']['Code']))
                        logger.info(traceback.format_exc())
                        logger.error("Omitted the getting the report for profile :{}".format(profile))
                get_report_queue.task_done()
                logger.info("Getting credential report for profile {} done!!".format(profile))
            # Sleeping for 10 seconds until the queue gets any job for regeneration of report
            logger.debug(
                "IAM get report queue is empty and IAM generate report worker(s) is/are running , going to sleep !!")
            time.sleep(10)


def file_writer(file_output=None):
    global report_output_queue
    global gen_report_complete
    global get_report_complete

    out = open(file_output, 'w')
    csv_columns = ['Account',
                   'Account Type',
                   'User',
                   'Arn',
                   'User Creation Time',
                   'Console Login Enabled',
                   'Console Password Last Used',
                   'Console Password Last Changed',
                   'Console Password Next Rotation',
                   'MFA Active',
                   'Access Key 1 Active',
                   'Access Key 1 Last Rotated',
                   'Access Key 1 Last Used',
                   'Access Key 1 Last Used Region',
                   'Access Key 1 Last Used Service',
                   'Access Key 2 Active',
                   'Access Key 2 Last Rotated',
                   'Access Key 2 Last Used',
                   'Access Key 2 Last Used Region',
                   'Access Key 2 Last Used Service',
                   'Certificate 1 Active',
                   'Certificate 1 Last Rotated',
                   'Certificate 2 Active',
                   'Certificate 2 Last Rotated',
                   ]
    writer = csv.DictWriter(out, fieldnames=csv_columns)
    writer.writeheader()

    while True:
        if gen_report_complete and get_report_complete and report_output_queue.empty():
            logger.info("All report has been taken and queue is empty, I am done :) !!")
            break
        else:
            while not report_output_queue.empty():
                logger.debug("Report output queue is not empty, Starting to work !!")
                report_details = report_output_queue.get()
                if report_details['profile'].lower().__contains__("staging"):
                    account_type = "Non-Production"
                else:
                    account_type = "Production"

                report_data = report_details['raw_report'].decode('utf-8')
                records = list(csv.DictReader(io.StringIO(report_data)))
                for record in records:
                    csv_temp_record = dict()
                    csv_temp_record['Account'] = report_details['profile']
                    csv_temp_record['Account Type'] = account_type
                    csv_temp_record['User'] = record['user']
                    csv_temp_record['Arn'] = record['arn']
                    csv_temp_record['User Creation Time'] = record['user_creation_time']
                    csv_temp_record['Console Login Enabled'] = record['password_enabled']
                    csv_temp_record['Console Password Last Used'] = record['password_last_used']
                    csv_temp_record['Console Password Last Changed'] = record['password_next_rotation']
                    csv_temp_record['Console Password Next Rotation'] = record['password_next_rotation']
                    csv_temp_record['MFA Active'] = record['mfa_active']
                    csv_temp_record['Access Key 1 Active'] = record['access_key_1_active']
                    csv_temp_record['Access Key 1 Last Rotated'] = record['access_key_1_last_rotated']
                    csv_temp_record['Access Key 1 Last Used'] = record['access_key_1_last_used_date']
                    csv_temp_record['Access Key 1 Last Used Region'] = record['access_key_1_last_used_region']
                    csv_temp_record['Access Key 1 Last Used Service'] = record['access_key_1_last_used_service']
                    csv_temp_record['Access Key 2 Active'] = record['access_key_2_active']
                    csv_temp_record['Access Key 2 Last Rotated'] = record['access_key_2_last_rotated']
                    csv_temp_record['Access Key 2 Last Used'] = record['access_key_2_last_used_date']
                    csv_temp_record['Access Key 2 Last Used Region'] = record['access_key_2_last_used_region']
                    csv_temp_record['Access Key 2 Last Used Service'] = record['access_key_2_last_used_service']
                    csv_temp_record['Certificate 1 Active'] = record['cert_1_active']
                    csv_temp_record['Certificate 1 Last Rotated'] = record['cert_1_last_rotated']
                    csv_temp_record['Certificate 2 Active'] = record['cert_2_active']
                    csv_temp_record['Certificate 2 Last Rotated'] = record['cert_2_last_rotated']
                    writer.writerow(csv_temp_record)
                report_output_queue.task_done()
            # Sleeping for 10 seconds until report generation job fills up
            logger.debug(
                "Report output queue is empty and report getting worker(s) is/are running , going to sleep !!")
            time.sleep(10)
    out.close()

def start(profiles=None, worker_count=None, out_file=None):
    global profile_queue
    global gen_report_complete
    global get_report_complete


    # List containing all workers or threads
    gen_report_workers = []
    get_report_workers = []

    # Load all profiles to profile queue
    logger.info("Pushing all profiles in to profile queue !!")
    for profile in profiles:
        profile_queue.put(profile)
    logger.debug("Completed pushing all profiles in to profile queue !!")

    # Initiate Report Generation Workers
    logger.info("Initiating workers for Report generation !! ")
    for each in range(1):
        worker = Thread(target=generate_credential_report)
        worker.setDaemon(True)
        worker.start()
        gen_report_workers.append(worker)
    logger.debug("Completed initiation of  workers for report generation !! ")

    # Initiating the Workers for getting the report
    logger.info("Initiating workers for getting the report !! ")
    for each in range(1):
        worker = Thread(target=get_credential_report)
        worker.setDaemon(True)
        worker.start()
        get_report_workers.append(worker)
    logger.debug("Completed initiation of workers for getting the report !! ")

    # Initiate the File writer worker
    logger.info("Initiating worker for file write !! ")
    file_write_worker = Thread(target=file_writer, args=(out_file,))
    file_write_worker.setDaemon(True)
    file_write_worker.start()
    logger.debug("Completed initiating worker for file write !! ")

    # Monitor the workers
    logger.info("Initiating Worker Monitor!! ")
    while True:

        if not gen_report_complete:
            logger.debug("Checking on whether credential report generation is complete !! ")
            if not (True in [worker.is_alive() for worker in gen_report_workers]):
                # Making all workers join
                [worker.join() for worker in gen_report_workers]
                logger.info("Credential report generation is complete !! ")
                gen_report_complete = True

        if not get_report_complete:
            logger.debug("Checking on whether getting credential report is complete !! ")
            if not (True in [worker.is_alive() for worker in get_report_workers]):
                # Making all workers join
                [worker.join() for worker in get_report_workers]
                logger.info("Getting credential report is complete !! ")
                get_report_complete = True

        if not (gen_report_complete and get_report_complete):
            logger.debug("Workers are still busy working !! Going to sleep !! ")
            time.sleep(10)
        else:
            if file_write_worker.is_alive():
                logger.debug(
                    "Query Workers are done !! File writing worker is still busy working !! Going to sleep !! ")
                time.sleep(10)
            else:
                # This check catches one edge case.
                if profile_queue.empty() and get_report_queue.empty() and report_output_queue.empty():
                    logger.info("Operation Complete :) !!")
                else:
                    logger.error(
                        "There were some elements missed from processing probably due to sync issues. Likely chances being these "
                        "candidates would have been under process by get report which would have failed eventually, when gen report would have made check for empty get report queue before exiting and the failed ones had no get report workers to process them!!")
                    while profile_queue.empty():
                        profiles = profile_queue.get()
                        logger.error("Missed processing this  profile {}".format(profiles['profile']))
                        profile_queue.task_done()
                break

if __name__ == "__main__":

    with open('profiles', 'r') as file_in:
        content = file_in.readlines()

    profiles = [profile.replace("\n","") for profile in content]
    # Argument , profile , workers
    start(profiles=profiles,
          worker_count=None, out_file='credential_report.csv')
