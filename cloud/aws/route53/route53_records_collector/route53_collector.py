from queue import Queue
from threading import Thread
from boto3 import session
from botocore.config import Config
from botocore.exceptions import ClientError as awsClientError
import logging
import time
import csv
import traceback

# Logger
logger = logging.getLogger(__name__)
FORMAT = "%(asctime)s — %(relativeCreated)6d — %(threadName)s — %(name)s — %(levelname)s — %(funcName)s:%(lineno)d — %(message)s"

logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

# Queues for maintaining synchronization
zone_queue = Queue()
record_set_queue = Queue()
profile_queue = Queue()

# AWS Configuration to escape throttling
config = Config(
   retries = {
      'max_attempts': 10,
      'mode': 'adaptive'
   }
)

# Global Flag to signify all AWS related queries are done. This is to control file writing operation
zone_query_complete = False
record_set_query_complete = False



def get_hosted_zones():
    global profile_queue
    global zone_queue
    global config

    while not profile_queue.empty():
        profile = profile_queue.get()
        aws_session = session.Session(profile_name=profile)
        r53_client = aws_session.client('route53', config=config)
        marker = None
        while True:
            try:
                if marker:
                    response = r53_client.list_hosted_zones(
                        Marker=marker, MaxItems='100')
                else:
                    response = r53_client.list_hosted_zones(MaxItems='100')


                for zone in response.get('HostedZones'):
                    zone_queue.put({'Profile' : profile,
                                    'ZoneId': zone['Id'],
                                    'ZoneName': zone['Name'],
                                    'RecordCount' : zone['ResourceRecordSetCount'],
                                    'Description': zone['Config'].get('Comment'),
                                    'PrivateZone': zone['Config']['PrivateZone'],
                                    'Client': r53_client
                                    })
                if response.get('IsTruncated'):
                    marker = response.get('NextMarker')
                else:
                    break
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
                    logger.error("Encountered Error: {} !! Omitting profile {} from processing ".format(error.response['Error']['Code'], profile))
                    logger.info(traceback.format_exc())
                    break
        profile_queue.task_done()
        logger.info("Zone query for profile {} done!!".format(profile))
    logger.info("No more profiles to process !!")

def get_record_sets():
    global zone_query_complete
    global zone_queue
    global record_set_queue

    while True:
        if zone_query_complete and zone_queue.empty():
            logger.info("Zone query is complete and zone queue is empty, I am done :) !!")
            break
        else:
            while not zone_queue.empty():
                logger.debug("Starting to work on zone querying!!")
                zone = zone_queue.get()
                r53_client = zone.get('Client')
                record_count = zone.get('RecordCount')
                processed_record=0
                marker = dict()
                marker['NextRecordName'] = ''
                marker['NextRecordType'] = ''
                marker['NextRecordIdentifier'] = ''
                while True:
                    try:
                        if marker.get('NextRecordName'):
                            if marker.get('NextRecordIdentifier'):
                                # This would exist only if resource record sets have non-simple routing policy.
                                # Refer https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/route53.html
                                response = r53_client.list_resource_record_sets(
                                    StartRecordName= marker['NextRecordName'],
                                    StartRecordType = marker['NextRecordType'],
                                    StartRecordIdentifier = marker['NextRecordIdentifier'],
                                    HostedZoneId=zone.get('ZoneId'),
                                    MaxItems='100'
                                )
                            else:
                                response = r53_client.list_resource_record_sets(
                                    StartRecordName=marker['NextRecordName'],
                                    StartRecordType=marker['NextRecordType'],
                                    HostedZoneId=zone.get('ZoneId'),
                                    MaxItems='100'
                                )
                        else:
                            response = r53_client.list_resource_record_sets(
                                HostedZoneId=zone.get('ZoneId'),
                                MaxItems='100'
                            )
                        for recordset in response.get('ResourceRecordSets'):
                            targets=[]
                            if recordset.get('AliasTarget'):
                                targets = [recordset['AliasTarget']['DNSName']]
                            elif recordset.get("ResourceRecords"):
                                for record in recordset.get("ResourceRecords"):
                                    targets.append(record.get("Value"))
                            else:
                                targets = None

                            for target in targets:
                                record_set_queue.put({'Profile' : zone.get('Profile'),
                                                  'DomainName' : zone.get('ZoneName'),
                                                  'ZoneId': zone.get('ZoneId'),
                                                  'ZoneDescription': zone.get('Description'),
                                                  'PrivateZone': zone.get('PrivateZone'),
                                                  'Subdomain': recordset['Name'],
                                                  'RecordSetType': recordset['Type'],
                                                  'Target': target}
                                                 )
                            processed_record += 1

                            logger.debug("Processed {} records out of total {} for domain {}. Remaining : {} records to be processed".format(processed_record,
                                                                                                                                         record_count,
                                                                                                                                         zone.get('ZoneName'),
                                                                                                                                         record_count-processed_record))
                        if response.get('IsTruncated'):
                            marker['NextRecordName'] = response.get('NextRecordName')
                            marker['NextRecordType'] = response.get('NextRecordType')
                            marker['NextRecordIdentifier'] = response.get('NextRecordIdentifier')
                        else:
                            break
                    except awsClientError as error:
                        if error.response['Error']['Code'] in ["RequestTimeout",
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
                            logger.error("Encountered Error: {} !! Sleeping for 20 seconds".format(
                                error.response['Error']['Code']))
                            logger.info(traceback.format_exc())
                            time.sleep(20)
                        else:
                            logger.error("Encountered Error: {} !! Omitting zone {} from profile {} "
                                         "from processing further record sets ".format(error.response['Error']['Code'],
                                                                                       zone.get('ZoneId'),
                                                                                       zone.get('Profile')))
                            logger.info(traceback.format_exc())
                            break
                zone_queue.task_done()
                logger.info("Domain {} from profile {} completed.".format(zone.get('ZoneName'), zone.get('Profile')))

            # Sleeping for 10 seconds until zone fills up
            logger.debug("Zone queue is empty and zone worker(s) is/are running , going to sleep !!")
            time.sleep(10)

def file_writer(file_output=None):
    global record_set_query_complete
    global record_set_queue

    out = open(file_output, 'w')
    csv_columns =['Profile', 'DomainName','ZoneId', 'ZoneDescription', 'PrivateZone', 'Subdomain', 'RecordSetType', 'Target']
    writer = csv.DictWriter(out, fieldnames=csv_columns)
    writer.writeheader()

    while True:
        if record_set_query_complete and record_set_queue.empty():
            logger.info("Record set query is complete and queue is empty, I am done :) !!")
            break
        else:
            while not record_set_queue.empty():
                logger.debug("Record set query is not empty, Starting to work !!")
                record = record_set_queue.get()
                writer.writerow(record)
                record_set_queue.task_done()
            # If no records in queue yet sleep for 10 seconds
            time.sleep(10)
    out.close()


def start(profiles=None, worker_count=None, out_file=None):

    global zone_query_complete
    global record_set_query_complete

    # List containing all workers or threads
    zone_workers = []
    record_set_workers = []

    # Load all profiles to profile queue
    logger.info("Pushing all profiles in to profile queue !!")
    for profile in profiles:
        profile_queue.put(profile)
    logger.debug("Completed pushing all profiles in to profile queue !!")

    # Initiate Zone workers
    logger.info("Initiating workers for zone collection !! ")
    if len(profiles) == 1:
        worker = Thread(target=get_hosted_zones)
        worker.setDaemon(True)
        worker.start()
        zone_workers.append(worker)
    else:
        # By default assigning 2 workers for zone
        for each in range(2):
            worker = Thread(target=get_hosted_zones, )
            worker.setDaemon(True)
            worker.start()
            zone_workers.append(worker)
    logger.debug("Completed initiation of  workers for zone collection !! ")

    # Initiating the Record Set Query Workers
    # By default assigning 2 workers for record_set
    logger.info("Initiating workers for record set collection !! ")
    for each in range(2):
        worker = Thread(target=get_record_sets)
        worker.setDaemon(True)
        worker.start()
        record_set_workers.append(worker)
    logger.debug("Completed initiation of workers for record set collection !! ")

    # Initiate the File writer worker
    logger.info("Initiating worker for file write !! ")
    file_write_worker = Thread(target=file_writer, args=(out_file,) )
    file_write_worker.setDaemon(True)
    file_write_worker.start()
    logger.debug("Completed initiating worker for file write !! ")

    # Monitor the workers
    logger.info("Initiating Worker Monitor!! ")
    while True:
        if not zone_query_complete:
            logger.debug("Checking on whether zone query is complete !! ")
            if not (True in [worker.is_alive() for worker in zone_workers]):
                # Making all workers join
                [worker.join() for worker in zone_workers]
                logger.info("Zone query is complete !! ")
                zone_query_complete = True

        if not record_set_query_complete:
            logger.debug("Checking on whether record set query is complete !! ")
            if not (True in [worker.is_alive() for worker in record_set_workers]):
                # Making all threads join
                [worker.join() for worker in record_set_workers]
                logger.info("Record set query is complete !! ")
                record_set_query_complete = True

        if not(record_set_query_complete and zone_query_complete):
            logger.debug("Query Workers are still busy working !! Going to sleep !! ")
            time.sleep(10)
        else:
            if file_write_worker.is_alive():
                logger.debug("Query Workers are done !! File writing worker is still busy working !! Going to sleep !! ")
                time.sleep(10)
            else:
                logger.debug("Operation Complete :) !!")
                break


if __name__ == "__main__":

    with open('profiles', 'r') as file_in:
        content = file_in.readlines()

    profiles = [profile.replace("\n", "") for profile in content]

    # Argument , profile , workers
    start(profiles=profiles or ["default"],
          worker_count=None, out_file='route53_collection.csv')