import logging


def print_and_log(message):
    # Configure logging to write to a file
    logging.basicConfig(filename='../log/log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

    # print and log the input string
    logging.info(message)


print_and_log("testing")
