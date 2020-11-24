from datetime import datetime


def print_with_time(str):
    print(datetime.now().strftime("[%H:%M:%S]" + " " + str))
