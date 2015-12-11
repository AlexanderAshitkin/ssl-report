import logging

import yaml

from datafetch.SslLabsReport import analyze_all
from emailsender.EmailSender import send_report_email

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)-15s %(levelname)s %(message)s [%(filename)s] [%(threadName)s]')
logger = logging.getLogger("Main")

with open("config.yml") as config_yml:
    config = yaml.safe_load(config_yml)

hosts = config.get("hosts")
reports = analyze_all(hosts)
send_report_email(reports)
